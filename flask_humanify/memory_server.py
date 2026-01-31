import json
import logging
import socket
import time
import threading
import importlib.metadata
import importlib.resources
import urllib.request
import urllib.error
import gzip
import pickle
import random
import secrets
import hmac
from pathlib import Path
from typing import Any
from datetime import datetime, timedelta
from netaddr import IPNetwork, IPAddress

try:
    import fcntl
except ImportError:
    fcntl = None

logger = logging.getLogger(__name__)

try:
    importlib.metadata.distribution("flask-humanify")
    base_dir = importlib.resources.files("flask_humanify")
except importlib.metadata.PackageNotFoundError:
    base_dir = Path(__file__).parent

BASE_DIR = Path(str(base_dir)) if not isinstance(base_dir, Path) else base_dir
DATASET_DIR = BASE_DIR / "datasets"
DATASET_DIR.mkdir(parents=True, exist_ok=True)
IPSET_DATA_PATH = DATASET_DIR / "ipset.json"
SECRET_KEY_FILE = BASE_DIR / "secret_key.bin"

MAX_REQUEST_SIZE = 8192
MAX_IP_LENGTH = 45
SOCKET_TIMEOUT = 10.0
SERVER_SOCKET_TIMEOUT = 30.0
DATA_UPDATE_DAYS = 7
FAILED_ATTEMPTS_WINDOW_HOURS = 1
MAX_RETRIES = 3
CHUNK_SIZE = 32768
DATASET_CHECKSUMS = {
    "keys": "PLACEHOLDER_SHA256_CHECKSUM_FOR_KEYS",
    "animals": "PLACEHOLDER_SHA256_CHECKSUM_FOR_ANIMALS",
    "ai_dogs": "PLACEHOLDER_SHA256_CHECKSUM_FOR_AI_DOGS",
    "characters": "PLACEHOLDER_SHA256_CHECKSUM_FOR_CHARACTERS",
}

CAPTCHA_DATASETS = {
    "image": {
        "keys": (
            "https://raw.githubusercontent.com/tn3w/"
            "Captcha_Datasets/refs/heads/master/datasets/keys.pkl"
        ),
        "animals": (
            "https://raw.githubusercontent.com/tn3w/"
            "Captcha_Datasets/refs/heads/master/datasets/animals.pkl"
        ),
        "ai_dogs": (
            "https://raw.githubusercontent.com/tn3w/"
            "Captcha_Datasets/refs/heads/master/datasets/ai-dogs.pkl"
        ),
    },
    "audio": {
        "characters": (
            "https://raw.githubusercontent.com/librecap/"
            "audiocaptcha/refs/heads/main/characters/characters.pkl"
        )
    },
}


def validate_ip_format(ip: str) -> bool:
    if not ip or not isinstance(ip, str):
        return False
    ip = ip.strip()
    if not ip or len(ip) > MAX_IP_LENGTH:
        return False
    return all(c in "0123456789abcdefABCDEF.:" for c in ip)


def validate_dataset_name(name: str) -> bool:
    if not name or not isinstance(name, str):
        return False
    return name.replace("_", "").replace("-", "").isalnum()


def safe_file_read(
    file_path: Path, mode: str = "r", encoding: str | None = "utf-8"
) -> str | bytes | None:
    try:
        with open(file_path, mode, encoding=encoding) as file:
            if fcntl and hasattr(fcntl, "LOCK_SH"):
                try:
                    fcntl.flock(file.fileno(), fcntl.LOCK_SH)
                except (OSError, IOError):
                    pass
            return file.read()
    except OSError as error:
        logger.error(f"Error reading file {file_path}: {error}")
        return None


def safe_file_write(
    file_path: Path,
    content: str | bytes,
    mode: str = "w",
    encoding: str | None = "utf-8",
) -> bool:
    temp_path = file_path.with_suffix(file_path.suffix + ".tmp")
    try:
        with open(temp_path, mode, encoding=encoding) as file:
            file.write(content)
        if file_path.exists():
            file_path.unlink()
        temp_path.rename(file_path)
        return True
    except OSError as error:
        logger.error(f"Error writing file {file_path}: {error}")
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        return False


class MemoryServer:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, port: int = 9876, data_path: Path | None = None):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance.initialized = False
            return cls._instance

    def __init__(self, port: int = 9876, data_path: Path | None = None):
        if getattr(self, "initialized", False):
            return

        self.port = port
        self.data_path = data_path or IPSET_DATA_PATH
        self._data_lock = threading.RLock()
        self._socket_lock = threading.Lock()
        self._file_lock = threading.Lock()
        self.failed_attempts: dict[str, tuple[datetime, int]] = {}
        self.ip_to_groups: dict[str, list[str]] = {}
        self.cidrs_to_ips: dict[IPNetwork, list[str]] = {}
        self.last_update: datetime | None = None
        self.server_socket: socket.socket | None = None
        self.server_thread: threading.Thread | None = None
        self.running = threading.Event()
        self.captcha_data: dict[str, dict[str, Any]] = {
            "image": {},
            "audio": {},
        }
        self.current_datasets: dict[str, str | None] = {
            "image": None,
            "audio": None,
        }
        self.secret_key: bytes = self._load_or_create_secret_key()
        self.auth_token: bytes = secrets.token_bytes(32)
        self.initialized = True

    def _load_or_create_secret_key(self) -> bytes:
        with self._file_lock:
            if SECRET_KEY_FILE.exists():
                content = safe_file_read(SECRET_KEY_FILE, mode="rb", encoding=None)
                if content and isinstance(content, bytes):
                    return content

            secret_key = secrets.token_bytes(32)
            safe_file_write(SECRET_KEY_FILE, secret_key, mode="wb", encoding=None)

            try:
                import os

                os.chmod(SECRET_KEY_FILE, 0o600)
            except (OSError, AttributeError):
                pass

            return secret_key

    def is_server_running(self) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_socket:
                return test_socket.connect_ex(("127.0.0.1", self.port)) == 0
        except (ConnectionRefusedError, OSError):
            return False

    def _is_data_fresh(self) -> bool:
        if not self.data_path.exists():
            return False

        content = safe_file_read(self.data_path)
        if not content:
            return False

        try:
            data = json.loads(content)
            if not isinstance(data, dict) or "_timestamp" not in data:
                return False
            timestamp = datetime.fromisoformat(data["_timestamp"])
            age = datetime.now() - timestamp
            return age < timedelta(days=DATA_UPDATE_DAYS)
        except (json.JSONDecodeError, KeyError, ValueError) as error:
            logger.warning(f"Error checking data freshness: {error}")
            return False

    def _download_data(self, force: bool = False) -> bool:
        with self._file_lock:
            if not force and self._is_data_fresh():
                return True

            try:
                url = (
                    "https://raw.githubusercontent.com/tn3w/"
                    "IPSet/refs/heads/master/ipset.json"
                )
                with urllib.request.urlopen(url, timeout=30) as response:
                    data = json.loads(response.read().decode("utf-8"))

                data["_timestamp"] = datetime.now().isoformat()
                return safe_file_write(self.data_path, json.dumps(data), mode="w")
            except (
                urllib.error.URLError,
                json.JSONDecodeError,
                OSError,
            ) as error:
                logger.error(f"Error downloading IP data: {error}")
                return False

    def _download_captcha(self, url: str, name: str) -> Path | None:
        if not validate_dataset_name(name):
            logger.error(f"Invalid dataset name: {name}")
            return None

        file_path = DATASET_DIR / f"{name}.pkl"
        if file_path.exists():
            return file_path

        try:
            temp_path = file_path.with_suffix(file_path.suffix + ".tmp")
            urllib.request.urlretrieve(url, temp_path)
            if temp_path.exists():
                if file_path.exists():
                    file_path.unlink()
                temp_path.rename(file_path)
            return file_path
        except (urllib.error.URLError, OSError) as error:
            logger.error(f"Failed to download {name}: {error}")
            temp_path = file_path.with_suffix(file_path.suffix + ".tmp")
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            return None

    def _load_data(self) -> bool:
        with self._file_lock:
            for attempt in range(MAX_RETRIES):
                content = safe_file_read(self.data_path)
                if not content:
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(0.5 * (attempt + 1))
                        continue
                    return False

                try:
                    data = json.loads(content)
                    with self._data_lock:
                        self.last_update = datetime.fromisoformat(
                            data.pop("_timestamp", datetime.now().isoformat())
                        )

                        self.ip_to_groups.clear()
                        self.cidrs_to_ips.clear()

                        for group, ips in data.items():
                            if not isinstance(ips, list):
                                continue
                            for ip in ips:
                                if not isinstance(ip, str):
                                    continue
                                if "/" in ip:
                                    try:
                                        cidr = IPNetwork(ip)
                                        self.cidrs_to_ips.setdefault(cidr, []).append(
                                            group
                                        )
                                    except (ValueError, TypeError):
                                        continue
                                else:
                                    self.ip_to_groups.setdefault(ip, []).append(group)
                    return True

                except json.JSONDecodeError as error:
                    logger.error(
                        f"JSON decode error on attempt {attempt + 1}: " f"{error}"
                    )
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(0.5 * (attempt + 1))
                        continue

            return False

    def _decompress_images(
        self, keys: dict[str, list[bytes]]
    ) -> dict[str, list[bytes]]:
        first_key = next(iter(keys))
        if not keys[first_key]:
            return keys

        if keys[first_key][0].startswith(b"\x89PNG"):
            return keys

        try:
            return {
                key: [gzip.decompress(img) for img in images]
                for key, images in keys.items()
            }
        except gzip.BadGzipFile as error:
            logger.error(f"Failed to decompress images: {error}")
            return keys

    def _load_captcha_datasets(
        self, image: str | None = None, audio: str | None = None
    ) -> bool:
        if (
            self.current_datasets["image"] == image
            and self.current_datasets["audio"] == audio
            and (self.captcha_data["image"] or self.captcha_data["audio"])
        ):
            return True

        success = False

        if image and image in CAPTCHA_DATASETS["image"]:
            dataset_path = self._download_captcha(
                CAPTCHA_DATASETS["image"][image], image
            )
            if dataset_path:
                content = safe_file_read(dataset_path, mode="rb", encoding=None)
                if content and isinstance(content, bytes):
                    try:
                        data = pickle.loads(content)
                        if data.get("type") == "image":
                            keys = data.get("keys", {})
                            if keys:
                                data["keys"] = self._decompress_images(keys)
                            self.captcha_data["image"] = data
                            self.current_datasets["image"] = image
                            success = True
                    except (
                        pickle.UnpicklingError,
                        gzip.BadGzipFile,
                    ) as error:
                        logger.error(
                            f"Failed to load image dataset {image}: " f"{error}"
                        )

        if audio and audio in CAPTCHA_DATASETS["audio"]:
            dataset_path = self._download_captcha(
                CAPTCHA_DATASETS["audio"][audio], audio
            )
            if dataset_path:
                content = safe_file_read(dataset_path, mode="rb", encoding=None)
                if content and isinstance(content, bytes):
                    try:
                        self.captcha_data["audio"] = pickle.loads(content)
                        self.current_datasets["audio"] = audio
                        success = True
                    except pickle.UnpicklingError as error:
                        logger.error(
                            f"Failed to load audio dataset {audio}: " f"{error}"
                        )

        return success

    def _check_update(self) -> None:
        should_update = (
            self.last_update is None
            or datetime.now() - self.last_update > timedelta(days=DATA_UPDATE_DAYS)
        )
        if not should_update:
            return

        def update_task():
            if self._download_data(True):
                self._load_data()

        threading.Thread(target=update_task, daemon=True).start()

    def find_groups(self, ip: str) -> list[str]:
        if not validate_ip_format(ip):
            return []

        ip = ip.strip()
        self._check_update()

        with self._data_lock:
            groups = list(self.ip_to_groups.get(ip, []))

            try:
                ip_object = IPAddress(ip)
                for cidr, cidr_groups in self.cidrs_to_ips.items():
                    if cidr.version != ip_object.version:
                        continue
                    if ip_object in cidr:
                        groups.extend(
                            group for group in cidr_groups if group not in groups
                        )
            except (ValueError, TypeError) as error:
                logger.warning(f"Invalid IP address format: {ip} - {error}")
                return []

            return groups

    def get_images(
        self,
        dataset: str = "ai_dogs",
        count: int = 9,
        correct_range: int | tuple[int, int] = (2, 3),
        preview: bool = False,
    ) -> tuple[list[bytes], str, str]:
        if not self._load_captcha_datasets(image=dataset):
            return [], "", ""

        data = self.captcha_data["image"]
        if not data or data.get("type") != "image":
            return [], "", ""

        keys = data.get("keys", {})
        if not keys:
            return [], "", ""

        correct_key = (
            next(iter(keys)) if len(keys) <= 2 else random.choice(list(keys.keys()))
        )
        correct_images = keys[correct_key]
        incorrect_images = [
            img for key, images in keys.items() for img in images if key != correct_key
        ]

        if not correct_images or not incorrect_images:
            return [], "", ""

        num_correct = (
            correct_range
            if isinstance(correct_range, int)
            else random.randint(*correct_range)
        )

        selected_correct = random.sample(
            correct_images, min(num_correct, len(correct_images))
        )
        selected_incorrect = random.sample(
            incorrect_images,
            min(count - len(selected_correct), len(incorrect_images)),
        )

        combined = [(img, True) for img in selected_correct] + [
            (img, False) for img in selected_incorrect
        ]
        random.shuffle(combined)

        if combined:
            images, is_correct = zip(*combined)
        else:
            images, is_correct = (), ()

        correct_indices = "".join(
            str(index) for index, correct in enumerate(is_correct) if correct
        )

        if preview:
            images = tuple([random.choice(correct_images)]) + tuple(images)

        return list(images), correct_indices, correct_key

    def get_audio(
        self, dataset: str = "characters", chars: int = 6, lang: str = "en"
    ) -> tuple[list[bytes], str]:
        if not self._load_captcha_datasets(audio=dataset):
            return [], ""

        data = self.captcha_data["audio"]
        if not data or data.get("type") != "audio":
            return [], ""

        keys = data.get("keys", {})
        if not keys:
            return [], ""

        selected = random.choices(list(keys.keys()), k=chars)
        correct_string = "".join(selected)

        try:
            audio_files = [keys[char][lang] for char in selected]
            return audio_files, correct_string
        except KeyError:
            return [], ""

    def record_failure(self, ip_hash: str) -> int:
        now = datetime.now()
        cutoff = now - timedelta(hours=FAILED_ATTEMPTS_WINDOW_HOURS)

        self.failed_attempts = {
            key: value
            for key, value in self.failed_attempts.items()
            if value[0] > cutoff
        }

        if (
            ip_hash in self.failed_attempts
            and self.failed_attempts[ip_hash][0] > cutoff
        ):
            count = self.failed_attempts[ip_hash][1] + 1
        else:
            count = 1

        self.failed_attempts[ip_hash] = (now, count)
        return count

    def get_failed_attempts(self, ip_hash: str) -> int:
        cutoff = datetime.now() - timedelta(hours=FAILED_ATTEMPTS_WINDOW_HOURS)
        if (
            ip_hash not in self.failed_attempts
            or self.failed_attempts[ip_hash][0] <= cutoff
        ):
            return 0

        return self.failed_attempts[ip_hash][1]

    def _receive_until_newline(self, client: socket.socket) -> str | None:
        buffer = b""
        while b"\n" not in buffer:
            chunk = client.recv(1024)
            if not chunk:
                return None
            buffer += chunk
            if len(buffer) > MAX_REQUEST_SIZE:
                logger.warning("Client sent too much data")
                return None

        data, _ = buffer.split(b"\n", 1)
        try:
            return data.decode("utf-8").strip()
        except UnicodeDecodeError:
            return None

    def _send_response(self, client: socket.socket, response: str) -> bool:
        try:
            client.send(f"{response}\n".encode("utf-8"))
            return True
        except (ConnectionResetError, BrokenPipeError):
            return False

    def _handle_failed_attempts_query(self, data: str) -> str:
        ip_hash = data[20:].strip()
        if not ip_hash:
            return "0"
        return str(self.get_failed_attempts(ip_hash))

    def _handle_failed_attempt_record(self, data: str) -> str:
        ip_hash = data[15:].strip()
        if not ip_hash:
            return "0"
        return str(self.record_failure(ip_hash))

    def _handle_ipset_query(self, data: str) -> str:
        ip_address = data[6:].strip()
        return json.dumps(self.find_groups(ip_address))

    def _handle_secret_key_query(self) -> str:
        return json.dumps(self.secret_key.hex())

    def _parse_image_captcha_params(
        self, parts: list[str]
    ) -> tuple[str, int, int | tuple[int, int], bool]:
        dataset = parts[1] if len(parts) > 1 and parts[1] else "ai_dogs"
        count = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 9
        correct = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else (2, 3)
        preview = len(parts) > 4 and parts[4].lower() == "true"
        return dataset, count, correct, preview

    def _handle_image_captcha(self, client: socket.socket, data: str) -> bool:
        parts = data.split(":")
        dataset, count, correct, preview = self._parse_image_captcha_params(parts)

        images, indices, subject = self.get_images(dataset, count, correct, preview)
        response = json.dumps(
            {
                "status": "success" if images else "error",
                "correct_indexes": indices,
                "subject": subject,
                "num_images": len(images),
            }
        )

        if not self._send_response(client, response):
            return False

        try:
            for img in images:
                client.sendall(len(img).to_bytes(4, "big") + img)
            return True
        except (ConnectionResetError, BrokenPipeError):
            return False

    def _parse_audio_captcha_params(self, parts: list[str]) -> tuple[str, int, str]:
        dataset = parts[1] if len(parts) > 1 and parts[1] else "characters"
        chars = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 6
        lang = parts[3] if len(parts) > 3 else "en"
        return dataset, chars, lang

    def _handle_audio_captcha(self, client: socket.socket, data: str) -> bool:
        parts = data.split(":")
        dataset, chars, lang = self._parse_audio_captcha_params(parts)

        audio, correct = self.get_audio(dataset, chars, lang)
        response = json.dumps(
            {
                "status": "success" if audio else "error",
                "correct_chars": correct,
                "num_files": len(audio),
            }
        )

        if not self._send_response(client, response):
            return False

        try:
            for audio_file in audio:
                client.sendall(len(audio_file).to_bytes(4, "big") + audio_file)
            return True
        except (ConnectionResetError, BrokenPipeError):
            return False

    def _authenticate_request(self, data: str) -> tuple[bool, str]:
        if data.startswith("AUTH::GET_AUTH_TOKEN"):
            return True, "GET_AUTH_TOKEN"

        if not data.startswith("AUTH:"):
            return False, ""

        parts = data.split(":", 2)
        if len(parts) < 3:
            return False, ""

        provided_token = parts[1]
        actual_data = parts[2]

        expected_token = self.auth_token.hex()
        if not hmac.compare_digest(provided_token, expected_token):
            return False, ""

        return True, actual_data

    def _process_request(self, client: socket.socket, data: str) -> bool:
        is_authenticated, actual_data = self._authenticate_request(data)
        if not is_authenticated:
            error_response = json.dumps({"error": "authentication_failed"})
            return self._send_response(client, error_response)

        if actual_data.startswith("GET_FAILED_ATTEMPTS:"):
            response = self._handle_failed_attempts_query(actual_data)
            return self._send_response(client, response)

        if actual_data.startswith("FAILED_ATTEMPT:"):
            response = self._handle_failed_attempt_record(actual_data)
            return self._send_response(client, response)

        if actual_data.startswith("IPSET:"):
            response = self._handle_ipset_query(actual_data)
            return self._send_response(client, response)

        if actual_data.startswith("SECRET_KEY"):
            response = self._handle_secret_key_query()
            return self._send_response(client, response)

        if actual_data.startswith("IMAGE_CAPTCHA:"):
            return self._handle_image_captcha(client, actual_data)

        if actual_data.startswith("AUDIO_CAPTCHA:"):
            return self._handle_audio_captcha(client, actual_data)

        if actual_data.startswith("GET_AUTH_TOKEN"):
            response = json.dumps(self.auth_token.hex())
            return self._send_response(client, response)

        clean_data = actual_data.strip()
        response = json.dumps(self.find_groups(clean_data))
        return self._send_response(client, response)

    def _handle_client(self, client: socket.socket, addr: tuple[str, int]) -> None:
        try:
            client.settimeout(SOCKET_TIMEOUT)
            while True:
                data = self._receive_until_newline(client)
                if not data:
                    break

                try:
                    if not self._process_request(client, data):
                        break
                except ValueError:
                    error_response = json.dumps({"error": "invalid_request"})
                    if not self._send_response(client, error_response):
                        break

        except socket.timeout:
            pass
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            try:
                client.close()
            except (OSError, socket.error):
                pass

    def run(
        self,
        image_dataset: str | None = "ai_dogs",
        audio_dataset: str | None = "characters",
    ) -> None:
        if self.is_server_running():
            logger.info(f"Server already running on port {self.port}")
            return

        if not self.data_path.exists() and not self._download_data():
            logger.error("Failed to download data")
            return

        if not self._load_data():
            logger.error("Failed to load data")
            return

        self._check_update()
        self._load_captcha_datasets(image_dataset, audio_dataset)

        try:
            with self._socket_lock:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.settimeout(SERVER_SOCKET_TIMEOUT)
                self.server_socket.bind(("127.0.0.1", self.port))
                self.server_socket.listen(10)
                self.running.set()

            logger.info(f"Server started on port {self.port}")

            while self.running.is_set():
                try:
                    client, addr = self.server_socket.accept()
                    threading.Thread(
                        target=self._handle_client,
                        args=(client, addr),
                        daemon=True,
                    ).start()
                except socket.timeout:
                    continue
                except (ConnectionResetError, OSError) as error:
                    if self.running.is_set():
                        logger.error(f"Accept error: {error}")
                    time.sleep(0.1)

        except (OSError, socket.error) as error:
            logger.error(f"Server error: {error}")
        finally:
            if self.server_socket:
                try:
                    self.server_socket.close()
                except (OSError, socket.error):
                    pass

    def start(
        self,
        image_dataset: str | None = "ai_dogs",
        audio_dataset: str | None = "characters",
    ) -> None:
        with self._socket_lock:
            if self.server_thread and self.server_thread.is_alive():
                return
            self.running.set()
            self.server_thread = threading.Thread(
                target=self.run,
                args=(image_dataset, audio_dataset),
                daemon=True,
            )
            self.server_thread.start()

    def stop(self) -> None:
        self.running.clear()
        if self.server_socket:
            try:
                self.server_socket.close()
            except (OSError, socket.error):
                pass


class MemoryClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 9876):
        self.host = host
        self.port = port
        self.socket: socket.socket | None = None
        self.auth_token: str | None = None

    def connect(self) -> bool:
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(SOCKET_TIMEOUT)
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.socket.connect((self.host, self.port))

            if not self.auth_token:
                self.auth_token = self._fetch_auth_token()

            return True
        except (ConnectionRefusedError, OSError):
            return False

    def _fetch_auth_token(self) -> str:
        try:
            if not self.socket:
                return ""

            self.socket.send(b"AUTH::GET_AUTH_TOKEN\n")

            response_bytes = b""
            while b"\n" not in response_bytes:
                chunk = self.socket.recv(4096)
                if not chunk:
                    break
                response_bytes += chunk

            if b"\n" in response_bytes:
                response_bytes = response_bytes.split(b"\n")[0]

            response = response_bytes.decode("utf-8").strip()
            return json.loads(response) if response else ""
        except Exception:
            return ""

    def _send_recv(self, command: str) -> str:
        if not self.socket and not self.connect():
            return ""

        for attempt in range(MAX_RETRIES):
            try:
                if not self.socket or not self.auth_token:
                    return ""

                clean_command = command.replace("\n", " ").strip()
                authenticated_command = f"AUTH:{self.auth_token}:{clean_command}"
                self.socket.send(f"{authenticated_command}\n".encode("utf-8"))

                response_bytes = b""
                while b"\n" not in response_bytes:
                    try:
                        chunk = self.socket.recv(4096)
                        if not chunk:
                            break
                        response_bytes += chunk
                    except socket.timeout:
                        break

                if b"\n" in response_bytes:
                    response_bytes = response_bytes.split(b"\n")[0]

                try:
                    return response_bytes.decode("utf-8").strip()
                except UnicodeDecodeError:
                    return ""

            except (
                ConnectionResetError,
                BrokenPipeError,
                OSError,
            ):

                try:
                    if self.socket:
                        self.socket.close()
                except (OSError, socket.error):
                    pass
                self.socket = None

                self.auth_token = None

                if attempt < MAX_RETRIES - 1:
                    time.sleep(0.1 * (attempt + 1))
                    if not self.connect():
                        continue
                else:
                    return ""

        return ""

    def is_attempt_limit_reached(self, ip_hash: str, limit: int = 3) -> bool:
        failed_attempts = self._send_recv(f"GET_FAILED_ATTEMPTS:{ip_hash}")
        try:
            return int(failed_attempts) >= limit
        except (ValueError, TypeError):
            return False

    def record_failed_attempt(self, ip_hash: str) -> int:
        try:
            return int(self._send_recv(f"FAILED_ATTEMPT:{ip_hash}"))
        except (ValueError, TypeError):
            return 0

    def lookup_ip(self, ip: str) -> list[str]:
        try:
            response = self._send_recv(f"IPSET:{ip}")
            return json.loads(response) if response else []
        except (json.JSONDecodeError, TypeError):
            return []

    def get_secret_key(self) -> bytes:
        try:
            response = self._send_recv("SECRET_KEY")
            parsed = json.loads(response) if response else ""
            return bytes.fromhex(parsed) if isinstance(parsed, str) else b""
        except (json.JSONDecodeError, ValueError, TypeError):
            return b""

    def _receive_binary_chunks(self, num_items: int) -> list[bytes] | None:
        if not self.socket:
            return None

        items = []
        for _ in range(num_items):
            size_bytes = self.socket.recv(4)
            if len(size_bytes) != 4:
                raise ConnectionError("Failed to read item size")
            size = int.from_bytes(size_bytes, "big")

            item_data = bytearray()
            remaining = size

            while remaining > 0:
                chunk = self.socket.recv(min(remaining, CHUNK_SIZE))
                if not chunk:
                    break
                item_data.extend(chunk)
                remaining -= len(chunk)

            if len(item_data) != size:
                raise ConnectionError(
                    f"Incomplete item data: {len(item_data)} != {size}"
                )

            items.append(bytes(item_data))

        return items

    def get_captcha_images(
        self,
        dataset: str | None = None,
        count: int = 9,
        correct: int | tuple[int, int] = (2, 3),
        preview: bool = False,
    ) -> tuple[list[bytes], str, str]:
        for retry in range(2):
            if not self.socket and not self.connect():
                return [], "", ""

            try:
                if not self.socket or not self.auth_token:
                    return [], "", ""

                cmd = f"IMAGE_CAPTCHA:{dataset or ''}:{count}:{correct}:{preview}"
                authenticated_cmd = f"AUTH:{self.auth_token}:{cmd}"
                self.socket.send(f"{authenticated_cmd}\n".encode("utf-8"))

                json_data = b""
                while b"\n" not in json_data:
                    chunk = self.socket.recv(4096)
                    if not chunk:
                        break
                    json_data += chunk

                if b"\n" in json_data:
                    json_data = json_data.split(b"\n")[0]

                response = json.loads(json_data.decode("utf-8"))
                if response.get("status") != "success":
                    return [], "", ""

                num_images = response.get("num_images", 0)
                images = self._receive_binary_chunks(num_images)
                if images is None:
                    return [], "", ""

                return (
                    images,
                    response.get("correct_indexes", ""),
                    response.get("subject", ""),
                )
            except (
                json.JSONDecodeError,
                ConnectionResetError,
                BrokenPipeError,
                OSError,
            ) as error:
                logger.error(f"Error getting images: {error}")

                try:
                    if self.socket:
                        self.socket.close()
                except (OSError, socket.error):
                    pass
                self.socket = None
                self.auth_token = None

                if retry == 0:
                    time.sleep(0.1)
                    continue

                return [], "", ""

        return [], "", ""

    def get_captcha_audio(
        self, dataset: str | None = None, chars: int = 6, lang: str = "en"
    ) -> tuple[list[bytes], str]:
        for retry in range(2):
            if not self.socket and not self.connect():
                return [], ""

            try:
                if not self.socket or not self.auth_token:
                    return [], ""

                cmd = f"AUDIO_CAPTCHA:{dataset or ''}:{chars}:{lang}"
                authenticated_cmd = f"AUTH:{self.auth_token}:{cmd}"
                self.socket.send(f"{authenticated_cmd}\n".encode("utf-8"))

                json_data = b""
                while b"\n" not in json_data:
                    chunk = self.socket.recv(4096)
                    if not chunk:
                        break
                    json_data += chunk

                if b"\n" in json_data:
                    json_data = json_data.split(b"\n")[0]

                response = json.loads(json_data.decode("utf-8"))
                if response.get("status") != "success":
                    return [], ""

                num_files = response.get("num_files", 0)
                audio_files = self._receive_binary_chunks(num_files)
                if audio_files is None:
                    return [], ""

                return audio_files, response.get("correct_chars", "")
            except (
                json.JSONDecodeError,
                ConnectionResetError,
                BrokenPipeError,
                OSError,
            ) as error:
                logger.error(f"Error getting audio: {error}")

                try:
                    if self.socket:
                        self.socket.close()
                except (OSError, socket.error):
                    pass
                self.socket = None
                self.auth_token = None

                if retry == 0:
                    time.sleep(0.1)
                    continue

                return [], ""

        return [], ""

    def close(self) -> None:
        if self.socket:
            try:
                self.socket.close()
            except (OSError, socket.error):
                pass
            self.socket = None


def ensure_server_running(
    port: int = 9876,
    data_path: Path | None = None,
    image_dataset: str | None = None,
    audio_dataset: str | None = None,
) -> None:
    server = MemoryServer(port, data_path)
    server.start(image_dataset, audio_dataset)
    while not server.is_server_running():
        time.sleep(0.1)
