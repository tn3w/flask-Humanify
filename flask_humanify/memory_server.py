import json
import logging
import socket
import time
import threading
import os
import importlib.metadata
import importlib.resources
import urllib.request
import gzip
import pickle
import random
import secrets
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from datetime import datetime, timedelta
from netaddr import IPNetwork, IPAddress


logger = logging.getLogger(__name__)


try:
    importlib.metadata.distribution("flask-humanify")
    BASE_DIR = importlib.resources.files("flask_humanify")
except importlib.metadata.PackageNotFoundError:
    BASE_DIR = Path(__file__).parent

if not isinstance(BASE_DIR, Path):
    BASE_DIR = Path(str(BASE_DIR))

DATASET_DIR = BASE_DIR / "datasets"
if not DATASET_DIR.exists():
    DATASET_DIR.mkdir(parents=True)

IPSET_DATA_PATH = str(DATASET_DIR / "ipset.json")
SECRET_KEY_FILE = BASE_DIR / "secret_key.bin"

IMAGES_CAPTCHA_DATASETS = {
    "keys": (
        "https://raw.githubusercontent.com/tn3w/Captcha_Datasets/"
        "refs/heads/master/datasets/keys.pkl"
    ),
    "animals": (
        "https://raw.githubusercontent.com/tn3w/Captcha_Datasets/"
        "refs/heads/master/datasets/animals.pkl"
    ),
    "ai_dogs": (
        "https://raw.githubusercontent.com/tn3w/Captcha_Datasets/"
        "refs/heads/master/datasets/ai-dogs.pkl"
    ),
}

AUDIO_CAPTCHA_DATASETS = {
    "characters": (
        "https://raw.githubusercontent.com/librecap/audiocaptcha/"
        "refs/heads/main/characters/characters.pkl"
    )
}


class MemoryServer:
    """A singleton memory server that manages IP sets and provides lookup functionality."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, port: int = 9876, data_path: Optional[str] = None):
        if data_path is None:
            data_path = IPSET_DATA_PATH

        with cls._lock:
            if cls._instance is None:
                cls._instance = super(MemoryServer, cls).__new__(cls)
                cls._instance.initialized = False
            return cls._instance

    def __init__(self, port: int = 9876, data_path: Optional[str] = None):
        if data_path is None:
            data_path = IPSET_DATA_PATH

        if getattr(self, "initialized", False):
            return

        self.port = port
        self.data_path = data_path
        self.ip_to_groups: Dict[str, List[str]] = {}
        self.cidrs_to_ips: Dict[IPNetwork, List[str]] = {}
        self.last_update: Optional[datetime] = None
        self.server_socket = None
        self.server_thread = None
        self.running = False

        self.captcha_image_data: Dict[str, Dict[str, List[bytes]]] = {}
        self.captcha_audio_data: Dict[str, Dict[str, Dict[str, List[bytes]]]] = {}
        self.current_image_dataset: Optional[str] = None
        self.current_audio_dataset: Optional[str] = None
        self.secret_key: bytes = self._load_or_create_secret_key()

        self.initialized = True

    def _load_or_create_secret_key(self) -> bytes:
        """Load the secret key from file or create a new one if it doesn't exist."""
        if SECRET_KEY_FILE.exists():
            logger.info("Loading secret key from %s", SECRET_KEY_FILE)
            with open(SECRET_KEY_FILE, "rb") as f:
                return f.read()

        logger.info("Generating new secret key")
        secret_key = secrets.token_bytes(32)
        with open(SECRET_KEY_FILE, "wb") as f:
            f.write(secret_key)

        return secret_key

    def get_secret_key(self) -> bytes:
        """Return the secret key."""
        return self.secret_key

    def is_server_running(self) -> bool:
        """Check if the server is already running on the specified port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("127.0.0.1", self.port))
                return True
        except (ConnectionRefusedError, socket.error):
            return False

    def download_data(self, force: bool = False) -> bool:
        """Download IP set data from GitHub and update the timestamp."""
        try:
            if not force and os.path.exists(self.data_path):
                with open(self.data_path, "r", encoding="utf-8") as f:
                    try:
                        data = json.load(f)
                        if isinstance(data, dict) and "_timestamp" in data:
                            timestamp = datetime.fromisoformat(data["_timestamp"])
                            if datetime.now() - timestamp < timedelta(days=7):
                                return True
                    except (json.JSONDecodeError, KeyError, ValueError):
                        pass

            url = "https://raw.githubusercontent.com/tn3w/IPSet/refs/heads/master/ipset.json"
            with urllib.request.urlopen(url, timeout=30) as response:
                response_data = response.read().decode("utf-8")

            data = json.loads(response_data)
            data["_timestamp"] = datetime.now().isoformat()

            with open(self.data_path, "w", encoding="utf-8") as f:
                json.dump(data, f)

            return True
        except Exception as e:
            logger.error("Error downloading IP set data: %s", e)
            return False

    def download_captcha_dataset(self, dataset_url: str, dataset_name: str) -> str:
        """Download a captcha dataset from the internet."""
        filename = f"{dataset_name}.pkl"
        file_path = os.path.join(DATASET_DIR, filename)

        if os.path.exists(file_path):
            return file_path

        try:
            urllib.request.urlretrieve(dataset_url, file_path)
            return file_path
        except Exception as e:
            logger.error("Failed to download captcha dataset %s: %s", dataset_name, e)
            return ""

    def load_data(self) -> bool:
        """Load IP set data into memory."""
        try:
            with open(self.data_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if "_timestamp" in data:
                self.last_update = datetime.fromisoformat(data.pop("_timestamp"))

            self.ip_to_groups = {}
            self.cidrs_to_ips = {}

            for group, ips in data.items():
                for ip in ips:
                    if "/" in ip:
                        try:
                            ip_obj = IPNetwork(ip)
                            if ip_obj not in self.cidrs_to_ips:
                                self.cidrs_to_ips[ip_obj] = []
                            self.cidrs_to_ips[ip_obj].append(group)
                        except Exception:
                            continue
                        continue

                    if ip not in self.ip_to_groups:
                        self.ip_to_groups[ip] = []
                    self.ip_to_groups[ip].append(group)

            return True
        except Exception as e:
            logger.error("Error loading IP set data: %s", e)
            return False

    def load_captcha_datasets(
        self,
        image_dataset: Optional[str] = None,
        audio_dataset: Optional[str] = None,
    ) -> bool:
        """Load captcha datasets into memory."""
        try:
            with self._lock:
                if (
                    self.current_image_dataset == image_dataset
                    and self.current_audio_dataset == audio_dataset
                    and (self.captcha_image_data or self.captcha_audio_data)
                ):
                    return True

                temp_image_data = {}
                temp_audio_data = {}

                self.current_image_dataset = image_dataset
                self.current_audio_dataset = audio_dataset

            if image_dataset in IMAGES_CAPTCHA_DATASETS:
                dataset_url = IMAGES_CAPTCHA_DATASETS[image_dataset]
                try:
                    dataset_path = self.download_captcha_dataset(
                        dataset_url, image_dataset
                    )
                    if dataset_path:
                        with open(dataset_path, "rb") as f:
                            data = pickle.load(f)
                        if data["type"] == "image":
                            first_image = data["keys"][next(iter(data["keys"]))][0]
                            if not first_image.startswith(b"\x89PNG\r\n\x1a\n"):
                                data["keys"] = {
                                    k: [gzip.decompress(img) for img in v]
                                    for k, v in data["keys"].items()
                                }
                        temp_image_data = data
                        logger.info("Loaded %s image captcha dataset", image_dataset)
                except Exception as e:
                    logger.error(
                        "Failed to load %s image captcha dataset: %s",
                        image_dataset,
                        e,
                    )
                    return False

            if audio_dataset in AUDIO_CAPTCHA_DATASETS:
                dataset_url = AUDIO_CAPTCHA_DATASETS[audio_dataset]
                try:
                    dataset_path = self.download_captcha_dataset(
                        dataset_url, audio_dataset
                    )
                    if dataset_path:
                        with open(dataset_path, "rb") as f:
                            data = pickle.load(f)
                        temp_audio_data = data
                        logger.info("Loaded %s audio captcha dataset", audio_dataset)
                except Exception as e:
                    logger.error(
                        "Failed to load %s audio captcha dataset: %s",
                        audio_dataset,
                        e,
                    )
                    return False

                if temp_image_data:
                    self.captcha_image_data = temp_image_data
                if temp_audio_data:
                    self.captcha_audio_data = temp_audio_data

                return True
        except Exception as e:
            logger.error("Error loading captcha datasets: %s", e)
            return False

        return False

    def check_and_update_data(self) -> None:
        """Check if data needs updating and update if necessary."""
        if self.last_update is None or datetime.now() - self.last_update > timedelta(
            days=7
        ):
            threading.Thread(target=self._async_update).start()

    def _async_update(self) -> None:
        """Update data in the background without affecting current operations."""
        if self.download_data(force=True):
            self.load_data()

    def find_matching_groups(self, ip: str) -> List[str]:
        """Find all groups matching the given IP."""
        self.check_and_update_data()

        matching_groups = self.ip_to_groups.get(ip, [])

        try:
            ip_obj = IPAddress(ip)
            ip_version = ip_obj.version

            for cidr, groups in self.cidrs_to_ips.items():
                if cidr.version != ip_version:
                    continue

                if ip_obj in cidr:
                    for group in groups:
                        if group not in matching_groups:
                            matching_groups.append(group)

        except Exception:
            return []

        return matching_groups

    def get_captcha_images(
        self,
        image_dataset: Optional[str] = None,
        correct_index_range: Union[Tuple[int, int], int] = (2, 3),
        num_images: int = 9,
        preview_image: bool = False,
    ) -> Tuple[List[bytes], str, str]:
        """
        Get captcha images for verification.

        Args:
            image_dataset: The image dataset to use. If None, uses the current dataset.
            correct_index_range: The range of correct indexes to select.
            num_images: The number of images to select.
            preview_image: If True, add an additional correct image at the beginning of the list.

        Returns:
            A tuple containing:
            - List of images
            - A string containing indexes of correct images. (e.g., "034")
            - The subject that represents the correct images (e.g., "smiling dog")
        """
        if image_dataset:
            self.load_captcha_datasets(image_dataset=image_dataset)
        elif not self.captcha_image_data:
            self.load_captcha_datasets()

        if (
            not self.captcha_image_data
            or self.captcha_image_data.get("type") != "image"
            or not self.captcha_image_data.get("keys")
        ):
            logger.error("Image captcha dataset not loaded or invalid")
            return [], "", ""

        keys = self.captcha_image_data.get("keys", {})
        if not keys:
            logger.error("Invalid image captcha dataset structure")
            return [], "", ""

        all_keys = list(keys.keys())
        if len(all_keys) <= 2:
            correct_key = all_keys[0]
        else:
            correct_key = random.choice(all_keys)

        correct_images = keys.get(correct_key, [])

        incorrect_keys = [k for k in all_keys if k != correct_key]
        incorrect_images = []
        for k in incorrect_keys:
            incorrect_images.extend(keys.get(k, []))

        if not correct_images or not incorrect_images:
            logger.error("Empty image lists in captcha dataset")
            return [], "", ""

        if isinstance(correct_index_range, int):
            num_correct = correct_index_range
        else:
            num_correct = random.randint(correct_index_range[0], correct_index_range[1])

        preview_correct_image = []
        if preview_image:
            preview_correct_image = [random.choice(correct_images)]

        selected_correct = random.sample(
            correct_images, min(num_correct, len(correct_images))
        )

        num_incorrect = num_images - len(selected_correct)
        selected_incorrect = random.sample(
            incorrect_images, min(num_incorrect, len(incorrect_images))
        )

        all_images = selected_correct + selected_incorrect

        combined = list(
            zip(all_images, [i < len(selected_correct) for i in range(len(all_images))])
        )
        random.shuffle(combined)
        all_images, is_correct = zip(*combined)
        correct_indexes = [i for i, correct in enumerate(is_correct) if correct]

        all_images = preview_correct_image + list(all_images)

        correct_indexes_str = "".join(str(i) for i in correct_indexes)

        return list(all_images), correct_indexes_str, correct_key

    def get_captcha_audio(
        self,
        audio_dataset: Optional[str] = None,
        num_chars: int = 6,
        language: str = "en",
    ) -> Tuple[List[bytes], str]:
        """
        Get captcha audio for verification.

        Args:
            audio_dataset: The audio dataset to use. If None, uses the current dataset.
            num_chars: The number of characters to include in the audio captcha.
            language: The language code for the audio files.

        Returns:
            A tuple containing:
            - List of audio file bytes
            - The correct characters string
        """
        if audio_dataset:
            self.load_captcha_datasets(audio_dataset=audio_dataset)
        elif not self.captcha_audio_data:
            self.load_captcha_datasets(audio_dataset="characters")

        if (
            not self.captcha_audio_data
            or self.captcha_audio_data.get("type") != "audio"
            or not self.captcha_audio_data.get("keys")
        ):
            logger.error("Audio captcha dataset not loaded or invalid")
            return [], ""

        keys = self.captcha_audio_data.get("keys", {})
        if not keys:
            logger.error("Invalid audio captcha dataset structure")
            return [], ""

        available_chars = list(keys.keys())

        selected_chars = random.choices(available_chars, k=num_chars)
        correct_chars_str = "".join(selected_chars)

        audio_files = []
        for char in selected_chars:
            try:
                audio_files.append(keys[char][language])
            except KeyError:
                logger.error(
                    "Error getting audio for character %s in language %s",
                    char,
                    language,
                )

        if not audio_files:
            logger.error("No audio files selected")
            return [], ""

        return audio_files, correct_chars_str

    def handle_client(
        self, client_socket: socket.socket, addr: Tuple[str, int]
    ) -> None:
        """Handle client connection and queries."""
        try:
            while True:
                data = client_socket.recv(1024).decode("utf-8").strip()
                if not data:
                    break

                if data.startswith("IPSET:"):
                    ip = data[6:]
                    result = self.find_matching_groups(ip)
                    response = json.dumps(result)
                elif data.startswith("IMAGE_CAPTCHA:"):
                    parts = data.split(":")
                    dataset_name = parts[1] if len(parts) > 1 else None
                    num_images = (
                        int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 9
                    )
                    correct_range = (
                        int(parts[3])
                        if len(parts) > 3 and parts[3].isdigit()
                        else (2, 3)
                    )
                    preview = parts[4].lower() == "true" if len(parts) > 4 else False

                    images, correct_indexes, subject = self.get_captcha_images(
                        image_dataset=dataset_name,
                        num_images=num_images,
                        correct_index_range=correct_range,
                        preview_image=preview,
                    )

                    response_data = {
                        "status": "success" if images else "error",
                        "correct_indexes": correct_indexes,
                        "subject": subject,
                        "num_images": len(images),
                    }
                    response = json.dumps(response_data)
                    client_socket.send(f"{response}\n".encode("utf-8"))

                    for img in images:
                        size_bytes = len(img).to_bytes(4, byteorder="big")
                        client_socket.send(size_bytes)
                        client_socket.send(img)
                    continue

                elif data.startswith("AUDIO_CAPTCHA:"):
                    parts = data.split(":")
                    dataset_name = parts[1] if len(parts) > 1 else None
                    num_chars = (
                        int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 6
                    )
                    language = parts[3] if len(parts) > 3 else "en"

                    audio_files, correct_chars = self.get_captcha_audio(
                        audio_dataset=dataset_name,
                        num_chars=num_chars,
                        language=language,
                    )

                    response_data = {
                        "status": "success" if audio_files else "error",
                        "correct_chars": correct_chars,
                        "num_files": len(audio_files),
                    }
                    response = json.dumps(response_data)
                    client_socket.send(f"{response}\n".encode("utf-8"))

                    for audio in audio_files:
                        size_bytes = len(audio).to_bytes(4, byteorder="big")
                        client_socket.send(size_bytes)
                        client_socket.send(audio)
                    continue
                elif data.startswith("SECRET_KEY:"):
                    secret_key = self.get_secret_key()
                    hex_key = secret_key.hex()
                    response = json.dumps(hex_key)
                else:
                    result = self.find_matching_groups(data)
                    response = json.dumps(result)

                client_socket.send(f"{response}\n".encode("utf-8"))
        except Exception as e:
            logger.error("Error handling client %s: %s", addr, e)
        finally:
            client_socket.close()

    def run_server(self) -> None:
        """Run the memory server."""
        if self.is_server_running():
            logger.info("Server already running on port %s", self.port)
            return

        if not os.path.exists(self.data_path):
            logger.info("IP data file not found at %s, downloading...", self.data_path)
            if not self.download_data():
                logger.error("Failed to download data, cannot start server")
                return

        if not self.load_data():
            logger.error("Failed to load data, cannot start server")
            return

        self.check_and_update_data()
        self.load_captcha_datasets(image_dataset="animals", audio_dataset="characters")

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(10)
            self.running = True

            logger.info(
                "Memory server started on port %s with data from %s",
                self.port,
                self.data_path,
            )

            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client, args=(client_socket, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except Exception as e:
                    if self.running:
                        logger.error("Error accepting connection: %s", e)

        except Exception as e:
            logger.error("Server error: %s", e)
        finally:
            if self.server_socket:
                self.server_socket.close()

    def start(self) -> None:
        """Start the server in a background thread."""
        if self.server_thread and self.server_thread.is_alive():
            return

        self.server_thread = threading.Thread(target=self.run_server)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self) -> None:
        """Stop the server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()


class MemoryClient:
    """Client to connect to the MemoryServer."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9876):
        self.host = host
        self.port = port
        self.socket = None

    def connect(self) -> bool:
        """Connect to the memory server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            return True
        except Exception as e:
            logger.error("Failed to connect to memory server: %s", e)
            return False

    def lookup_ip(self, ip: str) -> List[str]:
        """Look up an IP in the memory server."""
        if not self.socket:
            if not self.connect():
                return []

        try:
            if self.socket:
                self.socket.send(f"IPSET:{ip}\n".encode("utf-8"))
                response = self.socket.recv(4096).decode("utf-8").strip()
                return json.loads(response)
            return []
        except Exception as e:
            logger.error("Error looking up IP: %s", e)
            if self.connect():
                try:
                    if self.socket:
                        self.socket.send(f"IPSET:{ip}\n".encode("utf-8"))
                        response = self.socket.recv(4096).decode("utf-8").strip()
                        return json.loads(response)
                except Exception:
                    pass
            return []

    def get_captcha_images(
        self,
        dataset_name: Optional[str] = None,
        num_images: int = 9,
        num_correct: Union[int, Tuple[int, int]] = (2, 3),
        preview_image: bool = False,
    ) -> Tuple[List[bytes], str, str]:
        """
        Get captcha images from the memory server.

        Args:
            dataset_name: The name of the dataset to use
            num_images: Number of images to return
            num_correct: Number or range of correct images
            preview_image: Whether to include a preview image

        Returns:
            Tuple of (images list, correct indexes string, subject)
        """
        if not self.socket:
            if not self.connect():
                return [], "", ""

        try:
            if self.socket:
                command = (
                    f"IMAGE_CAPTCHA:{dataset_name or ''}:"
                    f"{num_images}:{num_correct}:{preview_image}"
                )
                self.socket.send(f"{command}\n".encode("utf-8"))

                json_data = b""
                while True:
                    chunk = self.socket.recv(1)
                    if not chunk:
                        return [], "", ""
                    json_data += chunk
                    if chunk == b"\n":
                        break

                response = json_data.decode("utf-8").strip()
                response_data = json.loads(response)

                if response_data.get("status") != "success":
                    return [], "", ""

                images = []
                num_images = response_data.get("num_images", 0)
                for _ in range(num_images):
                    size_bytes = self.socket.recv(4)
                    size = int.from_bytes(size_bytes, byteorder="big")
                    img_data = b""
                    remaining = size
                    while remaining > 0:
                        chunk = self.socket.recv(min(remaining, 4096))
                        if not chunk:
                            break
                        img_data += chunk
                        remaining -= len(chunk)
                    images.append(img_data)

                return (
                    images,
                    response_data.get("correct_indexes", ""),
                    response_data.get("subject", ""),
                )
            return [], "", ""
        except Exception as e:
            logger.error("Error getting captcha images: %s", e)
            return [], "", ""

    def get_captcha_audio(
        self,
        dataset_name: Optional[str] = None,
        num_chars: int = 6,
        language: str = "en",
    ) -> Tuple[List[bytes], str]:
        """
        Get captcha audio from the memory server.

        Args:
            dataset_name: The name of the dataset to use
            num_chars: Number of characters in the audio captcha
            language: Language code for the audio

        Returns:
            Tuple of (audio files list, correct characters string)
        """
        if not self.socket:
            if not self.connect():
                return [], ""

        try:
            if self.socket:
                command = f"AUDIO_CAPTCHA:{dataset_name or ''}:{num_chars}:{language}"
                self.socket.send(f"{command}\n".encode("utf-8"))

                json_data = b""
                while True:
                    chunk = self.socket.recv(1)
                    if not chunk:
                        return [], ""
                    json_data += chunk
                    if chunk == b"\n":
                        break

                response = json_data.decode("utf-8").strip()
                response_data = json.loads(response)

                if response_data.get("status") != "success":
                    return [], ""

                audio_files = []
                num_files = response_data.get("num_files", 0)
                for _ in range(num_files):
                    size_bytes = self.socket.recv(4)
                    size = int.from_bytes(size_bytes, byteorder="big")
                    audio_data = b""
                    remaining = size
                    while remaining > 0:
                        chunk = self.socket.recv(min(remaining, 4096))
                        if not chunk:
                            break
                        audio_data += chunk
                        remaining -= len(chunk)
                    audio_files.append(audio_data)

                return audio_files, response_data.get("correct_chars", "")
            return [], ""
        except Exception as e:
            logger.error("Error getting captcha audio: %s", e)
            return [], ""

    def get_secret_key(self) -> bytes:
        """Get the secret key from the memory server."""
        if not self.socket:
            if not self.connect():
                return b""

        try:
            if self.socket:
                self.socket.send("SECRET_KEY:\n".encode("utf-8"))
                response = self.socket.recv(4096).decode("utf-8").strip()
                try:
                    json_response = json.loads(response)
                    if isinstance(json_response, str):
                        return bytes.fromhex(json_response)
                    return b""
                except (json.JSONDecodeError, ValueError):
                    return b""
            return b""
        except Exception as e:
            logger.error("Error getting secret key: %s", e)
            return b""

    def close(self) -> None:
        """Close the connection to the memory server."""
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None


def ensure_server_running(
    port: int = 9876,
    data_path: Optional[str] = None,
    image_dataset: Optional[str] = None,
    audio_dataset: Optional[str] = None,
) -> None:
    """Ensure that the memory server is running."""
    if data_path is None:
        data_path = IPSET_DATA_PATH

    server = MemoryServer(port=port, data_path=data_path)
    server.load_captcha_datasets(
        image_dataset=image_dataset, audio_dataset=audio_dataset
    )
    server.start()

    while not server.is_server_running():
        time.sleep(0.1)
