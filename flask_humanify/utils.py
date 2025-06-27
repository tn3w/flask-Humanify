import base64
import hashlib
import hmac
import io
import logging
import math
import random
import secrets
import time
from typing import List, Optional
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Request
from netaddr import AddrFormatError, IPAddress
import cv2
import numpy as np
from pydub import AudioSegment
from scipy.io.wavfile import write as write_wav


logger = logging.getLogger(__name__)


def is_valid_routable_ip(ip: str) -> bool:
    """Check if the IP address is valid and routable."""
    try:
        ip_obj = IPAddress(ip)

        is_private = (ip_obj.version == 4 and ip_obj.is_ipv4_private_use()) or (
            ip_obj.version == 6 and ip_obj.is_ipv6_unique_local()
        )

        return not (
            is_private
            or ip_obj.is_loopback()
            or ip_obj.is_multicast()
            or ip_obj.is_reserved()
            or ip_obj.is_link_local()
        )
    except (AddrFormatError, ValueError):
        return False


def get_client_ip(request: Request) -> Optional[str]:
    """Get the client IP address from the request."""
    remote_ip = request.environ.get("REMOTE_ADDR")
    if remote_ip and remote_ip not in ["127.0.0.1", "::1"]:
        return remote_ip

    remote_ip_addresses = set()
    for header in [
        "HTTP_X_FORWARDED_FOR",
        "HTTP_X_REAL_IP",
        "HTTP_CF_CONNECTING_IP",
        "HTTP_X_FORWARDED",
    ]:
        if not (value := request.environ.get(header)):
            continue

        for ip in [ip.strip() for ip in value.split(",")]:
            if ip.startswith("[") and "]" in ip:
                remote_ip_addresses.add(ip[1 : ip.find("]")])
            elif ":" in ip and ip.count(":") == 1 and "::" not in ip:
                remote_ip_addresses.add(ip.split(":")[0])
            else:
                remote_ip_addresses.add(ip)

    valid_ipv4s: List[str] = []
    valid_ipv6s: List[str] = []

    for ip in remote_ip_addresses:
        if not is_valid_routable_ip(ip):
            continue

        ip_obj = IPAddress(ip)
        if ip_obj.version == 4:
            valid_ipv4s.append(ip)
        elif ip_obj.version == 6:
            valid_ipv6s.append(ip)

    if valid_ipv4s:
        return valid_ipv4s[0]
    if valid_ipv6s:
        return valid_ipv6s[0]

    return None


def get_return_url(request: Request) -> str:
    """Get the return URL from the request."""
    return_url = request.args.get(
        "return_url", request.form.get("return_url", "")
    ).strip()
    if not return_url:
        return "/"

    parsed_url = urlparse(return_url)
    if parsed_url.netloc or parsed_url.scheme:
        return "/"

    if return_url.count("?") == 1:
        return return_url.strip("?")

    return return_url


def generate_random_token(length: int = 32) -> str:
    """Generate a random token using URL-safe base64 character set."""
    url_safe_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    return "".join(secrets.choice(url_safe_chars) for _ in range(length))


def generate_signature(data: str, key: bytes) -> str:
    """Generate a signature for the given data using the given key."""
    hmac_digest = hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(hmac_digest).decode("utf-8").rstrip("=")


def validate_signature(data: str, signature: str, key: bytes) -> bool:
    """Validate the signature for the given data using the given key."""
    expected_signature = generate_signature(data, key)
    return hmac.compare_digest(expected_signature, signature)


def generate_user_hash(ip: str, user_agent: str) -> str:
    """Generate a user hash for the given ip and user agent."""
    return hashlib.sha256(f"{ip}{user_agent}".encode("utf-8")).hexdigest()


def generate_clearance_token(user_hash: str, key: bytes) -> str:
    """Generate a clearance token for the given user hash."""
    nonce = generate_random_token(32)
    timestamp = str(int(time.time())).zfill(10)
    data = f"{nonce}{timestamp}{user_hash}"
    signature = generate_signature(data, key)
    return f"{data}{signature}"


def validate_clearance_token(
    token: str, key: bytes, user_hash: str, ttl: int = 14400
) -> bool:
    """Validate the clearance token."""
    try:
        if len(token) < 85:
            return False

        signature_length = 43

        nonce = token[:32]
        timestamp = token[32:42]
        token_user_hash = token[42:106]
        signature = token[-signature_length:]

        if token_user_hash != user_hash:
            return False

        data = f"{nonce}{timestamp}{user_hash}"
        if not validate_signature(data, signature, key):
            return False

        if int(timestamp) + ttl < int(time.time()):
            return False

        return True
    except Exception as e:
        logger.error("Token validation error: %s", str(e))
        return False


def encrypt_data(data: str, key: bytes) -> str:
    """Encrypt data using AES-GCM."""
    aesgcm = AESGCM(key[:32])
    iv = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(iv, data.encode("utf-8"), None)
    encrypted = iv + ciphertext
    return base64.urlsafe_b64encode(encrypted).decode("utf-8")


def decrypt_data(encrypted_data: str, key: bytes) -> Optional[str]:
    """Decrypt data encrypted with AES-GCM."""
    try:
        encrypted = base64.urlsafe_b64decode(encrypted_data)
        iv = encrypted[:12]
        ciphertext = encrypted[12:]

        aesgcm = AESGCM(key[:32])
        decrypted = aesgcm.decrypt(iv, ciphertext, None)
        return decrypted.decode("utf-8")
    except (ValueError, KeyError):
        return None


def generate_captcha_token(user_hash: str, correct_indexes: str, key: bytes) -> str:
    """Generate a captcha verification token."""
    nonce = generate_random_token(32)
    timestamp = str(int(time.time())).zfill(10)

    encrypted_answer = encrypt_data(correct_indexes, key)

    data = f"{nonce}{timestamp}{user_hash}{encrypted_answer}"
    return f"{data}{generate_signature(data, key)}"


def validate_captcha_token(
    token: str,
    key: bytes,
    user_hash: str,
    ttl: int = 600,
    valid_lengths: Optional[List[int]] = None,
) -> Optional[str]:
    """Validate the captcha token and return the correct indexes if valid."""
    try:
        if valid_lengths is None:
            valid_lengths = [189, 193]

        if len(token) not in valid_lengths:
            return None

        nonce = token[:32]
        timestamp = token[32:42]
        token_user_hash = token[42:106]
        encrypted_answer = token[106:-43]
        signature = token[-43:]

        if token_user_hash != user_hash:
            print("User hash mismatch")
            return None

        data = f"{nonce}{timestamp}{token_user_hash}{encrypted_answer}"

        if not validate_signature(data, signature, key):
            print("Signature mismatch")
            return None

        if int(timestamp) + ttl < int(time.time()):
            print("Token expired")
            return None

        correct_indexes = decrypt_data(encrypted_answer, key)
        return correct_indexes

    except Exception as e:
        logger.error("Token validation error: %s", str(e))
        return None


def manipulate_image_bytes(
    image_data: bytes, is_small: bool = False, hardness: int = 1
) -> bytes:
    """Manipulates an image represented by bytes to create a distorted version."""
    # pylint: disable=no-member

    img = cv2.imdecode(np.frombuffer(image_data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        logger.error("Image data could not be decoded by OpenCV")
        raise ValueError("Image data could not be decoded.")

    size = 100 if is_small else 200
    img = cv2.resize(img, (size, size), interpolation=cv2.INTER_LINEAR)

    if hardness > 3:
        num_dots = np.random.randint(20, 100) * (hardness - 3)
        dot_coords = np.random.randint(0, [size, size], size=(num_dots, 2))
        colors = np.random.randint(0, 256, size=(num_dots, 3))

        for (x, y), color in zip(dot_coords, colors):
            img[y, x] = color

        num_lines = np.random.randint(20, 100) * (hardness - 3)
        start_coords = np.random.randint(0, [size, size], size=(num_lines, 2))
        end_coords = np.random.randint(0, [size, size], size=(num_lines, 2))
        colors = np.random.randint(0, 256, size=(num_lines, 3))

        for (start, end), color in zip(zip(start_coords, end_coords), colors):
            cv2.line(img, tuple(start), tuple(end), color.tolist(), 1)

    max_shift = max(3, hardness + 1)
    x_shifts = np.random.randint(-max(2, hardness + 4), max_shift, size=(size, size))
    y_shifts = np.random.randint(-max(1, hardness + 4), max_shift, size=(size, size))

    map_x, map_y = np.meshgrid(np.arange(size), np.arange(size))
    map_x = (map_x + x_shifts) % size
    map_y = (map_y + y_shifts) % size

    shifted_img = cv2.remap(
        img, map_x.astype(np.float32), map_y.astype(np.float32), cv2.INTER_LINEAR
    )
    shifted_img_hsv = cv2.cvtColor(shifted_img, cv2.COLOR_BGR2HSV)

    shifted_img_hsv[..., 1] = np.clip(
        shifted_img_hsv[..., 1] * (1 + hardness * 0.12), 0, 255
    )
    shifted_img_hsv[..., 2] = np.clip(
        shifted_img_hsv[..., 2] * (1 - hardness * 0.09), 0, 255
    )

    shifted_img = cv2.cvtColor(shifted_img_hsv, cv2.COLOR_HSV2BGR)
    shifted_img = cv2.GaussianBlur(shifted_img, (5, 5), hardness * 0.1)

    _, output_bytes = cv2.imencode(".png", shifted_img)
    if not _:
        logger.error("Image encoding failed")
        raise ValueError("Image encoding failed.")

    return output_bytes.tobytes()


def image_bytes_to_data_url(image_bytes: bytes, image_format: str = "png") -> str:
    """Convert image bytes to a data URL."""
    b64_image = base64.b64encode(image_bytes).decode("utf-8")
    return f"data:image/{image_format};base64,{b64_image}"


def audio_bytes_to_data_url(audio_bytes: bytes, audio_format: str = "mp3") -> str:
    """Convert audio bytes to a data URL."""
    b64_audio = base64.b64encode(audio_bytes).decode("utf-8")
    return f"data:audio/{audio_format};base64,{b64_audio}"


# Audio processing functions

WAVE_SAMPLE_RATE = 44100  # Hz
audio_cache = {}


def numpy_to_audio_segment(samples, sample_rate=44100):
    """Convert numpy array directly to AudioSegment without temporary files."""
    try:
        samples = samples.astype(np.int16)
        wav_io = io.BytesIO()
        write_wav(wav_io, sample_rate, samples)
        wav_io.seek(0)

        return AudioSegment.from_wav(wav_io)
    except ImportError:
        logger.error("pydub or scipy not installed. Audio processing unavailable.")
        return None


def generate_sine_wave(freq, duration_ms, sample_rate=44100):
    """Generate a sine wave at the specified frequency and duration."""
    cache_key = f"sine_{freq}_{duration_ms}_{sample_rate}"
    if cache_key in audio_cache:
        return audio_cache[cache_key]

    num_samples = int(sample_rate * duration_ms / 1000.0)
    t = np.linspace(0, duration_ms / 1000.0, num_samples, endpoint=False)
    samples = (np.sin(2 * np.pi * freq * t) * 32767).astype(np.int16)

    beep_segment = numpy_to_audio_segment(samples, sample_rate)

    audio_cache[cache_key] = beep_segment
    return beep_segment


def change_speed(audio_segment, speed=1.0):
    """Change the speed of an AudioSegment."""
    if speed == 1.0:
        return audio_segment

    return audio_segment._spawn(
        audio_segment.raw_data,
        overrides={"frame_rate": int(audio_segment.frame_rate * speed)},
    ).set_frame_rate(audio_segment.frame_rate)


def change_volume(audio_segment, level=1.0):
    """Change the volume of an AudioSegment."""
    if level == 1.0:
        return audio_segment

    db_change = 20 * math.log10(level)
    return audio_segment.apply_gain(db_change)


def create_silence(duration_ms):
    """Create a silent AudioSegment."""
    try:
        return AudioSegment.silent(duration=duration_ms)
    except ImportError:
        logger.error("pydub not installed. Audio processing unavailable.")
        return None


def create_noise(duration_ms, level=0.05, sample_rate=44100):
    """Create white noise."""
    cache_key = f"noise_{duration_ms}_{level}_{sample_rate}"
    if cache_key in audio_cache:
        return audio_cache[cache_key]

    num_samples = int(sample_rate * duration_ms / 1000.0)
    noise_samples = (np.random.uniform(-1, 1, num_samples) * level * 32767).astype(
        np.int16
    )

    noise_segment = numpy_to_audio_segment(noise_samples, sample_rate)

    audio_cache[cache_key] = noise_segment
    return noise_segment


def mix_audio(audio1, audio2, position_ms=0):
    """Mix two AudioSegments."""
    try:
        return audio1.overlay(audio2, position=position_ms)
    except Exception as e:
        logger.error(f"Audio overlay failed: {e}")
        try:
            if audio1.frame_rate != audio2.frame_rate:
                audio2 = audio2.set_frame_rate(audio1.frame_rate)
            if audio1.channels != audio2.channels:
                audio2 = audio2.set_channels(audio1.channels)
            if audio1.sample_width != audio2.sample_width:
                audio2 = audio2.set_sample_width(audio1.sample_width)

            return audio1.overlay(audio2, position=position_ms)
        except Exception as e2:
            logger.error(f"Second audio overlay attempt failed: {e2}")
            return audio1


def batch_mix_audio(base_audio, segments_with_positions):
    """
    More efficient way to mix multiple audio segments with their positions.

    Args:
        base_audio: Base AudioSegment
        segments_with_positions: List of tuples (segment, position_ms)

    Returns:
        Mixed AudioSegment
    """
    result = base_audio

    segments_with_positions.sort(key=lambda x: x[1])

    batch_size = 10
    for i in range(0, len(segments_with_positions), batch_size):
        batch = segments_with_positions[i : i + batch_size]

        for segment, position in batch:
            result = mix_audio(result, segment, position)

    return result


def bytes_to_audio_segment(audio_bytes):
    """Convert bytes directly to AudioSegment without temp files."""
    try:
        wav_io = io.BytesIO(audio_bytes)
        return AudioSegment.from_wav(wav_io)
    except ImportError:
        logger.error("pydub not installed. Audio processing unavailable.")
        return None


def combine_audio_files(audio_files):
    """
    Combine a list of audio file bytes into a single audio file.

    Args:
        audio_files: List of audio file bytes

    Returns:
        Combined audio file bytes
    """
    try:
        if not audio_files:
            logger.error("No audio files provided")
            return None

        segments = []
        for audio_bytes in audio_files:
            wav_io = io.BytesIO(audio_bytes)
            try:
                segment = AudioSegment.from_wav(wav_io)
                segments.append(segment)
            except Exception as e:
                logger.error(f"Error converting audio bytes to segment: {e}")

        if not segments:
            logger.error("No valid audio segments found")
            return None

        result = create_silence(random.randint(200, 500))

        for segment in segments:
            result += segment
            result += create_silence(random.randint(300, 700))

        noise_level = random.uniform(0.01, 0.03)
        result = add_background_noise(result, noise_level)

        output_io = io.BytesIO()
        result.export(output_io, format="mp3")
        output_io.seek(0)

        return output_io.read()
    except ImportError:
        logger.error("pydub not installed. Audio processing unavailable.")
        return None


def add_background_noise(audio_segment, noise_level=0.05):
    """Add background noise to an AudioSegment."""
    noise = create_noise(len(audio_segment), level=noise_level)
    return mix_audio(audio_segment, noise)
