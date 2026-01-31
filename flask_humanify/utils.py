import base64
import hashlib
import hmac
import io
import logging
import math
import re
import secrets
import time
from urllib.parse import urlparse

import cv2
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Request, g
from netaddr import AddrFormatError, IPAddress
from pydub import AudioSegment
from scipy.io.wavfile import write as write_wav

logger = logging.getLogger(__name__)

WAVE_SAMPLE_RATE = 44100
audio_cache = {}
secure_random = secrets.SystemRandom()


def generate_csrf_token(request: Request, secret_key: bytes) -> str:
    cookie_value = request.cookies.get("csrf_token", "")
    csrf_ttl = 1800

    if cookie_value and len(cookie_value) == 117:
        stored_token = cookie_value[:64]
        timestamp = cookie_value[64:74]
        signature = cookie_value[74:]

        data = f"{stored_token}{timestamp}"
        if validate_signature(data, signature, secret_key):
            try:
                token_time = int(timestamp)
                current_time = int(time.time())
                if token_time <= current_time and token_time + csrf_ttl >= current_time:
                    return stored_token
            except ValueError:
                pass

    token = secrets.token_hex(32)
    timestamp = str(int(time.time())).zfill(10)
    data = f"{token}{timestamp}"
    signature = generate_signature(data, secret_key)
    signed_token = f"{data}{signature}"
    g.humanify_csrf_cookie = signed_token
    return token


def validate_csrf_token(
    request: Request,
    token: str,
    secret_key: bytes,
    ttl: int = 1800,
) -> bool:
    if not token:
        return False

    cookie_value = request.cookies.get("csrf_token", "")
    if not cookie_value:
        return False

    expected_length = 117
    if len(cookie_value) != expected_length:
        return False

    stored_token = cookie_value[:64]
    timestamp = cookie_value[64:74]
    signature = cookie_value[74:]

    data = f"{stored_token}{timestamp}"
    if not validate_signature(data, signature, secret_key):
        return False

    try:
        token_time = int(timestamp)
        current_time = int(time.time())
        if token_time > current_time or token_time + ttl < current_time:
            return False
    except ValueError:
        return False

    return hmac.compare_digest(token, stored_token)


def verify_request_csrf(request: Request, secret_key: bytes) -> bool:
    if request.method not in ["POST", "PUT", "DELETE", "PATCH"]:
        return True

    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    return validate_csrf_token(request, token or "", secret_key)


def get_crawler_name(user_agent):
    if not user_agent:
        return None

    pattern = (
        r"(?:^|compatible; )"
        r"([A-Za-z][A-Za-z0-9._-]*(?:bot|spider|crawler|Bot|Spider|Crawler))"
        r"[/\s]?[\d.]*"
        r"|"
        r"^([A-Za-z][A-Za-z0-9._-]+)"
        r"(?:/[\d.]+)?"
    )

    match = re.search(pattern, user_agent)
    return match.group(1) or match.group(2) if match else None


def is_valid_routable_ip(ip):
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


def get_next_url(request):
    next_url = request.args.get(
        "next",
        request.form.get("next", ""),
    ).strip()

    if not next_url:
        return "/"

    if len(next_url) > 400:
        return "/"

    if not next_url.startswith("/"):
        return "/"

    if next_url.startswith(("//", "/\\", "/\\")):
        return "/"

    parsed_url = urlparse(next_url)
    if parsed_url.netloc or parsed_url.scheme:
        return "/"

    return next_url.rstrip("?")


def generate_random_token(length=32):
    url_safe_chars = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz" "0123456789-_"
    )
    return "".join(secrets.choice(url_safe_chars) for _ in range(length))


def generate_signature(data, key):
    hmac_digest = hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(hmac_digest).decode("utf-8").rstrip("=")


def validate_signature(data, signature, key):
    expected_signature = generate_signature(data, key)
    return hmac.compare_digest(expected_signature, signature)


def generate_user_hash(ip, user_agent):
    return hashlib.sha256(f"{ip}{user_agent}".encode("utf-8")).hexdigest()


def generate_clearance_token(user_hash, key):
    nonce = generate_random_token(32)
    timestamp = str(int(time.time())).zfill(10)
    data = f"{nonce}{timestamp}{user_hash}"
    signature = generate_signature(data, key)
    return f"{data}{signature}"


def generate_client_id_token(secret_key, client_id):
    h = hmac.new(secret_key, client_id.encode(), hashlib.sha256)
    return f"{client_id}:{h.hexdigest()}"


def verify_client_id_token(secret_key, token):
    if not token or ":" not in token:
        return None
    client_id, signature = token.rsplit(":", 1)
    expected = hmac.new(
        secret_key,
        client_id.encode(),
        hashlib.sha256,
    ).hexdigest()
    if hmac.compare_digest(signature, expected):
        return client_id
    return None


def get_or_create_client_id(request, client_ip, secret_key, use_client_id=False):
    if not use_client_id:
        if not client_ip:
            client_ip = "127.0.0.1"
        return hashlib.sha256(client_ip.encode()).hexdigest()

    if not secret_key:
        raise ValueError("Secret key is required for client ID.")

    client_id_token = request.cookies.get("client_id")
    if client_id_token:
        verified_id = verify_client_id_token(secret_key, client_id_token)
        if verified_id:
            return verified_id

    new_id = secrets.token_hex(16)
    g.humanify_new_client_id = generate_client_id_token(secret_key, new_id)
    return new_id


def validate_clearance_token(token, key, user_hash, ttl=7200):
    try:
        expected_length = 149
        if not isinstance(token, str):
            return False

        if not hmac.compare_digest(
            str(len(token)).zfill(10), str(expected_length).zfill(10)
        ):
            return False

        signature_length = 43

        nonce = token[:32]
        timestamp = token[32:42]
        token_user_hash = token[42:106]
        signature = token[-signature_length:]

        if not hmac.compare_digest(token_user_hash, user_hash):
            return False

        data = f"{nonce}{timestamp}{user_hash}"
        if not validate_signature(data, signature, key):
            return False

        current_time = int(time.time())
        token_time = int(timestamp)

        if token_time > current_time or token_time + ttl < current_time:
            return False

        return True
    except Exception:
        logger.error("Token validation error")
        return False


def encrypt_data(data, key):
    aesgcm = AESGCM(key[:32])
    iv = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(iv, data.encode("utf-8"), None)
    encrypted = iv + ciphertext
    return base64.urlsafe_b64encode(encrypted).decode("utf-8")


def decrypt_data(encrypted_data, key):
    try:
        encrypted = base64.urlsafe_b64decode(encrypted_data)
        iv = encrypted[:12]
        ciphertext = encrypted[12:]

        aesgcm = AESGCM(key[:32])
        decrypted = aesgcm.decrypt(iv, ciphertext, None)
        return decrypted.decode("utf-8")
    except (ValueError, KeyError):
        return None


def generate_captcha_token(user_hash, correct_indexes, key):
    nonce = generate_random_token(32)
    timestamp = str(int(time.time())).zfill(10)

    encrypted_answer = encrypt_data(correct_indexes, key)

    data = f"{nonce}{timestamp}{user_hash}{encrypted_answer}"
    return f"{data}{generate_signature(data, key)}"


def validate_captcha_token(
    token,
    key,
    user_hash,
    ttl=600,
    valid_lengths=None,
):
    try:
        if valid_lengths is None:
            valid_lengths = [189, 193]

        token_length = len(token) if isinstance(token, str) else 0
        is_valid_length = any(
            hmac.compare_digest(str(token_length).zfill(10), str(vl).zfill(10))
            for vl in valid_lengths
        )

        if not is_valid_length:
            return None

        nonce = token[:32]
        timestamp = token[32:42]
        token_user_hash = token[42:106]
        encrypted_answer = token[106:-43]
        signature = token[-43:]

        if not hmac.compare_digest(token_user_hash, user_hash):
            return None

        data = f"{nonce}{timestamp}{token_user_hash}{encrypted_answer}"

        if not validate_signature(data, signature, key):
            return None

        if int(timestamp) + ttl < int(time.time()):
            return None

        correct_indexes = decrypt_data(encrypted_answer, key)
        return correct_indexes

    except Exception:
        logger.error("Token validation error")
        return None


def manipulate_image_bytes(image_data, is_small=False, hardness=1):
    hardness = min(max(1, hardness), 5)

    img = cv2.imdecode(np.frombuffer(image_data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        logger.error("Image data could not be decoded by OpenCV")
        raise ValueError("Image data could not be decoded.")

    size = 100 if is_small else 200
    img = cv2.resize(img, (size, size), interpolation=cv2.INTER_LINEAR)

    mask_pattern = np.zeros((size, size, 3), dtype=np.uint8)

    grid_size = max(8, 16 - hardness * 2)
    for i in range(0, size, grid_size):
        thickness = 1
        cv2.line(mask_pattern, (i, 0), (i, size), (2, 2, 2), thickness)
        cv2.line(mask_pattern, (0, i), (size, i), (2, 2, 2), thickness)

    mask_opacity = min(0.06 + hardness * 0.03, 0.18)
    img = cv2.addWeighted(img, 1 - mask_opacity, mask_pattern, mask_opacity, 0)

    noise_max = max(1, 1 + hardness // 2)
    noise_pattern = np.random.randint(
        0,
        noise_max,
        size=(size, size, 3),
        dtype=np.uint8,
    )
    img = cv2.add(img, noise_pattern)

    num_dots = secure_random.randint(5 + 5 * hardness, 10 + 10 * hardness)
    dot_coords = np.array(
        [
            [secure_random.randint(0, size - 1), secure_random.randint(0, size - 1)]
            for _ in range(num_dots)
        ]
    )

    dot_intensity = 0.05 + hardness * 0.05
    rand_max = max(1, 10 * hardness)
    colors = np.array(
        [
            [secure_random.randint(0, rand_max - 1) for _ in range(3)]
            for _ in range(num_dots)
        ]
    ) + np.array([img[coord[1], coord[0]] for coord in dot_coords]) * (
        1 - dot_intensity
    )
    colors = np.clip(colors, 0, 255).astype(np.uint8)

    for (x, y), color in zip(dot_coords, colors):
        img[y, x] = color

    num_lines = secure_random.randint(2 * hardness, 5 * hardness)
    start_coords = np.array(
        [
            [secure_random.randint(0, size - 1), secure_random.randint(0, size - 1)]
            for _ in range(num_lines)
        ]
    )
    end_coords = np.array(
        [
            [secure_random.randint(0, size - 1), secure_random.randint(0, size - 1)]
            for _ in range(num_lines)
        ]
    )

    line_intensity = max(4, 3 * hardness)
    colors = np.array(
        [
            [secure_random.randint(3, line_intensity - 1) for _ in range(3)]
            for _ in range(num_lines)
        ]
    )

    for (start, end), color in zip(zip(start_coords, end_coords), colors):
        cv2.line(img, tuple(start), tuple(end), color.tolist(), 1)

    for _ in range(hardness):
        x = secure_random.randint(0, size - 1)
        y = secure_random.randint(0, size - 1)
        length = secure_random.randint(5 + 3 * hardness, 10 + 5 * hardness)
        angle = secure_random.randint(0, 359)
        text_max = max(3, 2 + hardness)
        text_color = [secure_random.randint(1, text_max - 1) for _ in range(3)]

        end_x = int(x + length * np.cos(np.radians(angle)))
        end_y = int(y + length * np.sin(np.radians(angle)))
        cv2.line(img, (x, y), (end_x, end_y), text_color, 1)

    for _ in range(1 + hardness // 2):
        patch_size = secure_random.randint(4 + hardness, 6 + 3 * hardness)
        x = secure_random.randint(0, size - patch_size)
        y = secure_random.randint(0, size - patch_size)

        patch = np.zeros((patch_size, patch_size, 3), dtype=np.uint8)
        for i in range(0, patch_size, 2):
            for j in range(0, patch_size, 2):
                if (i + j) % 4 == 0:
                    patch_color_max = max(2, 1 + hardness)
                    patch[i : i + 2, j : j + 2] = [
                        secure_random.randint(1, patch_color_max - 1)
                    ] * 3

        patch_opacity = 0.03 + 0.02 * hardness
        roi = img[y : y + patch_size, x : x + patch_size]
        img[y : y + patch_size, x : x + patch_size] = cv2.addWeighted(
            roi,
            1 - patch_opacity,
            patch,
            patch_opacity,
            0,
        )

    max_shift = hardness
    x_shifts = np.array(
        [
            [secure_random.randint(-max_shift, max_shift) for _ in range(size)]
            for _ in range(size)
        ]
    )
    y_shifts = np.array(
        [
            [secure_random.randint(-max_shift, max_shift) for _ in range(size)]
            for _ in range(size)
        ]
    )

    saturation_factor = 1 + hardness * 0.05
    value_factor = 1 - hardness * 0.03
    blur_factor = hardness * 0.05

    map_x, map_y = np.meshgrid(np.arange(size), np.arange(size))
    map_x = (map_x + x_shifts) % size
    map_y = (map_y + y_shifts) % size

    shifted_img = cv2.remap(
        img,
        map_x.astype(np.float32),
        map_y.astype(np.float32),
        cv2.INTER_LINEAR,
    )
    shifted_img_hsv = cv2.cvtColor(shifted_img, cv2.COLOR_BGR2HSV)

    shifted_img_hsv[..., 1] = np.clip(
        shifted_img_hsv[..., 1] * saturation_factor,
        0,
        255,
    )
    shifted_img_hsv[..., 2] = np.clip(
        shifted_img_hsv[..., 2] * value_factor,
        0,
        255,
    )

    shifted_img = cv2.cvtColor(shifted_img_hsv, cv2.COLOR_HSV2BGR)
    shifted_img = cv2.GaussianBlur(shifted_img, (5, 5), blur_factor)

    noise_high = max(1, 1 + hardness // 3)
    high_freq_noise = np.random.randint(
        0,
        noise_high,
        size=shifted_img.shape,
        dtype=np.uint8,
    )
    shifted_img = cv2.add(shifted_img, high_freq_noise)

    _, output_bytes = cv2.imencode(".png", shifted_img)
    if not _:
        logger.error("Image encoding failed")
        raise ValueError("Image encoding failed.")

    return output_bytes.tobytes()


def image_bytes_to_data_url(image_bytes, image_format="png"):
    b64_image = base64.b64encode(image_bytes).decode("utf-8")
    return f"data:image/{image_format};base64,{b64_image}"


def audio_bytes_to_data_url(audio_bytes, audio_format="mp3"):
    b64_audio = base64.b64encode(audio_bytes).decode("utf-8")
    return f"data:audio/{audio_format};base64,{b64_audio}"


def numpy_to_audio_segment(samples, sample_rate=44100):
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
    if speed == 1.0:
        return audio_segment

    return audio_segment._spawn(
        audio_segment.raw_data,
        overrides={"frame_rate": int(audio_segment.frame_rate * speed)},
    ).set_frame_rate(audio_segment.frame_rate)


def change_volume(audio_segment, level=1.0):
    if level == 1.0:
        return audio_segment

    db_change = 20 * math.log10(level)
    return audio_segment.apply_gain(db_change)


def create_silence(duration_ms):
    try:
        return AudioSegment.silent(duration=duration_ms)
    except ImportError:
        logger.error("pydub not installed. Audio processing unavailable.")
        return None


def create_noise(duration_ms, level=0.05, sample_rate=44100):
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
    try:
        return audio1.overlay(audio2, position=position_ms)
    except Exception:
        logger.error("Audio overlay failed")
        try:
            if audio1.frame_rate != audio2.frame_rate:
                audio2 = audio2.set_frame_rate(audio1.frame_rate)
            if audio1.channels != audio2.channels:
                audio2 = audio2.set_channels(audio1.channels)
            if audio1.sample_width != audio2.sample_width:
                audio2 = audio2.set_sample_width(audio1.sample_width)

            return audio1.overlay(audio2, position=position_ms)
        except Exception:
            logger.error("Second audio overlay attempt failed")
            return audio1


def batch_mix_audio(base_audio, segments_with_positions):
    result = base_audio

    segments_with_positions.sort(key=lambda x: x[1])

    batch_size = 10
    for i in range(0, len(segments_with_positions), batch_size):
        batch = segments_with_positions[i : i + batch_size]

        for segment, position in batch:
            result = mix_audio(result, segment, position)

    return result


def bytes_to_audio_segment(audio_bytes):
    try:
        wav_io = io.BytesIO(audio_bytes)
        return AudioSegment.from_wav(wav_io)
    except ImportError:
        logger.error("pydub not installed. Audio processing unavailable.")
        return None


def combine_audio_files(audio_files):
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
            except Exception:
                logger.error("Error converting audio bytes to segment")

        if not segments:
            logger.error("No valid audio segments found")
            return None

        result = create_silence(secure_random.randint(200, 500))

        for segment in segments:
            result += segment
            result += create_silence(secure_random.randint(300, 700))

        noise_level = secure_random.uniform(0.01, 0.03)
        result = add_background_noise(result, noise_level)

        output_io = io.BytesIO()
        result.export(output_io, format="mp3")
        output_io.seek(0)

        return output_io.read()
    except ImportError:
        logger.error("pydub not installed. Audio processing unavailable.")
        return None


def add_background_noise(audio_segment, noise_level=0.05):
    noise = create_noise(len(audio_segment), level=noise_level)
    return mix_audio(audio_segment, noise)
