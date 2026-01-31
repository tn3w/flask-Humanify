from dataclasses import dataclass, field
import fnmatch
import logging
import re
import secrets
from typing import Optional

try:
    import re2 as regex_engine  # type: ignore
    USING_RE2 = True
except ImportError:
    import re as regex_engine
    USING_RE2 = False

import crawleruseragents
from flask import (
    Blueprint,
    abort,
    current_app,
    g,
    redirect,
    render_template,
    request,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.wrappers import Response

from .memory_server import MemoryClient, ensure_server_running
from .utils import (
    audio_bytes_to_data_url,
    combine_audio_files,
    generate_captcha_token,
    generate_clearance_token,
    generate_csrf_token,
    generate_user_hash,
    get_or_create_client_id,
    get_next_url,
    image_bytes_to_data_url,
    is_valid_routable_ip,
    manipulate_image_bytes,
    validate_captcha_token,
    validate_clearance_token,
    verify_request_csrf,
)

logger = logging.getLogger(__name__)
secure_random = secrets.SystemRandom()

DEFAULT_EXEMPT_PATTERNS = [
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/*",
    "/apple-touch-icon*.png",
    "/browserconfig.xml",
    "/manifest.json",
    "/site.webmanifest",
    "/_health",
    "/_healthz",
    "/health",
    "/healthz",
    "/ping",
    "/status",
]

VPN_PROVIDERS = [
    "NordVPN",
    "ProtonVPN",
    "ExpressVPN",
    "Surfshark",
    "PrivateInternetAccess",
    "CyberGhost",
    "TunnelBear",
    "Mullvad",
]

IMAGE_CAPTCHA_MAPPING = {
    "grid": {
        "num_correct": (2, 3),
        "num_images": 9,
        "preview_image": False,
        "hardness_range": (1, 3),
    },
    "one_click": {
        "num_correct": 1,
        "num_images": 6,
        "preview_image": True,
        "hardness_range": (1, 3),
    },
}

AUDIO_CAPTCHA_CONFIG = {
    "num_chars": 6,
    "languages": [
        "es",
        "ko",
        "ja",
        "hi",
        "zh-CN",
        "pt",
        "it",
        "de",
        "ru",
        "en",
        "ar",
        "fr",
    ],
}


@dataclass
class HumanifyResult:
    ip: Optional[str] = field(default=None)
    is_vpn: bool = field(default=False)
    vpn_provider: Optional[str] = field(default=None)
    is_proxy: bool = field(default=False)
    is_datacenter: bool = field(default=False)
    is_forum_spammer: bool = field(default=False)
    is_firehol: bool = field(default=False)
    is_tor_exit_node: bool = field(default=False)
    is_invalid_ip: bool = field(default=False)
    is_crawler: bool = field(default=False)
    crawler_name: Optional[str] = field(default=None)

    @property
    def is_bot(self):
        return (
            self.is_invalid_ip
            or self.is_vpn
            or self.is_proxy
            or self.is_datacenter
            or self.is_forum_spammer
            or self.is_firehol
            or self.is_tor_exit_node
            or self.is_crawler
        )

    @classmethod
    def from_ip_groups(cls, ip, ip_groups, user_agent=None):
        vpn_provider = next(
            (name for name in VPN_PROVIDERS if name in ip_groups),
            None,
        )

        is_crawler = False
        crawler_name = None
        if user_agent:
            is_crawler = crawleruseragents.is_crawler(user_agent)
            if is_crawler:
                crawler_name = user_agent.split("/")[0].strip()

        is_proxy = "FireholProxies" in ip_groups or "AwesomeProxies" in ip_groups

        return cls(
            ip=ip,
            is_vpn=vpn_provider is not None,
            vpn_provider=vpn_provider,
            is_proxy=is_proxy,
            is_datacenter="Datacenter" in ip_groups,
            is_forum_spammer="StopForumSpam" in ip_groups,
            is_firehol="FireholLevel1" in ip_groups,
            is_tor_exit_node="TorExitNodes" in ip_groups,
            is_crawler=is_crawler,
            crawler_name=crawler_name,
        )

    def __bool__(self):
        return self.is_bot


def compile_patterns(patterns):
    compiled = []
    for pattern in patterns:
        if pattern is None:
            continue

        if not validate_regex_complexity(pattern):
            logger.warning(f"Pattern too complex, skipping: {pattern[:50]}")
            continue

        if "*" in pattern or "?" in pattern:
            regex_pattern = fnmatch.translate(pattern)
            try:
                compiled.append(regex_engine.compile(regex_pattern))
            except (re.error, Exception):
                continue
        else:
            try:
                compiled.append(regex_engine.compile(pattern))
            except (re.error, Exception):
                try:
                    compiled.append(regex_engine.compile(re.escape(pattern)))
                except (re.error, Exception):
                    continue

    return compiled


def validate_regex_complexity(pattern: str, max_length: int = 200) -> bool:
    """
    Validate regex complexity to prevent ReDoS attacks.
    Returns True if pattern is safe to compile.
    """
    if not isinstance(pattern, str) or len(pattern) > max_length:
        return False

    repetition_count = pattern.count("*") + pattern.count("+") + pattern.count("{")
    if repetition_count > 10:
        return False

    nested_quantifier_patterns = [
        r'\([^)]*[*+]\)[*+{]',
        r'[*+]\s*[*+]',
    ]
    for dangerous_pattern in nested_quantifier_patterns:
        try:
            if re.search(dangerous_pattern, pattern):
                return False
        except re.error:
            pass

    nested_groups = 0
    max_nesting = 3
    for char in pattern:
        if char == "(":
            nested_groups += 1
            if nested_groups > max_nesting:
                return False
        elif char == ")":
            nested_groups = max(0, nested_groups - 1)

    if pattern.count("|") > 5:
        return False

    if pattern.count("[") > 10:
        return False

    return True


def matches_any_pattern(endpoint, path, compiled_patterns):
    for pattern in compiled_patterns:
        if endpoint is not None and pattern.search(endpoint):
            return True
        if path is not None and pattern.search(path):
            return True
    return False


def matches_request_filters(request_filters):
    for key, value in request_filters.items():
        parts = key.split(".")
        obj = request

        for part in parts[:-1]:
            if hasattr(obj, part):
                obj = getattr(obj, part)
            elif isinstance(obj, dict) and part in obj:
                obj = obj[part]
            else:
                return False

        final_attr = parts[-1]

        if hasattr(obj, final_attr):
            attr_value = getattr(obj, final_attr)
        elif isinstance(obj, dict) and final_attr in obj:
            attr_value = obj[final_attr]
        else:
            return False

        if isinstance(value, str) and value.startswith("regex:"):
            regex_pattern = value[6:]
            if not validate_regex_complexity(regex_pattern):
                return False
            try:
                if not re.search(regex_pattern, str(attr_value)):
                    return False
            except (re.error, TypeError):
                return False
        elif isinstance(value, list):
            if attr_value not in value:
                return False
        elif attr_value != value:
            return False

    return True


def get_client_ip():
    if hasattr(g, "humanify_client_ip"):
        return g.humanify_client_ip

    remote_addr = request.remote_addr or "127.0.0.1"
    client_ip = request.remote_addr if is_valid_routable_ip(remote_addr) else None
    g.humanify_client_ip = client_ip
    return client_ip


def get_client_id(use_client_id, client_ip, secret_key):
    if hasattr(g, "humanify_client_id"):
        return g.humanify_client_id

    client_id = get_or_create_client_id(
        request,
        client_ip,
        secret_key,
        use_client_id,
    )
    g.humanify_client_id = client_id
    return client_id


def get_check_result(memory_client, client_ip):
    if client_ip is None:
        return HumanifyResult(ip=client_ip, is_invalid_ip=True)

    user_agent = request.user_agent.string or ""

    if hasattr(g, "humanify_ip_groups"):
        humanify_ip_groups = g.humanify_ip_groups
        if isinstance(humanify_ip_groups, list):
            return HumanifyResult.from_ip_groups(
                client_ip,
                humanify_ip_groups,
                user_agent,
            )

    ip_groups = memory_client.lookup_ip(client_ip)
    g.humanify_ip_groups = ip_groups
    return HumanifyResult.from_ip_groups(
        client_ip,
        ip_groups,
        user_agent,
    )


def has_valid_clearance_token(secret_key, client_ip):
    return validate_clearance_token(
        request.cookies.get("clearance_token", ""),
        secret_key,
        generate_user_hash(
            client_ip or "127.0.0.1",
            request.user_agent.string or "",
        ),
    )


def check_attempt_limit(memory_client, client_id, retrys):
    is_limit_reached = memory_client.is_attempt_limit_reached(
        client_id,
        retrys,
    )
    if is_limit_reached:
        return deny_access()
    return None


def deny_access():
    return redirect(
        url_for(
            "humanify.access_denied",
            next=request.full_path.rstrip("?"),
        )
    )


def challenge_request():
    return redirect(
        url_for(
            "humanify.challenge",
            next=request.full_path.rstrip("?"),
        )
    )


def render_challenge(humanify_instance, memory_client, secret_key, is_audio=False):
    next_url = get_next_url(request)
    client_ip = get_client_ip()

    if has_valid_clearance_token(secret_key, client_ip):
        return redirect(next_url)

    client_id = get_client_id(
        humanify_instance.use_client_id,
        client_ip,
        secret_key,
    )
    limit_response = check_attempt_limit(
        memory_client,
        client_id,
        humanify_instance.retrys,
    )
    if limit_response:
        return limit_response

    error = request.args.get("error", None)
    valid_errors = [
        "Invalid captcha token",
        "Wrong selection. Try again.",
        "Wrong response. Try again.",
    ]
    if error not in valid_errors:
        error = None

    if is_audio:
        return render_audio_challenge(
            humanify_instance,
            memory_client,
            secret_key,
            next_url,
            error,
        )

    if humanify_instance.challenge_type in ["grid", "one_click"]:
        return render_image_challenge(
            humanify_instance,
            memory_client,
            secret_key,
            next_url,
            error,
        )

    abort(404, "Invalid challenge type")


def render_image_challenge(
    humanify_instance,
    memory_client,
    secret_key,
    next_url,
    error,
):
    captcha_config = IMAGE_CAPTCHA_MAPPING[humanify_instance.challenge_type]
    use_preview_image = captcha_config["preview_image"]

    result = memory_client.get_captcha_images(
        dataset=humanify_instance.image_dataset,
        count=captcha_config["num_images"],
        correct=captcha_config["num_correct"],
        preview=use_preview_image,
    )
    images_bytes, correct_indexes, subject = result

    if not images_bytes:
        abort(500, "Could not load captcha images")

    processed_images = process_captcha_images(
        images_bytes,
        use_preview_image,
        captcha_config,
        humanify_instance.hardness,
    )

    preview_image = None
    if use_preview_image:
        preview_image = processed_images[0]
        processed_images = processed_images[1:]

    client_ip = get_client_ip()
    user_hash = generate_user_hash(
        client_ip or "127.0.0.1",
        request.user_agent.string or "",
    )
    captcha_data = generate_captcha_token(
        user_hash,
        correct_indexes,
        secret_key,
    )

    csrf_token = generate_csrf_token(request, secret_key)

    response = Response(
        render_template(
            f"{humanify_instance.challenge_type}_challenge.html",
            images=processed_images,
            preview_image=preview_image,
            subject=subject,
            captcha_data=captcha_data,
            next=next_url or "/",
            error=error,
            audio_challenge_available=humanify_instance.audio_dataset is not None,
            csrf_token=csrf_token,
        ),
        mimetype="text/html",
    )

    if hasattr(g, "humanify_csrf_cookie"):
        is_secure = (
            request.is_secure or request.headers.get("X-Forwarded-Proto", "") == "https"
        )
        response.set_cookie(
            "csrf_token",
            g.humanify_csrf_cookie,
            max_age=1800,
            httponly=True,
            samesite="Strict",
            secure=is_secure,
        )

    return response


def process_captcha_images(
    images_bytes,
    use_preview_image,
    captcha_config,
    hardness,
):
    processed_images = []
    for i, img_bytes in enumerate(images_bytes):
        try:
            is_small = not (i == 0 and use_preview_image)
            hardness_min = captcha_config["hardness_range"][0]
            hardness_max = captcha_config["hardness_range"][1]
            image_hardness = secure_random.randint(
                max(hardness_min + hardness - 1, 1),
                max(hardness_max + hardness - 1, 5),
            )
            distorted_img_bytes = manipulate_image_bytes(
                img_bytes,
                is_small=is_small,
                hardness=image_hardness,
            )
            data_url = image_bytes_to_data_url(distorted_img_bytes)
            processed_images.append(data_url)
        except Exception:
            current_app.logger.error("Error processing image")
            fallback_image = (
                "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB"
                "CAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
            )
            processed_images.append(fallback_image)

    return processed_images


def render_audio_challenge(
    humanify_instance,
    memory_client,
    secret_key,
    next_url,
    error,
):
    num_chars = AUDIO_CAPTCHA_CONFIG["num_chars"] + humanify_instance.hardness - 1
    languages = AUDIO_CAPTCHA_CONFIG["languages"]
    language = request.accept_languages.best_match(languages) or "en"

    audio_files, correct_chars = memory_client.get_captcha_audio(
        dataset=humanify_instance.audio_dataset,
        chars=num_chars,
        lang=language,
    )

    if not audio_files:
        abort(500, "Could not load captcha audio")

    combined_audio = combine_audio_files(audio_files)
    if not combined_audio:
        abort(500, "Could not process audio files")

    audio_data_url = audio_bytes_to_data_url(combined_audio, "mp3")

    client_ip = get_client_ip()
    user_hash = generate_user_hash(
        client_ip or "127.0.0.1",
        request.user_agent.string or "",
    )
    captcha_data = generate_captcha_token(
        user_hash,
        correct_chars,
        secret_key,
    )

    csrf_token = generate_csrf_token(request, secret_key)

    response = Response(
        render_template(
            "audio_challenge.html",
            audio_file=audio_data_url,
            captcha_data=captcha_data,
            next=next_url or "/",
            error=error,
            image_challenge_available=humanify_instance.image_dataset is not None,
            csrf_token=csrf_token,
        ),
        mimetype="text/html",
    )

    if hasattr(g, "humanify_csrf_cookie"):
        is_secure = (
            request.is_secure or request.headers.get("X-Forwarded-Proto", "") == "https"
        )
        response.set_cookie(
            "csrf_token",
            g.humanify_csrf_cookie,
            max_age=1800,
            httponly=True,
            samesite="Strict",
            secure=is_secure,
        )

    return response


def verify_captcha(humanify_instance, memory_client, secret_key):
    if not verify_request_csrf(request, secret_key):
        abort(403, "Invalid CSRF token")

    next_url = get_next_url(request)
    client_ip = get_client_ip()

    if has_valid_clearance_token(secret_key, client_ip):
        return redirect(next_url)

    client_id = get_client_id(
        humanify_instance.use_client_id,
        client_ip,
        secret_key,
    )
    limit_response = check_attempt_limit(
        memory_client,
        client_id,
        humanify_instance.retrys,
    )
    if limit_response:
        return limit_response

    captcha_data = request.form.get("captcha_data", "")
    if not captcha_data:
        return redirect(
            url_for(
                "humanify.challenge",
                error="Invalid captcha token",
                next=next_url,
            )
        )

    user_hash = generate_user_hash(
        client_ip or "127.0.0.1",
        request.user_agent.string or "",
    )
    decrypted_data = validate_captcha_token(
        captcha_data,
        secret_key,
        user_hash,
    )

    if decrypted_data is None:
        return redirect(
            url_for(
                "humanify.challenge",
                error="Invalid captcha token",
                next=next_url,
            )
        )

    verify_functions = {
        "grid": verify_image_captcha,
        "one_click": verify_image_captcha,
    }

    verify_function = verify_functions[humanify_instance.challenge_type]
    if not verify_function(humanify_instance, decrypted_data):
        memory_client.record_failed_attempt(client_id)
        return redirect(
            url_for(
                "humanify.challenge",
                error="Wrong selection. Try again.",
                next=next_url,
            )
        )

    clearance_token = generate_clearance_token(
        user_hash,
        secret_key,
    )

    response = redirect(next_url or "/")

    is_secure = (
        request.is_secure or request.headers.get("X-Forwarded-Proto", "") == "https"
    )

    response.set_cookie(
        "clearance_token",
        clearance_token,
        max_age=7200,
        httponly=True,
        samesite="Strict",
        secure=is_secure,
    )

    return response


def verify_image_captcha(humanify_instance, decrypted_data):
    captcha_config = IMAGE_CAPTCHA_MAPPING[humanify_instance.challenge_type]

    selected_indexes = []
    for i in range(1, captcha_config["num_images"] + 1):
        if request.form.get(str(i), None) == "1":
            selected_indexes.append(str(i - 1))

    selected_str = "".join(sorted(selected_indexes))
    correct_str = "".join(sorted(list(decrypted_data)))

    return selected_str == correct_str


def verify_audio_captcha(humanify_instance, memory_client, secret_key):
    if not verify_request_csrf(request, secret_key):
        abort(403, "Invalid CSRF token")

    next_url = get_next_url(request)
    client_ip = get_client_ip()

    if has_valid_clearance_token(secret_key, client_ip):
        return redirect(next_url)

    client_id = get_client_id(
        humanify_instance.use_client_id,
        client_ip,
        secret_key,
    )
    limit_response = check_attempt_limit(
        memory_client,
        client_id,
        humanify_instance.retrys,
    )
    if limit_response:
        return limit_response

    captcha_data = request.form.get("captcha_data", "")
    if not captcha_data:
        return redirect(
            url_for(
                "humanify.audio_challenge",
                error="Invalid captcha token",
                next=next_url,
            )
        )

    user_hash = generate_user_hash(
        client_ip or "127.0.0.1",
        request.user_agent.string or "",
    )
    correct_chars = validate_captcha_token(
        captcha_data,
        secret_key,
        user_hash,
        valid_lengths=[197],
    )

    if correct_chars is None:
        return redirect(
            url_for(
                "humanify.audio_challenge",
                error="Invalid captcha token",
                next=next_url,
            )
        )

    audio_response = request.form.get("audio_response", "").lower().strip()
    if not audio_response or audio_response != correct_chars:
        memory_client.record_failed_attempt(client_id)
        return redirect(
            url_for(
                "humanify.audio_challenge",
                error="Wrong response. Try again.",
                next=next_url,
            )
        )

    clearance_token = generate_clearance_token(
        user_hash,
        secret_key,
    )

    response = redirect(next_url or "/")

    is_secure = (
        request.is_secure or request.headers.get("X-Forwarded-Proto", "") == "https"
    )

    response.set_cookie(
        "clearance_token",
        clearance_token,
        max_age=7200,
        httponly=True,
        samesite="Strict",
        secure=is_secure,
    )

    return response


class Humanify:
    def __init__(
        self,
        app=None,
        challenge_type="one_click",
        image_dataset="ai_dogs",
        audio_dataset=None,
        retrys=3,
        hardness=1,
        behind_proxy=False,
        use_client_id=False,
    ):
        self._options = {
            "challenge_type": challenge_type,
            "image_dataset": image_dataset,
            "audio_dataset": audio_dataset,
            "retrys": retrys,
            "hardness": hardness,
            "behind_proxy": behind_proxy,
            "use_client_id": use_client_id,
        }
        if app is not None:
            self.init_app(app, **self._options)

    def init_app(self, app, **kwargs):
        options = self._options.copy()
        options.update(kwargs)

        self.challenge_type = options["challenge_type"]
        self.image_dataset = options["image_dataset"]
        self.audio_dataset = options["audio_dataset"]
        self.retrys = options["retrys"]
        self.hardness = options["hardness"]
        self.behind_proxy = options["behind_proxy"]
        self.use_client_id = options["use_client_id"]

        if not isinstance(app.wsgi_app, ProxyFix) and self.behind_proxy:
            app.wsgi_app = ProxyFix(
                app.wsgi_app,
                x_for=1,
                x_proto=1,
                x_host=1,
                x_port=1,
            )

        app.config.setdefault("HUMANIFY_USE_CLIENT_ID", self.use_client_id)

        ensure_server_running(
            image_dataset=self.image_dataset,
            audio_dataset=self.audio_dataset,
        )

        memory_client = MemoryClient()
        memory_client.connect()
        secret_key = memory_client.get_secret_key()

        if not app.secret_key:
            app.secret_key = secret_key
        app.config.setdefault("SECRET_KEY", secret_key)

        app.config.setdefault("HUMANIFY_SECRET_KEY", secret_key)
        app.config.setdefault("HUMANIFY_MEMORY_CLIENT", memory_client)

        blueprint = Blueprint(
            "humanify",
            __name__,
            template_folder="templates",
            static_folder=None,
        )

        register_routes(blueprint, self, memory_client, secret_key)
        app.register_blueprint(blueprint)

    def register_middleware(
        self,
        app,
        action="challenge",
        endpoint_patterns=None,
        url_patterns=None,
        exclude_patterns=None,
        request_filters=None,
        use_default_exemptions=True,
    ):
        app = app or current_app

        if isinstance(endpoint_patterns, str):
            endpoint_patterns = [endpoint_patterns]
        if isinstance(url_patterns, str):
            url_patterns = [url_patterns]
        if isinstance(exclude_patterns, str):
            exclude_patterns = [exclude_patterns]

        if use_default_exemptions:
            exclude_patterns = DEFAULT_EXEMPT_PATTERNS + (exclude_patterns or [])

        compiled_endpoint_patterns = (
            compile_patterns(endpoint_patterns) if endpoint_patterns else None
        )
        compiled_url_patterns = compile_patterns(url_patterns) if url_patterns else None
        compiled_exclude_patterns = (
            compile_patterns(exclude_patterns) if exclude_patterns else None
        )

        memory_client = app.config.get("HUMANIFY_MEMORY_CLIENT")
        secret_key = app.config.get("HUMANIFY_SECRET_KEY")

        @app.before_request
        def humanify_before_request():
            if request.endpoint and request.endpoint.startswith("humanify."):
                return

            if hasattr(g, "humanify_exempt"):
                return

            if action not in ["challenge", "deny_access", "always_challenge"]:
                return

            current_endpoint = request.endpoint or ""
            current_path = request.path

            if compiled_exclude_patterns and matches_any_pattern(
                current_endpoint,
                current_path,
                compiled_exclude_patterns,
            ):
                return

            patterns_specified = (
                compiled_endpoint_patterns is not None
                or compiled_url_patterns is not None
            )

            matches_endpoint = not patterns_specified or (
                compiled_endpoint_patterns
                and matches_any_pattern(
                    current_endpoint,
                    None,
                    compiled_endpoint_patterns,
                )
            )

            matches_url = not patterns_specified or (
                compiled_url_patterns
                and matches_any_pattern(
                    None,
                    current_path,
                    compiled_url_patterns,
                )
            )

            matches_filters = not request_filters or matches_request_filters(
                request_filters
            )

            should_check = (matches_endpoint or matches_url) and matches_filters

            if should_check:
                client_ip = get_client_ip()
                client_id = get_client_id(
                    self.use_client_id,
                    client_ip,
                    secret_key,
                )
                limit_response = check_attempt_limit(
                    memory_client,
                    client_id,
                    self.retrys,
                )
                if limit_response:
                    return limit_response

                check_result = get_check_result(
                    memory_client,
                    client_ip,
                )
                is_bot = check_result.is_bot

                if is_bot and action == "deny_access":
                    return deny_access()

                has_valid_token = has_valid_clearance_token(
                    secret_key,
                    client_ip,
                )

                if not has_valid_token:
                    if action == "always_challenge" or is_bot:
                        return challenge_request()

        if self.use_client_id:

            @app.after_request
            def humanify_after_request(response):
                if hasattr(g, "humanify_new_client_id"):
                    is_secure = (
                        request.is_secure
                        or request.headers.get("X-Forwarded-Proto", "") == "https"
                    )

                    response.set_cookie(
                        "client_id",
                        g.humanify_new_client_id,
                        max_age=7200,
                        httponly=True,
                        samesite="Strict",
                        secure=is_secure,
                    )
                return response


def register_routes(blueprint, humanify_instance, memory_client, secret_key):
    @blueprint.route("/humanify/challenge", methods=["GET"])
    def challenge():
        if humanify_instance.image_dataset is None:
            return render_challenge(
                humanify_instance,
                memory_client,
                secret_key,
                is_audio=True,
            )
        return render_challenge(humanify_instance, memory_client, secret_key)

    @blueprint.route("/humanify/audio_challenge", methods=["GET"])
    def audio_challenge():
        if humanify_instance.audio_dataset is None:
            return redirect(
                url_for(
                    "humanify.challenge",
                    next=request.full_path.rstrip("?"),
                )
            )
        return render_challenge(
            humanify_instance,
            memory_client,
            secret_key,
            is_audio=True,
        )

    @blueprint.route("/humanify/verify", methods=["POST"])
    def verify():
        if humanify_instance.image_dataset is None:
            abort(404)
        return verify_captcha(humanify_instance, memory_client, secret_key)

    @blueprint.route("/humanify/verify_audio", methods=["POST"])
    def verify_audio():
        if humanify_instance.audio_dataset is None:
            abort(404)
        return verify_audio_captcha(humanify_instance, memory_client, secret_key)

    @blueprint.route("/humanify/access_denied", methods=["GET"])
    def access_denied():
        return (
            render_template("access_denied.html", next=get_next_url(request)),
            403,
            {"Cache-Control": "public, max-age=15552000"},
        )


def require_human(action="challenge"):
    def decorator(f):
        def wrapped_function(*args, **kwargs):
            memory_client = current_app.config.get("HUMANIFY_MEMORY_CLIENT")
            secret_key = current_app.config.get("HUMANIFY_SECRET_KEY")

            if not memory_client or not secret_key:
                logger.warning("Humanify not initialized, skipping protection")
                return f(*args, **kwargs)

            client_ip = get_client_ip()
            client_id = get_client_id(
                current_app.config.get("HUMANIFY_USE_CLIENT_ID", False),
                client_ip,
                secret_key,
            )

            check_result = get_check_result(memory_client, client_ip)
            is_bot = check_result.is_bot

            has_valid_token = has_valid_clearance_token(secret_key, client_ip)

            if not has_valid_token and is_bot:
                if action == "deny_access":
                    return deny_access()
                else:
                    return challenge_request()

            return f(*args, **kwargs)

        wrapped_function.__name__ = f.__name__
        wrapped_function.__module__ = f.__module__
        return wrapped_function

    return decorator


def always_challenge(f):
    def wrapped_function(*args, **kwargs):
        secret_key = current_app.config.get("HUMANIFY_SECRET_KEY")

        if not secret_key:
            logger.warning("Humanify not initialized, skipping protection")
            return f(*args, **kwargs)

        client_ip = get_client_ip()
        has_valid_token = has_valid_clearance_token(secret_key, client_ip)

        if not has_valid_token:
            return challenge_request()

        return f(*args, **kwargs)

    wrapped_function.__name__ = f.__name__
    wrapped_function.__module__ = f.__module__
    return wrapped_function


def block_bots(f):
    def wrapped_function(*args, **kwargs):
        memory_client = current_app.config.get("HUMANIFY_MEMORY_CLIENT")

        if not memory_client:
            logger.warning("Humanify not initialized, skipping protection")
            return f(*args, **kwargs)

        client_ip = get_client_ip()
        check_result = get_check_result(memory_client, client_ip)

        if check_result.is_bot:
            return deny_access()

        return f(*args, **kwargs)

    wrapped_function.__name__ = f.__name__
    wrapped_function.__module__ = f.__module__
    return wrapped_function


def exempt_from_protection(f):
    def wrapped_function(*args, **kwargs):
        g.humanify_exempt = True
        return f(*args, **kwargs)

    wrapped_function.__name__ = f.__name__
    wrapped_function.__module__ = f.__module__
    return wrapped_function
