from dataclasses import dataclass
import logging
import random
from typing import List, Optional, Union, Dict, Any, Pattern
import re
import fnmatch

import crawleruseragents
from werkzeug.wrappers import Response
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import (
    Flask,
    Blueprint,
    request,
    render_template,
    redirect,
    url_for,
    current_app,
    g,
    abort,
)
from .memory_server import MemoryClient, ensure_server_running
from .utils import (
    is_valid_routable_ip,
    get_return_url,
    get_or_create_client_id,
    validate_clearance_token,
    generate_user_hash,
    manipulate_image_bytes,
    image_bytes_to_data_url,
    generate_captcha_token,
    validate_captcha_token,
    generate_clearance_token,
    combine_audio_files,
    audio_bytes_to_data_url,
)


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
    "language": "en",
}

logger = logging.getLogger(__name__)


@dataclass
class HumanifyResult:
    """
    Result of the Humanify check.
    """

    ip: Optional[str] = None
    is_vpn: bool = False
    vpn_provider: Optional[str] = None
    is_proxy: bool = False
    is_datacenter: bool = False
    is_forum_spammer: bool = False
    is_firehol: bool = False
    is_tor_exit_node: bool = False
    is_invalid_ip: bool = False
    is_crawler: bool = False
    crawler_name: Optional[str] = None

    @property
    def is_bot(self) -> bool:
        """
        Check if the IP is a bot.
        """
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
    def from_ip_groups(
        cls, ip: str, ip_groups: List[str], user_agent: Optional[str] = None
    ) -> "HumanifyResult":
        """
        Create a HumanifyResult from a list of IP groups and optional user agent.
        """
        vpn_provider = next((name for name in VPN_PROVIDERS if name in ip_groups), None)

        is_crawler = False
        crawler_name = None
        if user_agent:
            is_crawler = crawleruseragents.is_crawler(user_agent)
            if is_crawler:
                crawler_name = user_agent.split("/")[0].strip()

        result = HumanifyResult(
            ip=ip,
            is_vpn=vpn_provider is not None,
            vpn_provider=vpn_provider,
            is_proxy="FireholProxies" in ip_groups or "AwesomeProxies" in ip_groups,
            is_datacenter="Datacenter" in ip_groups,
            is_forum_spammer="StopForumSpam" in ip_groups,
            is_firehol="FireholLevel1" in ip_groups,
            is_tor_exit_node="TorExitNodes" in ip_groups,
            is_crawler=is_crawler,
            crawler_name=crawler_name,
        )
        return result

    def __bool__(self) -> bool:
        """
        Check if the IP is a bot.
        """
        return self.is_bot


class Humanify:
    """
    Protect against bots and DDoS attacks.
    """

    def __init__(
        self,
        app=None,
        challenge_type: str = "one_click",
        image_dataset: Optional[str] = "ai_dogs",
        audio_dataset: Optional[str] = None,
        retrys: int = 3,
        behind_proxy: bool = True,
        use_client_id: bool = False,
    ) -> None:
        self.app = app
        self.challenge_type = challenge_type
        self.image_dataset = image_dataset
        self.audio_dataset = audio_dataset
        self.retrys = retrys + 1
        self.behind_proxy = behind_proxy
        self.use_client_id = use_client_id
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """
        Initialize the Humanify extension.
        """
        self.app = app
        if not isinstance(app.wsgi_app, ProxyFix) and self.behind_proxy:
            app.wsgi_app = ProxyFix(
                app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1
            )
        self.app.config.setdefault("HUMANIFY_USE_CLIENT_ID", self.use_client_id)

        ensure_server_running(
            image_dataset=self.image_dataset,
            audio_dataset=self.audio_dataset,
        )
        self.memory_client = MemoryClient()
        self.memory_client.connect()
        self._secret_key = self.memory_client.get_secret_key()

        self.app.config.setdefault("HUMANIFY_SECRET_KEY", self._secret_key)

        self.blueprint = Blueprint(
            "humanify", __name__, template_folder="templates", static_folder=None
        )
        self._register_routes()
        app.register_blueprint(self.blueprint)

    def _register_routes(self) -> None:
        """Register the humanify routes."""

        @self.blueprint.route("/humanify/challenge", methods=["GET"])
        def challenge():
            """
            Challenge route.
            """
            if self.image_dataset is None:
                return self._render_challenge(is_audio=True)

            return self._render_challenge()

        @self.blueprint.route("/humanify/audio_challenge", methods=["GET"])
        def audio_challenge():
            """
            Audio challenge route.
            """
            if self.audio_dataset is None:
                return redirect(
                    url_for(
                        "humanify.challenge", return_url=request.full_path.rstrip("?")
                    )
                )

            return self._render_challenge(is_audio=True)

        @self.blueprint.route("/humanify/verify", methods=["POST"])
        def verify():
            """
            Verify route.
            """
            if self.image_dataset is None:
                abort(404)

            return self._verify_captcha()

        @self.blueprint.route("/humanify/verify_audio", methods=["POST"])
        def verify_audio():
            """
            Verify audio route.
            """
            if self.audio_dataset is None:
                abort(404)

            return self._verify_audio_captcha()

        @self.blueprint.route("/humanify/access_denied", methods=["GET"])
        def access_denied():
            """
            Access denied route.
            """
            return (
                render_template("access_denied.html").replace(
                    "RETURN_URL", get_return_url(request)
                ),
                403,
                {"Cache-Control": "public, max-age=15552000"},
            )

    def register_middleware(
        self,
        action: str = "challenge",
        endpoint_patterns: Union[str, List[str], None] = None,
        url_patterns: Union[str, List[str], None] = None,
        exclude_patterns: Union[str, List[str], None] = None,
        request_filters: Optional[Dict[str, Any]] = None,
    ):
        """
        Register the middleware with advanced filtering options.

        Args:
            action: The action to take when a bot is detected ('challenge' or 'deny_access')
            endpoint_patterns: Endpoint patterns to match (regex or glob patterns)
            url_patterns: URL patterns to match (regex or glob patterns)
            exclude_patterns: Patterns to exclude from protection (regex or glob patterns)
            request_filters: Dict of request attributes and values to filter by
        """
        self.app = self.app or current_app

        if isinstance(endpoint_patterns, str):
            endpoint_patterns = [endpoint_patterns]
        if isinstance(url_patterns, str):
            url_patterns = [url_patterns]
        if isinstance(exclude_patterns, str):
            exclude_patterns = [exclude_patterns]

        compiled_endpoint_patterns = (
            self._compile_patterns(endpoint_patterns) if endpoint_patterns else None
        )
        compiled_url_patterns = (
            self._compile_patterns(url_patterns) if url_patterns else None
        )
        compiled_exclude_patterns = (
            self._compile_patterns(exclude_patterns) if exclude_patterns else None
        )

        @self.app.before_request
        def before_request():
            """
            Before request hook with advanced filtering.
            """
            if request.endpoint and request.endpoint.startswith("humanify."):
                return

            if action not in ["challenge", "deny_access", "always_challenge"]:
                return

            current_endpoint = request.endpoint or ""
            current_path = request.path

            if compiled_exclude_patterns and self._matches_any_pattern(
                current_endpoint, current_path, compiled_exclude_patterns
            ):
                return

            patterns_specified = (
                compiled_endpoint_patterns is not None
                or compiled_url_patterns is not None
            )

            matches_endpoint = not patterns_specified or (
                compiled_endpoint_patterns
                and self._matches_any_pattern(
                    current_endpoint, None, compiled_endpoint_patterns
                )
            )

            matches_url = not patterns_specified or (
                compiled_url_patterns
                and self._matches_any_pattern(None, current_path, compiled_url_patterns)
            )

            matches_request_filters = (
                not request_filters or self._matches_request_filters(request_filters)
            )

            if (matches_endpoint or matches_url) and matches_request_filters:
                limit_response = self._check_attempt_limit()
                if limit_response:
                    return limit_response

                is_bot = self.check_result.is_bot
                if is_bot and action == "deny_access":
                    return self.deny_access()

                if not self.has_valid_clearance_token:
                    if action == "always_challenge" or is_bot:
                        return self.challenge()

        if self.use_client_id:

            @self.app.after_request
            def after_request(response):
                """
                After request hook to set client ID cookie if needed.
                """
                if hasattr(g, "humanify_new_client_id"):
                    response.set_cookie(
                        "client_id",
                        g.humanify_new_client_id,
                        max_age=14400,
                        httponly=True,
                        samesite="Strict",
                    )
                return response

    def _compile_patterns(self, patterns):
        """
        Compile a list of patterns into regex patterns.
        Handles glob patterns like * and ? by converting them to regex.
        """
        compiled = []
        for pattern in patterns:
            if pattern is None:
                continue

            if "*" in pattern or "?" in pattern:
                regex_pattern = fnmatch.translate(pattern)
                compiled.append(re.compile(regex_pattern))
            else:
                try:
                    compiled.append(re.compile(pattern))
                except re.error:
                    compiled.append(re.compile(re.escape(pattern)))

        return compiled

    def _matches_any_pattern(
        self,
        endpoint: Optional[str],
        path: Optional[str],
        compiled_patterns: List[Pattern],
    ):
        """
        Check if the current endpoint or path matches any of the compiled patterns.
        """
        for pattern in compiled_patterns:
            if endpoint is not None and pattern.search(endpoint):
                return True
            if path is not None and pattern.search(path):
                return True
        return False

    def _matches_request_filters(self, request_filters: Dict[str, Any]) -> bool:
        """
        Check if the current request matches all the specified filters.
        Filters can target any attribute of the request object or its nested properties.
        """
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

    @property
    def client_ip(self) -> Optional[str]:
        """Get the client IP address."""
        if hasattr(g, "humanify_client_ip"):
            return g.humanify_client_ip

        client_ip = (
            request.remote_addr
            if is_valid_routable_ip(request.remote_addr or "127.0.0.1")
            else None
        )
        g.humanify_client_ip = client_ip
        return client_ip

    @property
    def client_id(self) -> str:
        """Get the client ID from cookies."""
        if hasattr(g, "humanify_client_id"):
            return g.humanify_client_id

        client_id = get_or_create_client_id(
            request, self.client_ip, self._secret_key, self.use_client_id
        )
        g.humanify_client_id = client_id
        return client_id

    @property
    def check_result(self) -> HumanifyResult:
        """
        Check if the IP is a bot.
        """
        if self.client_ip is None:
            return HumanifyResult(ip=self.client_ip, is_invalid_ip=True)

        user_agent = request.user_agent.string or ""

        if hasattr(g, "humanify_ip_groups"):
            humanify_ip_groups = g.humanify_ip_groups
            if isinstance(humanify_ip_groups, list):
                return HumanifyResult.from_ip_groups(
                    self.client_ip, humanify_ip_groups, user_agent
                )

        ip_groups = self.memory_client.lookup_ip(self.client_ip)
        g.humanify_ip_groups = ip_groups
        return HumanifyResult.from_ip_groups(self.client_ip, ip_groups, user_agent)

    @property
    def has_valid_clearance_token(self) -> bool:
        """Check if the current client has a valid clearance token."""
        return validate_clearance_token(
            request.cookies.get("clearance_token", ""),
            self._secret_key,
            generate_user_hash(
                self.client_ip or "127.0.0.1",
                request.user_agent.string or "",
            ),
        )

    @property
    def is_bot(self) -> bool:
        """Check if the current client is a bot."""
        return not self.has_valid_clearance_token and self.check_result.is_bot

    def deny_access(self) -> Response:
        """
        Redirect to the access denied page.
        """
        return redirect(
            url_for("humanify.access_denied", return_url=request.full_path.rstrip("?"))
        )

    def challenge(self) -> Response:
        """
        Challenge the client.
        """
        limit_response = self._check_attempt_limit()
        if limit_response:
            return limit_response

        return redirect(
            url_for("humanify.challenge", return_url=request.full_path.rstrip("?"))
        )

    def _check_attempt_limit(self) -> Optional[Response]:
        """Check if client has reached attempt limit, return deny_access response if true."""
        if self.memory_client.is_attempt_limit_reached(self.client_id, self.retrys):
            return self.deny_access()
        return None

    def _render_challenge(self, is_audio: bool = False) -> Response:
        return_url = get_return_url(request)
        if self.has_valid_clearance_token:
            return redirect(return_url)

        limit_response = self._check_attempt_limit()
        if limit_response:
            return limit_response

        error = request.args.get("error", None)
        if error not in [
            "Invalid captcha token",
            "Wrong selection. Try again.",
            "Wrong response. Try again.",
        ]:
            error = None

        if is_audio:
            return self._render_audio_challenge(return_url, error)

        if self.challenge_type in ["grid", "one_click"]:
            return self._render_image_challenge(return_url, error)

        abort(404, "Invalid challenge type")

    def _render_image_challenge(
        self, return_url: str, error: Optional[str]
    ) -> Response:
        """
        Render the image challenge.
        """

        captcha_config = IMAGE_CAPTCHA_MAPPING[self.challenge_type]
        use_preview_image = captcha_config["preview_image"]

        images_bytes, correct_indexes, subject = self.memory_client.get_captcha_images(
            dataset=self.image_dataset,
            count=captcha_config["num_images"],
            correct=captcha_config["num_correct"],
            preview=use_preview_image,
        )

        if not images_bytes:
            abort(500, "Could not load captcha images")

        processed_images = []
        for i, img_bytes in enumerate(images_bytes):
            try:
                distorted_img_bytes = manipulate_image_bytes(
                    img_bytes,
                    is_small=not (i == 0 and use_preview_image),
                    hardness=random.randint(
                        captcha_config["hardness_range"][0],
                        captcha_config["hardness_range"][1],
                    ),
                )
                processed_images.append(image_bytes_to_data_url(distorted_img_bytes))
            except Exception as e:
                current_app.logger.error(f"Error processing image: {e}")
                processed_images.append(
                    (
                        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB"
                        "CAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
                    )
                )

        preview_image = None
        if use_preview_image:
            preview_image = processed_images[0]
            processed_images = processed_images[1:]

        user_hash = generate_user_hash(
            self.client_ip or "127.0.0.1", request.user_agent.string or ""
        )
        captcha_data = generate_captcha_token(
            user_hash, correct_indexes, self._secret_key
        )

        return Response(
            render_template(
                f"{self.challenge_type}_challenge.html",
                images=processed_images,
                preview_image=preview_image,
                subject=subject,
                captcha_data=captcha_data,
                return_url=return_url or "/",
                error=error,
                audio_challenge_available=self.audio_dataset is not None,
            ),
            mimetype="text/html",
        )

    def _render_audio_challenge(
        self, return_url: str, error: Optional[str]
    ) -> Response:
        """
        Render the audio challenge.
        """
        num_chars = AUDIO_CAPTCHA_CONFIG["num_chars"]
        language = AUDIO_CAPTCHA_CONFIG["language"]

        audio_files, correct_chars = self.memory_client.get_captcha_audio(
            dataset=self.audio_dataset, chars=num_chars, lang=language
        )

        if not audio_files:
            abort(500, "Could not load captcha audio")

        combined_audio = combine_audio_files(audio_files)
        if not combined_audio:
            abort(500, "Could not process audio files")

        audio_data_url = audio_bytes_to_data_url(combined_audio, "mp3")

        user_hash = generate_user_hash(
            self.client_ip or "127.0.0.1", request.user_agent.string or ""
        )
        captcha_data = generate_captcha_token(
            user_hash, correct_chars, self._secret_key
        )

        return Response(
            render_template(
                "audio_challenge.html",
                audio_file=audio_data_url,
                captcha_data=captcha_data,
                return_url=return_url or "/",
                error=error,
                image_challenge_available=self.image_dataset is not None,
            ),
            mimetype="text/html",
        )

    def _verify_captcha(self) -> Response:
        """Verify the captcha solution."""
        return_url = get_return_url(request)
        if self.has_valid_clearance_token:
            return redirect(return_url)

        limit_response = self._check_attempt_limit()
        if limit_response:
            return limit_response

        captcha_data = request.form.get("captcha_data", "")
        if not captcha_data:
            return redirect(
                url_for(
                    "humanify.challenge",
                    error="Invalid captcha token",
                    return_url=return_url,
                )
            )

        user_hash = generate_user_hash(
            self.client_ip or "127.0.0.1", request.user_agent.string or ""
        )
        decrypted_data = validate_captcha_token(
            captcha_data, self._secret_key, user_hash
        )

        if decrypted_data is None:
            return redirect(
                url_for(
                    "humanify.challenge",
                    error="Invalid captcha token",
                    return_url=return_url,
                )
            )

        verify_functions = {
            "grid": self._verify_image_captcha,
            "one_click": self._verify_image_captcha,
        }

        verify_function = verify_functions[self.challenge_type]
        if not verify_function(decrypted_data):
            self.memory_client.record_failed_attempt(self.client_id)
            return redirect(
                url_for(
                    "humanify.challenge",
                    error="Wrong selection. Try again.",
                    return_url=return_url,
                )
            )

        clearance_token = generate_clearance_token(user_hash, self._secret_key)

        response = redirect(return_url or "/")
        response.set_cookie(
            "clearance_token",
            clearance_token,
            max_age=14400,
            httponly=True,
            samesite="Strict",
        )

        return response

    def _verify_audio_captcha(self) -> Response:
        """Verify the audio captcha solution."""
        return_url = get_return_url(request)
        if self.has_valid_clearance_token:
            return redirect(return_url)

        limit_response = self._check_attempt_limit()
        if limit_response:
            return limit_response

        captcha_data = request.form.get("captcha_data", "")
        if not captcha_data:
            return redirect(
                url_for(
                    "humanify.audio_challenge",
                    error="Invalid captcha token",
                    return_url=return_url,
                )
            )

        user_hash = generate_user_hash(
            self.client_ip or "127.0.0.1", request.user_agent.string or ""
        )
        correct_chars = validate_captcha_token(
            captcha_data, self._secret_key, user_hash, valid_lengths=[197]
        )

        if correct_chars is None:
            return redirect(
                url_for(
                    "humanify.audio_challenge",
                    error="Invalid captcha token",
                    return_url=return_url,
                )
            )

        audio_response = request.form.get("audio_response", "").lower().strip()
        if not audio_response or audio_response != correct_chars:
            self.memory_client.record_failed_attempt(self.client_id)
            return redirect(
                url_for(
                    "humanify.audio_challenge",
                    error="Wrong response. Try again.",
                    return_url=return_url,
                )
            )

        clearance_token = generate_clearance_token(user_hash, self._secret_key)

        response = redirect(return_url or "/")
        response.set_cookie(
            "clearance_token",
            clearance_token,
            max_age=14400,
            httponly=True,
            samesite="Strict",
        )

        return response

    def _verify_image_captcha(self, decrypted_data: str) -> bool:
        """Verify the image captcha."""
        captcha_config = IMAGE_CAPTCHA_MAPPING[self.challenge_type]

        selected_indexes = []
        for i in range(1, captcha_config["num_images"] + 1):
            if request.form.get(str(i), None) == "1":
                selected_indexes.append(str(i - 1))

        selected_str = "".join(sorted(selected_indexes))
        correct_str = "".join(sorted(list(decrypted_data)))

        return selected_str == correct_str
