from dataclasses import dataclass
import logging
import random
from typing import List, Optional

from werkzeug.wrappers import Response
from flask import (
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
    get_client_ip,
    get_return_url,
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
        "hardness_range": (1, 4),
    },
    "one_click": {
        "num_correct": 1,
        "num_images": 6,
        "preview_image": True,
        "hardness_range": (1, 2),
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
        )

    @classmethod
    def from_ip_groups(cls, ip: str, ip_groups: List[str]) -> "HumanifyResult":
        """
        Create a HumanifyResult from a list of IP groups.
        """
        vpn_provider = next((name for name in VPN_PROVIDERS if name in ip_groups), None)

        result = HumanifyResult(
            ip=ip,
            is_vpn=vpn_provider is not None,
            vpn_provider=vpn_provider,
            is_proxy="FireholProxies" in ip_groups or "AwesomeProxies" in ip_groups,
            is_datacenter="Datacenter" in ip_groups,
            is_forum_spammer="StopForumSpam" in ip_groups,
            is_firehol="FireholLevel1" in ip_groups,
            is_tor_exit_node="TorExitNodes" in ip_groups,
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
        self, app=None, challenge_type: str = "one_click", captcha_dataset: str = "ai_dogs"
    ):
        self.app = app
        self.challenge_type = challenge_type
        self.captcha_dataset = captcha_dataset
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """
        Initialize the Humanify extension.
        """
        self.app = app

        ensure_server_running(
            image_dataset=self.captcha_dataset,
        )
        self.memory_client = MemoryClient()
        self.memory_client.connect()
        self._secret_key = self.memory_client.get_secret_key()

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
            return self._render_challenge()

        @self.blueprint.route("/humanify/audio_challenge", methods=["GET"])
        def audio_challenge():
            """
            Audio challenge route.
            """
            return self._render_challenge(is_audio=True)

        @self.blueprint.route("/humanify/verify", methods=["POST"])
        def verify():
            """
            Verify route.
            """
            return self._verify_captcha()

        @self.blueprint.route("/humanify/verify_audio", methods=["POST"])
        def verify_audio():
            """
            Verify audio route.
            """
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

    def register_middleware(self, action: str = "challenge"):
        """
        Register the middleware.
        """

        self.app = self.app or current_app

        @self.app.before_request
        def before_request():
            """
            Before request hook.
            """
            if request.endpoint and request.endpoint.startswith("humanify."):
                return

            if self.is_bot:
                if action == "challenge":
                    return self.challenge()
                if action == "deny_access":
                    return self.deny_access()

    @property
    def client_ip(self) -> Optional[str]:
        """Get the client IP address."""
        if hasattr(g, "humanify_client_ip"):
            return g.humanify_client_ip

        client_ip = get_client_ip(request)
        g.humanify_client_ip = client_ip
        return client_ip

    @property
    def check_result(self) -> HumanifyResult:
        """
        Check if the IP is a bot.
        """
        if self.client_ip is None:
            return HumanifyResult(ip=self.client_ip, is_invalid_ip=True)

        if hasattr(g, "humanify_ip_groups"):
            humanify_ip_groups = g.humanify_ip_groups
            if isinstance(humanify_ip_groups, list):
                return HumanifyResult.from_ip_groups(self.client_ip, humanify_ip_groups)

        ip_groups = self.memory_client.lookup_ip(self.client_ip)
        g.humanify_ip_groups = ip_groups
        return HumanifyResult.from_ip_groups(self.client_ip, ip_groups)

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
        return redirect(url_for("humanify.access_denied", return_url=request.full_path))

    def challenge(self) -> Response:
        """
        Challenge the client.
        """
        return redirect(url_for("humanify.challenge", return_url=request.full_path))

    def _render_challenge(self, is_audio: bool = False) -> Response:
        return_url = get_return_url(request)
        if self.has_valid_clearance_token:
            return redirect(return_url)

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
            num_correct=captcha_config["num_correct"],
            num_images=captcha_config["num_images"],
            preview_image=use_preview_image,
            dataset_name=self.captcha_dataset,
        )

        if not images_bytes:
            abort(500, "Could not load captcha images")

        processed_images = []
        for i, img_bytes in enumerate(images_bytes):
            try:
                hardness = random.randint(
                    captcha_config["hardness_range"][0],
                    captcha_config["hardness_range"][1],
                )
                distorted = manipulate_image_bytes(
                    img_bytes,
                    is_small=not (i == 0 and use_preview_image),
                    hardness=hardness,
                )
                processed_images.append(image_bytes_to_data_url(distorted))
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
                audio_challenge_available=True,
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
            num_chars=num_chars, language=language
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
                image_challenge_available=True,
            ),
            mimetype="text/html",
        )

    def _verify_captcha(self) -> Response:
        """Verify the captcha solution."""
        return_url = get_return_url(request)
        if self.has_valid_clearance_token:
            return redirect(return_url)

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
