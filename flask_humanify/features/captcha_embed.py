import html
import json
import hmac
import hashlib
import urllib.parse
import urllib.request
from base64 import b64decode
from secrets import token_hex, randbelow
from typing import Optional
from abc import ABC, abstractmethod
from flask import Flask, request
from markupsafe import Markup


def secure_randint(min_val: int, max_val: int) -> int:
    """
    Generate a cryptographically secure random integer in the given range.

    Args:
        min_val (int): Minimum value (inclusive)
        max_val (int): Maximum value (inclusive)

    Returns:
        int: A secure random integer between min_val and max_val
    """
    if min_val > max_val:
        raise ValueError("min_val must be less than or equal to max_val")

    range_size = max_val - min_val + 1
    return min_val + randbelow(range_size)


class ThirdPartyCredentials(ABC):
    """Abstract base class for third-party CAPTCHA credentials."""

    @abstractmethod
    def get_site_key(self) -> Optional[str]:
        """Get the site key for the CAPTCHA service."""

    @abstractmethod
    def get_secret_key(self) -> Optional[str]:
        """Get the secret key for the CAPTCHA service."""


class ReCaptchaCreds(ThirdPartyCredentials):
    """Credentials for Google reCAPTCHA."""

    def __init__(self, site_key: str, secret_key: Optional[str] = None):
        self.site_key = site_key
        self.secret_key = secret_key

    def get_site_key(self) -> str:
        return self.site_key

    def get_secret_key(self) -> Optional[str]:
        return self.secret_key


class HCaptchaCreds(ThirdPartyCredentials):
    """Credentials for hCaptcha."""

    def __init__(self, site_key: str, secret_key: Optional[str] = None):
        self.site_key = site_key
        self.secret_key = secret_key

    def get_site_key(self) -> str:
        return self.site_key

    def get_secret_key(self) -> Optional[str]:
        return self.secret_key


class TurnstileCreds(ThirdPartyCredentials):
    """Credentials for Cloudflare Turnstile."""

    def __init__(self, site_key: str, secret_key: Optional[str] = None):
        self.site_key = site_key
        self.secret_key = secret_key

    def get_site_key(self) -> str:
        return self.site_key

    def get_secret_key(self) -> Optional[str]:
        return self.secret_key


class FriendlyCaptchaCreds(ThirdPartyCredentials):
    """Credentials for Friendly Captcha."""

    def __init__(self, site_key: str, secret_key: Optional[str] = None):
        self.site_key = site_key
        self.secret_key = secret_key

    def get_site_key(self) -> str:
        return self.site_key

    def get_secret_key(self) -> Optional[str]:
        return self.secret_key


class AltchaCreds(ThirdPartyCredentials):
    """Credentials for Altcha."""

    def __init__(self, secret_key: str):
        self.secret_key = secret_key

    def get_site_key(self) -> Optional[str]:
        return None

    def get_secret_key(self) -> str:
        return self.secret_key


class Altcha:
    """A class for generating and verifying challenges for altcha."""

    def __init__(self, secret: bytes) -> None:
        """
        Initialize Altcha with the secret key.
        :param secret: The secret key for generating and verifying challenges.
        """
        self.secret = secret

    def create_challenge(self, hardness: int = 1) -> dict:
        """
        Creates a challenge response for the altcha protocol.
        :param hardness: The level of difficulty of the challenge.
        :return: A dictionary containing the challenge details.
        """
        salt = token_hex(12)
        secret_number = secure_randint(10000 * hardness, 25000 * hardness)
        challenge = hashlib.sha256(
            (salt + str(secret_number)).encode("utf-8")
        ).hexdigest()
        signature = hmac.new(
            self.secret, challenge.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        challenge = {
            "algorithm": "SHA-256",
            "challenge": challenge,
            "salt": salt,
            "signature": signature,
        }
        return challenge

    def verify_challenge(self, challenge: str) -> bool:
        """
        Verifies a challenge response for the altcha protocol.
        :param challenge: The challenge response to verify.
        :return: True if the challenge is valid, False otherwise.
        """
        try:
            data = json.loads(b64decode(challenge))
            challenge_computed = hashlib.sha256(
                (data["salt"] + str(data["number"])).encode("utf-8")
            ).hexdigest()
            signature_computed = hmac.new(
                self.secret, data["challenge"].encode("utf-8"), hashlib.sha256
            ).hexdigest()

            return (
                data["algorithm"] == "SHA-256"
                and challenge_computed == data["challenge"]
                and signature_computed == data["signature"]
            )
        except (json.JSONDecodeError, KeyError, ValueError):
            return False


CLASS_NAMES = {
    "recaptcha": "g-recaptcha",
    "hcaptcha": "h-captcha",
    "turnstile": "cf-turnstile",
    "friendly": "frc-captcha",
}

SCRIPT_URLS = {
    "recaptcha": "https://www.google.com/recaptcha/api.js",
    "hcaptcha": "https://hcaptcha.com/1/api.js",
    "turnstile": "https://challenges.cloudflare.com/turnstile/v0/api.js",
    "friendly": "https://cdn.jsdelivr.net/npm/friendly-challenge/widget.module.min.js",
}

CAPTCHA_API_URLS = {
    "recaptcha": "https://www.google.com/recaptcha/api/siteverify",
    "hcaptcha": "https://hcaptcha.com/siteverify",
    "turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    "friendly": "https://api.friendlycaptcha.com/api/v1/siteverify",
}

STANDARD_EMBED = """<div id="{type}Box" class="{class_name}" data-sitekey="{site_key}" data-lang="{language}" data-theme="{theme}"></div><script>(function(){{const t=document.createElement("script");t.src="{script_url}",t.async=!0,t.defer=!0,document.head.appendChild(t)}})();</script>"""
ALTCHA_EMBED = """<altcha-widget style="font-family:Segoe UI,Arial,sans-serif" hidelogo challengejson="{challenge}" strings="{strings}"></altcha-widget><script>{altcha_styles}(function(){{const t=document.createElement("script");t.src="https://cdn.jsdelivr.net/npm/altcha/dist/altcha.min.js",t.async=!0,t.defer=!0,t.type="module",document.head.appendChild(t)}})();</script>"""
ALTCHA_STYLES = """function c(t){{const e="altcha-theme-styles";let a=document.getElementById(e);a&&a.remove();const s=document.createElement("style");s.id=e;const l=":root{{--altcha-color-base:#f2f2f2;--altcha-color-text:#181818;--altcha-color-border:rgba(0,0,0,0.5);--altcha-color-border-focus:rgba(0,0,0,0.5);--altcha-color-footer-bg:#f2f2f2}}",o=":root{{--altcha-color-base:#121212;--altcha-color-text:#f2f2f2;--altcha-color-border:rgba(255,255,255,0.1);--altcha-color-border-focus:rgba(255,255,255,0.1);--altcha-color-footer-bg:#121212}}",r=":root{{--altcha-color-base:#f2f2f2;--altcha-color-text:#181818;--altcha-color-border:rgba(0,0,0,0.5);--altcha-color-border-focus:rgba(0,0,0,0.5);--altcha-color-footer-bg:#f2f2f2}}@media (prefers-color-scheme:dark){{:root{{--altcha-color-base:#121212;--altcha-color-text:#f2f2f2;--altcha-color-border:rgba(255,255,255,0.1);--altcha-color-border-focus:rgba(255,255,255,0.1);--altcha-color-footer-bg:#121212}}}}";s.textContent="dark"===t?o:"light"===t?l:r,document.head.appendChild(s)}}"{theme}"==="auto"?c("auto"):c("{theme}");"""


class CaptchaEmbed:
    """Generates the embed that is supposed to be added to the HTML document."""

    def __init__(
        self,
        app: Flask,
        language: str = "auto",
        theme: str = "auto",
        altcha_secret: Optional[str] = None,
        **kwargs,
    ):
        """
        Initializes the CaptchaEmbed object with Flask app and configuration.

        Args:
            app (Flask): The Flask application instance
            language (str): The language code for the CAPTCHA (default is "auto")
            theme (str): The theme for the CAPTCHA widgets ("light", "dark", or "auto")
            debug (bool): Enable debug mode for better error handling
            altcha_secret (Optional[str]): Secret key for Altcha CAPTCHA
            **kwargs: Additional configuration options
        """
        self.app = app
        self.language = language
        self.theme = theme
        self.kwargs = kwargs

        self.altcha = None
        if altcha_secret:
            self.altcha = Altcha(altcha_secret.encode("utf-8"))

        self._register_context_processor()

    def _register_context_processor(self):
        """Register the context processor with the Flask app."""

        @self.app.context_processor
        def add_third_parties():
            """Context processor that adds CAPTCHA embeds to template context."""
            embeds = {}

            if self.altcha:
                embeds["altcha"] = Markup(self.get_embed("altcha"))
                for hardness in range(1, 6):
                    embeds[f"altcha{hardness}"] = Markup(
                        self.get_embed("altcha", hardness=hardness)
                    )

            for third_party in ["recaptcha", "hcaptcha", "turnstile", "friendly"]:
                site_key = self.kwargs.get(f"{third_party}_site_key")

                if site_key:
                    embeds[third_party] = Markup(
                        self.get_embed(third_party, site_key=site_key)
                    )

            return embeds

    def get_embed(
        self, captcha_type: str, hardness: int = 2, site_key: Optional[str] = None
    ) -> str:
        """
        Generates the HTML embed for a CAPTCHA element.

        Args:
            captcha_type (str): The type of CAPTCHA to embed
            hardness (int): The difficulty level for Altcha CAPTCHAs (default is 2)
            site_key (Optional[str]): Site key for the CAPTCHA service

        Returns:
            str: The HTML embed code for the specified CAPTCHA type

        Raises:
            ValueError: If the captcha type is not supported or configuration is missing
        """
        if captcha_type == "altcha":
            return self._get_altcha_embed(hardness)

        if not site_key:
            site_key = self.kwargs.get(f"{captcha_type}_site_key")
        if not site_key:
            raise ValueError(f"No site key provided for CAPTCHA type: {captcha_type}")
        return self._get_standard_embed(captcha_type, site_key)

    def _get_standard_embed(self, captcha_type: str, site_key: str) -> str:
        """Generate embed for standard CAPTCHA types (reCAPTCHA, hCaptcha, etc.)."""
        if captcha_type not in CLASS_NAMES:
            raise ValueError(f"Unsupported CAPTCHA type: {captcha_type}")

        lang_param = f"?hl={self.language}" if self.language != "auto" else ""
        script_url = SCRIPT_URLS[captcha_type] + lang_param

        return STANDARD_EMBED.format(
            type=captcha_type,
            class_name=CLASS_NAMES[captcha_type],
            site_key=site_key,
            language=self.language,
            theme=self.theme,
            script_url=script_url,
        )

    def _get_altcha_embed(self, hardness: int) -> str:
        """Generate embed for Altcha CAPTCHA."""
        if not self.altcha:
            raise ValueError("Altcha not initialized - please provide altcha_secret")

        challenge = html.escape(json.dumps(self.altcha.create_challenge(hardness)))
        strings = html.escape(json.dumps({}))

        return ALTCHA_EMBED.format(
            challenge=challenge,
            strings=strings,
            altcha_styles=ALTCHA_STYLES.format(theme=self.theme),
        )

    def _get_credentials_for_validation(self, captcha_type: str) -> Optional[str]:
        """Get secret key for validation from kwargs."""
        if captcha_type == "altcha":
            return None

        return self.kwargs.get(f"{captcha_type}_secret")

    def _is_captcha_valid(self, captcha_type: str) -> bool:
        """
        Check if the captcha is valid.

        Args:
            captcha_type (str): The type of captcha

        Returns:
            bool: True if the captcha is valid, False otherwise
        """
        if not request:
            raise ImportError("Flask request object not available")

        third_party_name = {
            "recaptcha": "g-recaptcha",
            "turnstile": "cf-turnstile",
            "hcaptcha": "h-captcha",
            "friendly": "frc-captcha",
        }.get(captcha_type)

        if not third_party_name:
            return False

        response_or_solution = "solution" if captcha_type == "friendly" else "response"
        key = third_party_name + "-" + response_or_solution

        if request.method.lower() == "post":
            response_data = request.form.get(key)
        else:
            response_data = request.args.get(key)

        if not isinstance(response_data, str) or not response_data:
            return False

        secret = self._get_credentials_for_validation(captcha_type)
        if not secret:
            return False

        post_data = {"secret": secret, response_or_solution: response_data}

        api_url = CAPTCHA_API_URLS.get(captcha_type)
        if not api_url:
            return False

        post_data_encoded = urllib.parse.urlencode(post_data).encode("utf-8")
        req = urllib.request.Request(api_url, data=post_data_encoded)

        timeout = 3
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                response_data = response.read()
                response_json = json.loads(response_data)

            return response_json.get("success", False)
        except Exception:
            return False

    def is_recaptcha_valid(self) -> bool:
        """Check if the recaptcha is valid."""
        return self._is_captcha_valid("recaptcha")

    def is_hcaptcha_valid(self) -> bool:
        """Check if the hcaptcha is valid."""
        return self._is_captcha_valid("hcaptcha")

    def is_turnstile_valid(self) -> bool:
        """Check if the turnstile is valid."""
        return self._is_captcha_valid("turnstile")

    def is_friendly_valid(self) -> bool:
        """Check if the friendly captcha is valid."""
        return self._is_captcha_valid("friendly")

    def is_altcha_valid(self) -> bool:
        """Check if the altcha is valid."""
        if not request:
            raise ImportError("Flask request object not available")

        if not self.altcha:
            return False

        if request.method.lower() == "post":
            response_data = request.form.get("altcha")
        else:
            response_data = request.args.get("altcha")

        if not isinstance(response_data, str):
            return False

        return self.altcha.verify_challenge(response_data)
