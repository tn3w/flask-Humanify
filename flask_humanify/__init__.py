"""
Flask-Humanify
-----------
A Flask extension that protects against bots and DDoS attacks.
"""

__version__ = "0.2.9"

from . import utils
from .humanify import (
    Humanify,
    require_human,
    always_challenge,
    block_bots,
    exempt_from_protection,
)
from .features.rate_limiter import RateLimiter
from .features.error_handler import ErrorHandler
from .features.captcha_embed import CaptchaEmbed

__all__ = [
    "Humanify",
    "require_human",
    "always_challenge",
    "block_bots",
    "exempt_from_protection",
    "RateLimiter",
    "ErrorHandler",
    "CaptchaEmbed",
    "utils",
]
