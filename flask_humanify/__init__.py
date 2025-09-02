"""
Flask-Humanify
-----------
A Flask extension that protects against bots and DDoS attacks.
"""

__version__ = "0.2.8.3"

from . import utils
from .humanify import Humanify
from .features.rate_limiter import RateLimiter
from .features.error_handler import ErrorHandler
from .features.captcha_embed import CaptchaEmbed


__all__ = ["Humanify", "RateLimiter", "ErrorHandler", "CaptchaEmbed", "utils"]
