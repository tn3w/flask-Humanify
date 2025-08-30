"""
Flask-Humanify
-----------
A Flask extension that protects against bots and DDoS attacks.
"""

__version__ = "0.2.7.1"

from . import utils
from .humanify import Humanify
from .features.rate_limiter import RateLimiter
from .features.error_handler import ErrorHandler


__all__ = ["Humanify", "RateLimiter", "ErrorHandler", "utils"]
