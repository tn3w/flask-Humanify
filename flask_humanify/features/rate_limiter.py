import time
import os
from collections import defaultdict, deque
from typing import Optional, Dict, Union, Tuple
from functools import wraps
import re

from werkzeug.wrappers import Response
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, Blueprint, request, redirect, url_for, render_template, g
from flask_humanify.memory_server import MemoryClient, ensure_server_running
from flask_humanify.utils import (
    is_valid_routable_ip,
    get_or_create_client_id,
    get_return_url,
)


def parse_limit_string(limit_string: str) -> Tuple[int, int]:
    """
    Parse a limit string like "10/minute", "5 per hour", "100/day" into (count, seconds).

    Args:
        limit_string: String describing the rate limit

    Returns:
        Tuple of (max_requests, time_window_seconds)
    """
    limit_string = limit_string.strip().lower()

    patterns = [
        r"(\d+)\s*/\s*(\w+)",
        r"(\d+)\s+per\s+(\w+)",
        r"(\d+)\s*/\s*(\d+)\s*(\w*)",
    ]

    time_units = {
        "second": 1,
        "seconds": 1,
        "sec": 1,
        "minute": 60,
        "minutes": 60,
        "min": 60,
        "hour": 3600,
        "hours": 3600,
        "hr": 3600,
        "day": 86400,
        "days": 86400,
    }

    for pattern in patterns:
        match = re.match(pattern, limit_string)
        if match:
            if len(match.groups()) == 2:
                count, unit = match.groups()
                count = int(count)
                unit_seconds = time_units.get(unit, 1)
                return count, unit_seconds
            elif len(match.groups()) == 3:
                count, seconds, unit = match.groups()
                count = int(count)
                if unit and unit in time_units:
                    return count, int(seconds) * time_units[unit]
                else:
                    return count, int(seconds)

    raise ValueError(f"Invalid limit string format: {limit_string}")


class RateLimiter:
    """
    Rate limiter with per-route control capabilities.
    """

    def __init__(
        self,
        app=None,
        max_requests: int = 10,
        time_window: int = 10,
        behind_proxy: bool = True,
        use_client_id: Optional[bool] = None,
        default_limit: Optional[str] = None,
    ) -> None:
        """
        Initialize the rate limiter.

        Args:
            app: Flask application instance
            max_requests: Default maximum requests (deprecated, use default_limit)
            time_window: Default time window in seconds (deprecated, use default_limit)
            behind_proxy: Whether the app is behind a proxy
            use_client_id: Whether to use client ID for tracking
            default_limit: Default rate limit string (e.g., "10/minute")
        """
        self.app = app
        self.behind_proxy = behind_proxy
        self.use_client_id = use_client_id
        self._client_id_secret_key = None

        if default_limit:
            self.max_requests, self.time_window = parse_limit_string(default_limit)
        else:
            self.max_requests = max_requests
            self.time_window = time_window

        self.ip_request_times = defaultdict(lambda: defaultdict(deque))
        self.route_limits: Dict[str, Tuple[int, int]] = {}
        self.route_patterns: Dict[str, Tuple[int, int]] = {}

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """
        Initialize the rate limiter.
        """
        self.app = app
        if not isinstance(app.wsgi_app, ProxyFix) and self.behind_proxy:
            app.wsgi_app = ProxyFix(
                app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1
            )

        humanify_use_client_id = app.config.get("HUMANIFY_USE_CLIENT_ID", False)
        if self.use_client_id is None:
            self.use_client_id = humanify_use_client_id

        if self.use_client_id:
            humanify_secret_key = app.config.get("HUMANIFY_SECRET_KEY", None)
            if isinstance(humanify_secret_key, bytes):
                self._client_id_secret_key = humanify_secret_key
            elif humanify_secret_key is None:
                ensure_server_running()
                self.memory_client = MemoryClient()
                self.memory_client.connect()
                self._client_id_secret_key = self.memory_client.get_secret_key()

            if not humanify_use_client_id:
                app.config["HUMANIFY_SECRET_KEY"] = self._client_id_secret_key
                app.config["HUMANIFY_USE_CLIENT_ID"] = True

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

        self.app.before_request(self.before_request)

        if "humanify" not in self.app.blueprints:
            template_dir = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), "templates"
            )
            rate_limiter_bp = Blueprint(
                "humanify", __name__, template_folder=template_dir
            )

            @rate_limiter_bp.route("/rate_limited", methods=["GET"])
            def rate_limited():
                """
                Rate limited route.
                """
                return (
                    render_template("rate_limited.html").replace(
                        "RETURN_URL", get_return_url(request)
                    ),
                    429,
                    {"Cache-Control": "public, max-age=15552000"},
                )

            app.register_blueprint(rate_limiter_bp, url_prefix="/humanify")
        else:

            @app.route(
                "/humanify/rate_limited",
                methods=["GET"],
                endpoint="humanify.rate_limited",
            )
            def rate_limited():
                """
                Rate limited route.
                """
                return (
                    render_template("rate_limited.html").replace(
                        "RETURN_URL", get_return_url(request)
                    ),
                    429,
                    {"Cache-Control": "public, max-age=15552000"},
                )

    def limit(self, limit_string: str):
        """
        Decorator to apply rate limiting to specific routes.

        Args:
            limit_string: Rate limit string (e.g., "5/minute", "10 per hour")

        Usage:
            @app.route('/api/data')
            @limiter.limit("10/minute")
            def get_data():
                return "data"
        """

        def decorator(f):
            max_requests, time_window = parse_limit_string(limit_string)

            @wraps(f)
            def decorated_function(*args, **kwargs):
                route_key = f"{request.endpoint}:{request.method}"
                if self.is_rate_limited_for_route(route_key, max_requests, time_window):
                    return redirect(
                        url_for(
                            "humanify.rate_limited",
                            return_url=request.full_path.rstrip("?"),
                        )
                    )
                return f(*args, **kwargs)

            return decorated_function

        return decorator

    def set_route_limit(self, route_pattern: str, limit_string: str) -> None:
        """
        Set rate limit for a specific route pattern.

        Args:
            route_pattern: Route pattern (e.g., "/api/*", "/users/<int:id>")
            limit_string: Rate limit string (e.g., "10/minute")
        """
        if (
            route_pattern.startswith("/humanify/rate_limited")
            or route_pattern == "/humanify/*"
        ):
            return

        max_requests, time_window = parse_limit_string(limit_string)
        self.route_patterns[route_pattern] = (max_requests, time_window)

    def exempt(self, f):
        """
        Decorator to exempt a route from rate limiting.

        Usage:
            @app.route('/health')
            @limiter.exempt
            def health_check():
                return "OK"
        """

        @wraps(f)
        def decorated_function(*args, **kwargs):
            g.humanify_rate_limit_exempt = True
            return f(*args, **kwargs)

        return decorated_function

    @property
    def _client_ip(self) -> Optional[str]:
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

    def get_route_limit(self, endpoint: str, method: str, path: str) -> Tuple[int, int]:
        """
        Get the rate limit for a specific route.

        Args:
            endpoint: Flask endpoint name
            method: HTTP method
            path: Request path

        Returns:
            Tuple of (max_requests, time_window)
        """
        route_key = f"{endpoint}:{method}"

        if route_key in self.route_limits:
            return self.route_limits[route_key]

        for pattern, (max_req, time_win) in self.route_patterns.items():
            if self._match_route_pattern(path, pattern):
                return max_req, time_win

        return self.max_requests, self.time_window

    def _match_route_pattern(self, path: str, pattern: str) -> bool:
        """
        Check if a path matches a route pattern.

        Args:
            path: Request path
            pattern: Pattern to match against

        Returns:
            True if the path matches the pattern
        """
        pattern = pattern.replace("*", ".*")
        pattern = re.sub(r"<[^>]+>", "[^/]+", pattern)
        pattern = f"^{pattern}$"

        return bool(re.match(pattern, path))

    def before_request(self) -> Optional[Response]:
        """
        Before request hook.
        """
        if request.endpoint in ["humanify.rate_limited", "humanify.access_denied"]:
            return

        if hasattr(g, "humanify_rate_limit_exempt"):
            return

        if self.is_rate_limited():
            return redirect(
                url_for(
                    "humanify.rate_limited", return_url=request.full_path.rstrip("?")
                )
            )

    def is_rate_limited(self, ip: Optional[str] = None) -> bool:
        """
        Check if the IP is rate limited for the current route.
        """
        if not request.endpoint:
            return False

        max_requests, time_window = self.get_route_limit(
            request.endpoint, request.method, request.path
        )

        route_key = f"{request.endpoint}:{request.method}"
        return self.is_rate_limited_for_route(route_key, max_requests, time_window, ip)

    def is_rate_limited_for_route(
        self,
        route_key: str,
        max_requests: int,
        time_window: int,
        ip: Optional[str] = None,
    ) -> bool:
        """
        Check if the IP is rate limited for a specific route.

        Args:
            route_key: Unique key for the route
            max_requests: Maximum requests allowed
            time_window: Time window in seconds
            ip: IP address to check (optional)

        Returns:
            True if rate limited, False otherwise
        """
        client_id_secret_key = None
        if isinstance(self._client_id_secret_key, bytes):
            client_id_secret_key = self._client_id_secret_key

        client_id = ip or get_or_create_client_id(
            request,
            self._client_ip,
            client_id_secret_key,
            self.use_client_id or False,
        )

        current_time = time.time()
        request_times = self.ip_request_times[client_id][route_key]

        while request_times and request_times[0] <= current_time - time_window:
            request_times.popleft()

        if len(request_times) < max_requests:
            request_times.append(current_time)
            return False

        return True

    def reset_client(self, client_id: str, route_key: Optional[str] = None) -> None:
        """
        Reset rate limiting for a specific client.

        Args:
            client_id: Client identifier
            route_key: Specific route to reset (optional, resets all if None)
        """
        if client_id in self.ip_request_times:
            if route_key:
                if route_key in self.ip_request_times[client_id]:
                    self.ip_request_times[client_id][route_key].clear()
            else:
                del self.ip_request_times[client_id]

    def get_client_stats(
        self, client_id: str
    ) -> Dict[str, Dict[str, Union[int, float]]]:
        """
        Get statistics for a specific client.

        Args:
            client_id: Client identifier

        Returns:
            Dictionary with route statistics
        """
        stats = {}
        current_time = time.time()

        if client_id in self.ip_request_times:
            for route_key, request_times in self.ip_request_times[client_id].items():
                while (
                    request_times
                    and request_times[0] <= current_time - self.time_window
                ):
                    request_times.popleft()

                stats[route_key] = {
                    "current_requests": len(request_times),
                    "next_reset": (
                        request_times[0] + self.time_window if request_times else 0
                    ),
                }

        return stats
