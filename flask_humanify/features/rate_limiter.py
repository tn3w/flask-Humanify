import os
import re
import time
from collections import deque
from functools import wraps

from flask import Blueprint, Flask, g, redirect, render_template, request, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.wrappers import Response

import hashlib
import hmac
import re

from flask_humanify.memory_server import MemoryClient, ensure_server_running
from flask_humanify.utils import (
    get_or_create_client_id,
    get_next_url,
    is_valid_routable_ip,
)


def parse_limit_string(limit_string):
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


def validate_regex_complexity(pattern: str, max_length: int = 200) -> bool:
    if len(pattern) > max_length:
        return False

    repetition_count = pattern.count("*") + pattern.count("+") + pattern.count("{")
    if repetition_count > 10:
        return False

    nested_groups = 0
    max_nesting = 3
    for char in pattern:
        if char == "(":
            nested_groups += 1
            if nested_groups > max_nesting:
                return False
        elif char == ")":
            nested_groups = max(0, nested_groups - 1)

    return True


class RateLimiter:
    MAX_CLIENTS = 5000
    MAX_ROUTES_PER_CLIENT = 50
    MEMORY_PRESSURE_THRESHOLD = 0.8

    def __init__(
        self,
        app=None,
        max_requests=10,
        time_window=10,
        behind_proxy=False,
        use_client_id=None,
        default_limit=None,
    ):
        self.app = app
        self.behind_proxy = behind_proxy
        self.use_client_id = use_client_id
        self._client_id_secret_key = None

        if default_limit:
            self.max_requests, self.time_window = parse_limit_string(default_limit)
        else:
            self.max_requests = max_requests
            self.time_window = time_window

        self.ip_request_times = {}
        self.client_access_order = deque()
        self.route_limits = {}
        self.route_patterns = {}
        self._memory_check_counter = 0

        if app is not None:
            self.init_app(app)

    def _check_memory_pressure(self) -> bool:
        self._memory_check_counter += 1
        if self._memory_check_counter % 100 != 0:
            return False

        current_clients = len(self.ip_request_times)
        total_routes = sum(len(routes) for routes in self.ip_request_times.values())

        client_pressure = current_clients / self.MAX_CLIENTS
        route_pressure = total_routes / (self.MAX_CLIENTS * self.MAX_ROUTES_PER_CLIENT)

        return max(client_pressure, route_pressure) > self.MEMORY_PRESSURE_THRESHOLD

    def _aggressive_cleanup(self):
        if not self._check_memory_pressure():
            return

        clients_to_remove = max(1, len(self.ip_request_times) // 10)

        for _ in range(clients_to_remove):
            if self.client_access_order:
                oldest_client = self.client_access_order.popleft()
                if oldest_client in self.ip_request_times:
                    del self.ip_request_times[oldest_client]

    def init_app(self, app):
        self.app = app
        if not isinstance(app.wsgi_app, ProxyFix) and self.behind_proxy:
            app.wsgi_app = ProxyFix(
                app.wsgi_app,
                x_for=1,
                x_proto=1,
                x_host=1,
                x_port=1,
            )

        humanify_use_client_id = app.config.get(
            "HUMANIFY_USE_CLIENT_ID",
            False,
        )
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

        self.app.before_request(self.before_request)

        if "humanify" not in self.app.blueprints:
            template_dir = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                "templates",
            )
            rate_limiter_bp = Blueprint(
                "humanify",
                __name__,
                template_folder=template_dir,
            )

            @rate_limiter_bp.route("/rate_limited", methods=["GET"])
            def rate_limited():
                return (
                    render_template("rate_limited.html", next=get_next_url(request)),
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
                return (
                    render_template("rate_limited.html", next=get_next_url(request)),
                    429,
                    {"Cache-Control": "public, max-age=15552000"},
                )

    def limit(self, limit_string):
        def decorator(f):
            max_requests, time_window = parse_limit_string(limit_string)

            @wraps(f)
            def decorated_function(*args, **kwargs):
                route_key = f"{request.endpoint}:{request.method}"
                if self.is_rate_limited_for_route(
                    route_key,
                    max_requests,
                    time_window,
                ):
                    return redirect(
                        url_for(
                            "humanify.rate_limited",
                            next=request.full_path.rstrip("?"),
                        )
                    )
                return f(*args, **kwargs)

            return decorated_function

        return decorator

    def set_route_limit(self, route_pattern, limit_string):
        if (
            route_pattern.startswith("/humanify/rate_limited")
            or route_pattern == "/humanify/*"
        ):
            return

        max_requests, time_window = parse_limit_string(limit_string)
        self.route_patterns[route_pattern] = (max_requests, time_window)

    def exempt(self, f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            g.humanify_rate_limit_exempt = True
            return f(*args, **kwargs)

        return decorated_function

    @property
    def _client_ip(self):
        if hasattr(g, "humanify_client_ip"):
            return g.humanify_client_ip

        client_ip = (
            request.remote_addr
            if is_valid_routable_ip(request.remote_addr or "127.0.0.1")
            else None
        )
        g.humanify_client_ip = client_ip
        return client_ip

    def get_route_limit(self, endpoint, method, path):
        route_key = f"{endpoint}:{method}"

        if route_key in self.route_limits:
            return self.route_limits[route_key]

        for pattern, (max_req, time_win) in self.route_patterns.items():
            if self._match_route_pattern(path, pattern):
                return max_req, time_win

        return self.max_requests, self.time_window

    def _match_route_pattern(self, path, pattern):
        if not validate_regex_complexity(pattern):
            return False

        pattern = pattern.replace("*", ".*")
        pattern = re.sub(r"<[^>]+>", "[^/]+", pattern)
        pattern = f"^{pattern}$"

        try:
            return bool(re.match(pattern, path))
        except re.error:
            return False

    def before_request(self):
        if request.endpoint in [
            "humanify.rate_limited",
            "humanify.access_denied",
        ]:
            return

        if hasattr(g, "humanify_rate_limit_exempt"):
            return

        if self.is_rate_limited():
            return redirect(
                url_for(
                    "humanify.rate_limited",
                    next=request.full_path.rstrip("?"),
                )
            )

    def is_rate_limited(self, ip=None):
        if not request.endpoint:
            return False

        max_requests, time_window = self.get_route_limit(
            request.endpoint,
            request.method,
            request.path,
        )

        route_key = f"{request.endpoint}:{request.method}"
        return self.is_rate_limited_for_route(
            route_key,
            max_requests,
            time_window,
            ip,
        )

    def _evict_oldest_client(self):
        if not self.client_access_order:
            return

        oldest_client = self.client_access_order.popleft()
        if oldest_client in self.ip_request_times:
            del self.ip_request_times[oldest_client]

    def _cleanup_expired_requests(self, request_times, current_time, time_window):
        while request_times and request_times[0] <= current_time - time_window:
            request_times.popleft()

    def is_rate_limited_for_route(
        self,
        route_key,
        max_requests,
        time_window,
        ip=None,
    ):
        self._aggressive_cleanup()

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

        if len(self.ip_request_times) >= self.MAX_CLIENTS:
            self._evict_oldest_client()

        if client_id not in self.ip_request_times:
            self.ip_request_times[client_id] = {}
            self.client_access_order.append(client_id)

        client_routes = self.ip_request_times[client_id]

        if len(client_routes) >= self.MAX_ROUTES_PER_CLIENT:
            oldest_route = next(iter(client_routes))
            del client_routes[oldest_route]

        if route_key not in client_routes:
            client_routes[route_key] = deque()

        request_times = client_routes[route_key]

        self._cleanup_expired_requests(request_times, current_time, time_window)

        if len(request_times) < max_requests:
            request_times.append(current_time)
            return False

        return True

    def reset_client(self, client_id, route_key=None):
        if client_id in self.ip_request_times:
            if route_key:
                if route_key in self.ip_request_times[client_id]:
                    self.ip_request_times[client_id][route_key].clear()
            else:
                del self.ip_request_times[client_id]
                if client_id in self.client_access_order:
                    self.client_access_order.remove(client_id)

    def get_client_stats(self, client_id):
        stats = {}
        current_time = time.time()

        if client_id in self.ip_request_times:
            for route_key, request_times in self.ip_request_times[client_id].items():
                self._cleanup_expired_requests(
                    request_times, current_time, self.time_window
                )

                stats[route_key] = {
                    "current_requests": len(request_times),
                    "next_reset": (
                        request_times[0] + self.time_window if request_times else 0
                    ),
                }

        return stats
