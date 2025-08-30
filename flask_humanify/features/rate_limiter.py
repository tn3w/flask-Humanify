import hashlib
import time
from collections import defaultdict, deque
from typing import Optional

from werkzeug.wrappers import Response
from flask import Flask, request, redirect, url_for, render_template, g
from flask_humanify.utils import get_client_ip, get_return_url


class RateLimiter:
    """
    Rate limiter.
    """

    def __init__(
        self,
        app=None,
        max_requests: int = 10,
        time_window: int = 10,
    ) -> None:
        """
        Initialize the rate limiter.
        """
        self.app = app
        if app is not None:
            self.init_app(app)
        self.max_requests = max_requests
        self.time_window = time_window
        self.ip_request_times = defaultdict(deque)

    def init_app(self, app: Flask) -> None:
        """
        Initialize the rate limiter.
        """
        self.app = app
        self.app.before_request(self.before_request)

        @self.app.route(
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

    @property
    def _client_ip(self) -> Optional[str]:
        """Get the client IP address."""
        if hasattr(g, "humanify_client_ip"):
            return g.humanify_client_ip

        client_ip = get_client_ip(request)
        g.humanify_client_ip = client_ip
        return client_ip

    def before_request(self) -> Optional[Response]:
        """
        Before request hook.
        """
        if request.endpoint in ["humanify.rate_limited", "humanify.access_denied"]:
            return

        ip = self._client_ip or "127.0.0.1"
        if self.is_rate_limited(ip):
            return redirect(
                url_for(
                    "humanify.rate_limited", return_url=request.full_path.rstrip("?")
                )
            )

    def is_rate_limited(self, ip: str) -> bool:
        """
        Check if the IP is rate limited.
        """
        hashed_ip = hashlib.sha256(ip.encode()).hexdigest()

        current_time = time.time()
        request_times = self.ip_request_times[hashed_ip]

        while request_times and request_times[0] <= current_time - self.time_window:
            request_times.popleft()

        if len(request_times) < self.max_requests:
            request_times.append(current_time)
            return False

        return True
