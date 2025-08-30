import time
import os
from collections import defaultdict, deque
from typing import Optional

from werkzeug.wrappers import Response
from flask import Flask, Blueprint, request, redirect, url_for, render_template, g
from flask_humanify.memory_server import MemoryClient, ensure_server_running
from flask_humanify.utils import get_client_ip, get_or_create_client_id, get_return_url


class RateLimiter:
    """
    Rate limiter.
    """

    def __init__(
        self,
        app=None,
        max_requests: int = 10,
        time_window: int = 10,
        use_client_id: Optional[bool] = None,
    ) -> None:
        """
        Initialize the rate limiter.
        """
        self.app = app
        self.use_client_id = use_client_id
        self._client_id_secret_key = None
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
        humanify_use_client_id = app.config.get("HUMANIFY_USE_CLIENT_ID", False)
        if self.use_client_id is None:
            self.use_client_id = humanify_use_client_id

        if self.use_client_id:
            humanify_secret_key = app.config.get(
                "HUMANIFY_SECRET_KEY", None
            )
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
            template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
            rate_limiter_bp = Blueprint(
                "humanify", 
                __name__,
                template_folder=template_dir
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
            @app.route("/humanify/rate_limited", methods=["GET"], endpoint="humanify.rate_limited")
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

        if self.is_rate_limited():
            return redirect(
                url_for(
                    "humanify.rate_limited", return_url=request.full_path.rstrip("?")
                )
            )

    def is_rate_limited(self, ip: Optional[str] = None) -> bool:
        """
        Check if the IP is rate limited.
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
        request_times = self.ip_request_times[client_id]

        while request_times and request_times[0] <= current_time - self.time_window:
            request_times.popleft()

        if len(request_times) < self.max_requests:
            request_times.append(current_time)
            return False

        return True
