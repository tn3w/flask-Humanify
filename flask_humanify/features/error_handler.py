from typing import Final, Optional, List, Union, Dict, Tuple
from flask import Flask, render_template


ERROR_CODES: Final[Dict[int, Dict[str, str]]] = {
    400: {
        "title": "Bad Request",
        "description": "The server could not understand your request due to invalid syntax.",
    },
    401: {
        "title": "Unauthorized",
        "description": "You must authenticate yourself to get the requested response.",
    },
    403: {
        "title": "Forbidden",
        "description": "You do not have access rights to the content.",
    },
    404: {
        "title": "Not Found",
        "description": "The server cannot find the requested resource.",
    },
    405: {
        "title": "Method Not Allowed",
        "description": (
            "The request method is known by the server"
            " but is not supported by the target resource."
        ),
    },
    406: {
        "title": "Not Acceptable",
        "description": (
            "The server cannot produce a response matching the list of acceptable values "
            "defined in your request's proactive content negotiation headers."
        ),
    },
    408: {
        "title": "Request Timeout",
        "description": (
            "The server did not receive a complete request message from you within the time that "
            "it was prepared to wait."
        ),
    },
    409: {
        "title": "Conflict",
        "description": (
            "The request could not be completed due to a conflict with the current state of "
            "the target resource."
        ),
    },
    410: {
        "title": "Gone",
        "description": (
            "The requested resource is no longer available and will not be available again."
        ),
    },
    411: {
        "title": "Length Required",
        "description": (
            "The server refuses to accept the request without a defined Content-Length header."
        ),
    },
    412: {
        "title": "Precondition Failed",
        "description": (
            "The server does not meet one of the preconditions that you put on "
            "the request header fields."
        ),
    },
    413: {
        "title": "Payload Too Large",
        "description": "The request entity is larger than limits defined by the server.",
    },
    414: {
        "title": "URI Too Long",
        "description": (
            "The URI requested by you is longer than the server is willing to interpret."
        ),
    },
    415: {
        "title": "Unsupported Media Type",
        "description": "The media format of the requested data is not supported by the server.",
    },
    416: {
        "title": "Range Not Satisfiable",
        "description": (
            "The range specified by the Range header field in your request can't be fulfilled."
        ),
    },
    417: {
        "title": "Expectation Failed",
        "description": (
            "The expectation given in your request's Expect header field could not be met by at "
            "least one of the inbound servers."
        ),
    },
    418: {
        "title": "I'm a teapot",
        "description": "The web server rejects the attempt to make coffee with a teapot.",
    },
    422: {
        "title": "Unprocessable Entity",
        "description": (
            "The request was well-formed but was unable to be followed due to semantic errors."
        ),
    },
    423: {
        "title": "Locked",
        "description": "The resource that is being accessed is locked.",
    },
    424: {
        "title": "Failed Dependency",
        "description": "The request failed due to failure of a previous request.",
    },
    428: {
        "title": "Precondition Required",
        "description": "The origin server requires your request to be conditional.",
    },
    429: {
        "title": "Too Many Requests",
        "description": "You have sent too many requests in a given amount of time.",
    },
    431: {
        "title": "Request Header Fields Too Large",
        "description": (
            "The server is unwilling to process your request because its header "
            "fields are too large."
        ),
    },
    451: {
        "title": "Unavailable For Legal Reasons",
        "description": (
            "The server is denying access to the resource as a consequence of a legal demand."
        ),
    },
    500: {
        "title": "Internal Server Error",
        "description": "The server has encountered a situation it doesn't know how to handle.",
    },
    501: {
        "title": "Not Implemented",
        "description": "The request method is not supported by the server and cannot be handled.",
    },
    502: {
        "title": "Bad Gateway",
        "description": (
            "The server, while acting as a gateway or proxy, received an invalid response from "
            "the upstream server."
        ),
    },
    503: {
        "title": "Service Unavailable",
        "description": "The server is not ready to handle the request.",
    },
    504: {
        "title": "Gateway Timeout",
        "description": (
            "The server is acting as a gateway or proxy and did not receive a timely response "
            "from the upstream server."
        ),
    },
    505: {
        "title": "HTTP Version Not Supported",
        "description": "The HTTP version used in your request is not supported by the server.",
    },
}


class ErrorHandler:
    """Error handler for Flask applications."""

    def __init__(
        self,
        app: Flask,
        errors: Optional[Union[List[int], Dict[Union[int, str], dict]]] = None,
        template_path: Optional[str] = None,
    ) -> None:
        self.app = app
        self.errors = errors
        self.template_path = template_path

        if self.app:
            self.register_error_handlers()

    def register_error_handlers(self) -> None:
        """Register error handlers for the given error codes."""
        for error_code in self.errors or ERROR_CODES:
            if not isinstance(error_code, int):
                continue

            self.app.register_error_handler(error_code, self.handle_error)

    def handle_error(self, error: Exception) -> Tuple[str, int]:
        """Render exception page with appropriate error information."""
        code = getattr(error, "code", type(error).__name__)
        if isinstance(code, str) and code.isdigit():
            code = int(code)

        info = {}
        if isinstance(self.errors, dict):
            info = self.errors.get(code, {})
        elif isinstance(code, int):
            info = ERROR_CODES.get(code, {})

        title = f"{code} | {info.get('title', 'Error')}"
        message = (
            info.get("description")
            or str(error).split(" ", 1)[-1].strip()
            or "An error occurred"
        )
        template = info.get("template") or self.template_path or "exception.html"

        return (
            render_template(template)
            .replace("EXCEPTION_TITLE", title)
            .replace("EXCEPTION_CODE", str(code))
            .replace("EXCEPTION_MESSAGE", message),
            getattr(error, "code", 500),
        )
