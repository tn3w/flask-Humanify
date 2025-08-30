from flask import Flask
from flask_humanify import Humanify, RateLimiter, ErrorHandler


app = Flask(__name__)
humanify = Humanify(app)
humanify.register_middleware()
rate_limiter = RateLimiter(app)
error_handler = ErrorHandler(app)


@app.route("/")
def index():
    """
    Protect against bots and DDoS attacks.
    """
    return "Hello, Human!"


if __name__ == "__main__":
    app.run(debug=True)
