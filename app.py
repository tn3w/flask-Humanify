from flask import Flask
from flask_humanify import Humanify, RateLimiter, ErrorHandler

# Log to file
import logging

logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]",
)

app = Flask(__name__)
humanify = Humanify(app, audio_dataset="characters")
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
