from flask import Flask
from flask_humanify import (
    Humanify,
    require_human,
    always_challenge,
    block_bots,
    exempt_from_protection,
)

app = Flask(__name__)

humanify = Humanify(app)


@app.route("/")
def index():
    return "Welcome to the homepage!"


@app.route("/protected")
@require_human()
def protected():
    return "This route challenges bots with a captcha"


@app.route("/strict")
@require_human(action="deny_access")
def strict():
    return "This route blocks bots completely"


@app.route("/always-verify")
@always_challenge
def always_verify():
    return "Everyone must solve a captcha to access this"


@app.route("/no-bots")
@block_bots
def no_bots():
    return "Bots are immediately blocked without a challenge"


@app.route("/public")
@exempt_from_protection
def public():
    return "This route is exempt from all Humanify protection"


@app.route("/api/data")
@exempt_from_protection
def api_data():
    return {"data": "This API endpoint bypasses bot protection"}


if __name__ == "__main__":
    app.run(debug=True)
