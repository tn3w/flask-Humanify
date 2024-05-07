"""
⭐ Example code for flask_Captchaify

https://github.com/tn3w/flask_Captchaify
Made with 💩 in Germany by TN3W
"""

from flask import Flask
from flask_Captchaify import Captcha

app = Flask(__name__)
captcha = Captcha(app)

@app.route('/')
def index():
    """
    Very good protected Route
    """

    return 'Hello Human!'

if __name__ == '__main__':
    app.run(host = 'localhost', port = 8080)
