<h1 align="center">flask-Humanify</h1>
<p align="center">A strong bot protection system for Flask with many features: rate limiting, special rules for users, web crawler detection, and automatic bot detection.</p>
<p align="center"><a rel="noreferrer noopener" href="https://github.com/tn3w/flask-Humanify"><img alt="Github" src="https://img.shields.io/badge/Github-141e24.svg?&style=for-the-badge&logo=github&logoColor=white"></a>  <a rel="noreferrer noopener" href="https://pypi.org/project/flask-Humanify/"><img alt="PyPI" src="https://img.shields.io/badge/PyPi-141e24.svg?&style=for-the-badge&logo=python&logoColor=white"></a>  <a rel="noreferrer noopener" href="https://libraries.io/pypi/flask-Humanify"><img alt="Libraries.io" src="https://img.shields.io/badge/Libraries.io-141e24.svg?&style=for-the-badge&logo=npm&logoColor=white"></a></p>

<br>

```python
from flask import Flask
from flask_humanify import Humanify

app = Flask(__name__)
humanify = Humanify(app, challenge_type="one_click", image_dataset="ai_dogs")

# Register the middleware to deny access to bots
humanify.register_middleware(action="challenge")

@app.route("/")
def index():
    """
    A route that is protected against bots and DDoS attacks.
    """
    return "Hello, Human!"

if __name__ == "__main__":
    app.run()
```

### Advanced Protection Rules

You can customize bot protection with advanced filtering rules:

```python
# Protect specific endpoints with regex patterns
humanify.register_middleware(
    action="challenge",
    endpoint_patterns=["api.*", "admin.*"]  # Protect all API and admin endpoints
)

# Protect specific URL paths
humanify.register_middleware(
    action="deny_access",
    url_patterns=["/sensitive/*", "/admin/*"]  # Deny bot access to sensitive areas
)

# Exclude certain patterns from protection
humanify.register_middleware(
    endpoint_patterns=["api.*"],
    exclude_patterns=["api.public.*"]  # Don't protect public API endpoints
)

# Filter by request parameters
humanify.register_middleware(
    request_filters={
        "method": ["POST", "PUT", "DELETE"],  # Only protect write operations
        "args.admin": "true",                # Only when admin=true query parameter exists
        "headers.content-type": "regex:application/json.*"  # Match content type with regex
    }
)
```

Not using the middleware:

```python
@app.route("/")
def index():
    """
    A route that is protected against bots and DDoS attacks.
    """
    if humanify.is_bot:
        return humanify.challenge()
    return "Hello, Human!"
```

## Usage

### Installation

Install the package with pip:

```bash
pip install flask-humanify --upgrade
```

Import the extension:

```python
from flask_humanify import Humanify
```

Add the extension to your Flask app:

```python
app = Flask(__name__)
humanify = Humanify(app)
```

## Additional Features

### Rate Limiting

Flask-Humanify includes a rate limiting feature to protect your application from excessive requests:

```python
from flask import Flask
from flask_humanify import Humanify, RateLimiter

app = Flask(__name__)
humanify = Humanify(app)
# Default: 10 requests per 10 seconds
rate_limiter = RateLimiter(app)

# Or customize rate limits
rate_limiter = RateLimiter(app, max_requests=20, time_window=30)
```

The rate limiter will automatically:

- Track requests by IP address
- Hash IPs for privacy
- Redirect to a rate-limited page when limits are exceeded
- Ignore rate limits for special pages like the rate-limited and access-denied pages

### Error Handling

Flask-Humanify provides a clean error handling system:

```python
from flask import Flask
from flask_humanify import Humanify, ErrorHandler

app = Flask(__name__)
humanify = Humanify(app)
# Handle all standard HTTP errors
error_handler = ErrorHandler(app)

# Use custom template with placeholders: EXCEPTION_TITLE, EXCEPTION_CODE, EXCEPTION_MESSAGE
error_handler = ErrorHandler(app, template_path="templates/error.html")

# Or handle only specific error codes
error_handler = ErrorHandler(app, errors=[404, 429, 500])

# Or handle only specific error codes with a custom template
error_handler = ErrorHandler(app, errors={404: {"template": "404.html"}})
```

The error handler:

- Renders user-friendly error pages
- Uses the custom exception.html template
- Provides appropriate error messages and descriptions
- Includes HTTP status codes and titles

### Complete Example

Here's a complete example combining all features:

```python
from flask import Flask
from flask_humanify import Humanify, RateLimiter, ErrorHandler

app = Flask(__name__)
# Setup core protection
humanify = Humanify(app, challenge_type="one_click", image_dataset="animals")
humanify.register_middleware(action="challenge")

# Add rate limiting
rate_limiter = RateLimiter(app, max_requests=15, time_window=60)

# Add error handling
error_handler = ErrorHandler(app)

@app.route("/")
def index():
    return "Hello, Human!"

if __name__ == "__main__":
    app.run(debug=True)
```
