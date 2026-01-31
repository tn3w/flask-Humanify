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
humanify.register_middleware(app, action="challenge")

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
    app,
    action="challenge",
    endpoint_patterns=["api.*", "admin.*"]  # Protect all API and admin endpoints
)

# Protect specific URL paths
humanify.register_middleware(
    app,
    action="deny_access",
    url_patterns=["/sensitive/*", "/admin/*"]  # Deny bot access to sensitive areas
)

# Exclude certain patterns from protection
humanify.register_middleware(
    app,
    endpoint_patterns=["api.*"],
    exclude_patterns=["api.public.*"]  # Don't protect public API endpoints
)

# Filter by request parameters
humanify.register_middleware(
    app,
    request_filters={
        "method": ["POST", "PUT", "DELETE"],  # Only protect write operations
        "args.admin": "true",                # Only when admin=true query parameter exists
        "headers.content-type": "regex:application/json.*"  # Match content type with regex
    }
)
```

## Route-Level Protection with Decorators

Flask-Humanify provides powerful decorators for fine-grained bot protection on specific routes:

### `@require_human(action="challenge")`

Protects a route by challenging suspected bots with a captcha.

```python
from flask_humanify import require_human

@app.route("/protected")
@require_human()
def protected():
    return "Only humans can access this"

@app.route("/strict")
@require_human(action="deny_access")
def strict():
    return "Bots are blocked without a challenge"
```

**Parameters:**

- `action` (str): Action to take when a bot is detected
    - `"challenge"` (default): Show captcha challenge
    - `"deny_access"`: Block access immediately

### `@always_challenge`

Forces all visitors (including humans) to solve a captcha before accessing the route.

```python
from flask_humanify import always_challenge

@app.route("/sensitive")
@always_challenge
def sensitive():
    return "Everyone must solve a captcha"
```

### `@block_bots`

Immediately blocks all detected bots without showing a captcha challenge.

```python
from flask_humanify import block_bots

@app.route("/no-bots")
@block_bots
def no_bots():
    return "Bots cannot access this route"
```

### `@exempt_from_protection`

Exempts a route from all Humanify protection, including middleware rules.

```python
from flask_humanify import exempt_from_protection

@app.route("/public-api")
@exempt_from_protection
def public_api():
    return {"data": "No bot protection on this endpoint"}
```

### Decorator Priority

When both middleware and decorators are used:

1. `@exempt_from_protection` - Highest priority, bypasses all protection
2. Route-specific decorators - Override middleware settings for that route
3. Middleware rules - Apply to routes without decorators

## Usage

### Installation

Install the package with pip:

```bash
pip install flask-humanify --upgrade
```

#### Optional: Enhanced Security with re2

For better performance and protection against ReDoS (Regular Expression Denial of Service) attacks, install the `google-re2` library:

```bash
pip install google-re2
```

Flask-Humanify will automatically use `re2` if available, providing:
- Guaranteed linear-time regex execution (no catastrophic backtracking)
- Better performance with complex patterns
- Enhanced security when using custom `endpoint_patterns`, `url_patterns`, or `request_filters`

The library works without `re2`, but installing it is recommended for production environments.

### Basic Setup

```python
from flask import Flask
from flask_humanify import Humanify

app = Flask(__name__)
humanify = Humanify(app)
```

### Configuration Options

Humanify can be configured with various options to customize bot detection and challenge behavior:

```python
humanify = Humanify(
    app,
    challenge_type="one_click",    # Challenge type: "grid" or "one_click"
    image_dataset="ai_dogs",       # Image dataset: "ai_dogs", "animals", "characters", "keys"
    audio_dataset=None,            # Enable audio challenges: "characters" or None
    retrys=3,                      # Maximum failed attempts before blocking
    hardness=1,                    # Challenge difficulty: 1 (easy) to 5 (hard)
    behind_proxy=False,            # Set True if behind a proxy/load balancer
    use_client_id=False            # Use secure client IDs instead of IP addresses
)
```

**Configuration Parameters:**

- `challenge_type`: Type of visual challenge
    - `"one_click"`: Select one matching image from a grid (easier, faster)
    - `"grid"`: Select multiple matching images from a 3x3 grid (harder)

- `image_dataset`: Dataset for image challenges
    - `"ai_dogs"`: AI-generated dog images
    - `"animals"`: Various animal images
    - `"characters"`: Character/letter recognition
    - `"keys"`: Key/lock matching

- `audio_dataset`: Enable audio accessibility challenges
    - `None`: Disabled (default)
    - `"characters"`: Audio character recognition in multiple languages

- `retrys`: Number of failed attempts before temporary block (default: 3)

- `hardness`: Challenge difficulty level (1-5)
    - `1`: Easy - minimal distortion
    - `3`: Medium - moderate distortion
    - `5`: Hard - maximum distortion

- `behind_proxy`: Enable when behind reverse proxy/load balancer
    - Automatically configures ProxyFix for correct IP detection

- `use_client_id`: Use secure client IDs instead of IP addresses
    - Better for privacy and shared IP scenarios
    - Stored in secure HTTP-only cookies

## Additional Features

### Rate Limiting

Flask-Humanify includes a powerful rate limiting feature to protect your application from excessive requests:

```python
from flask import Flask
from flask_humanify import Humanify, RateLimiter

app = Flask(__name__)
humanify = Humanify(app)

# Initialize with default limits (10 requests per 10 seconds)
rate_limiter = RateLimiter(app)

# Or use human-readable limit strings
rate_limiter = RateLimiter(app, default_limit="100/day")

# Configure client tracking (defaults to IP-based)
rate_limiter = RateLimiter(
    app,
    default_limit="10/minute",
    use_client_id=True,     # Use secure client IDs instead of IPs
    behind_proxy=True       # Enable if behind a proxy/load balancer
)
```

#### Route-Specific Rate Limits

You can set different rate limits for specific routes or patterns:

```python
# Using decorator syntax
@app.route("/api/data")
@rate_limiter.limit("5/minute")  # Limit specific route
def get_data():
    return "data"

# Using pattern matching
rate_limiter.set_route_limit("/api/*", "100/hour")      # All API routes
rate_limiter.set_route_limit("/admin/<id>", "5/minute") # Admin routes

# Exempt routes from rate limiting
@app.route("/health")
@rate_limiter.exempt
def health_check():
    return "OK"
```

#### Advanced Usage

The rate limiter provides methods for managing and monitoring rate limits:

```python
# Reset rate limits for a client
rate_limiter.reset_client("client_id")                  # Reset all routes
rate_limiter.reset_client("client_id", "/api/data:GET") # Reset specific route

# Get client statistics
stats = rate_limiter.get_client_stats("client_id")
"""
Returns:
{
    "route:method": {
        "current_requests": 5,
        "next_reset": 1629123456.78
    }
}
"""

# Check rate limits programmatically
if rate_limiter.is_rate_limited():
    return "Too many requests!"
```

Features:

- Flexible rate limit formats: "10/second", "5 per minute", "100/day"
- Route-specific rate limits using decorators or patterns
- Client tracking via IPs or secure client IDs
- Proxy support with X-Forwarded-For headers
- Route exemptions for health checks and critical endpoints
- Built-in rate limit monitoring and management
- Automatic rate limit page with return URL

### CAPTCHA Integration

Flask-Humanify includes built-in support for multiple CAPTCHA providers to add an extra layer of protection:

```python
from flask import Flask
from flask_humanify import CaptchaEmbed

app = Flask(__name__)

# Initialize CAPTCHA with automatic theme detection and language
captcha = CaptchaEmbed(
    app,
    theme="auto",          # Options: "light", "dark", "auto"
    language="auto",       # Use specific language code like "en" if needed
    recaptcha_site_key="your_site_key",    # For Google reCAPTCHA
    recaptcha_secret="your_secret_key",
    hcaptcha_site_key="your_site_key",     # For hCaptcha
    hcaptcha_secret="your_secret_key",
    turnstile_site_key="your_site_key",    # For Cloudflare Turnstile
    turnstile_secret="your_secret_key",
    friendly_site_key="your_site_key",     # For Friendly Captcha
    friendly_secret="your_secret_key",
    altcha_secret="your_secret_key"        # For Altcha (a random generated secret)
)

@app.route("/protected", methods=["GET", "POST"])
def protected():
    if request.method == "POST":
        # Validate the CAPTCHA response
        if captcha.is_recaptcha_valid():    # Or use is_hcaptcha_valid(), is_turnstile_valid(), etc.
            return "Success!"
    return render_template("form.html")
```

In your templates, you can easily embed any supported CAPTCHA:

```html
<!-- Templates automatically get access to CAPTCHA embeds -->
<form method="POST">
    {{ recaptcha|safe }}
    <!-- For Google reCAPTCHA -->
    {{ hcaptcha|safe }}
    <!-- For hCaptcha -->
    {{ turnstile|safe }}
    <!-- For Cloudflare Turnstile -->
    {{ friendly|safe }}
    <!-- For Friendly Captcha -->
    {{ altcha|safe }}
    <!-- For Altcha (with default hardness) -->
    {{ altcha1|safe }}
    <!-- For Altcha (with hardness level 1-5) -->
    <button type="submit">Submit</button>
</form>
```

The CAPTCHA integration features:

- Automatic dark/light theme detection
- Multiple CAPTCHA provider support
- Customizable difficulty levels for Altcha
- Easy validation methods
- Automatic template context integration

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

## Bot Detection Features

Flask-Humanify automatically detects various types of suspicious traffic:

- **VPN Detection**: Identifies traffic from major VPN providers (NordVPN, ProtonVPN, ExpressVPN, etc.)
- **Proxy Detection**: Detects proxy servers and anonymizers
- **Datacenter IPs**: Flags requests from datacenter IP ranges
- **Tor Exit Nodes**: Identifies Tor network exit points
- **Web Crawlers**: Recognizes legitimate and malicious crawlers via user-agent analysis
- **Forum Spammers**: Blocks known spam sources from StopForumSpam database
- **Firehol Blocklists**: Uses Firehol Level 1 blocklist for known malicious IPs

All detection happens automatically with no additional configuration required.

## Complete Example

Here's a complete example combining all features:

```python
from flask import Flask
from flask_humanify import (
    Humanify,
    RateLimiter,
    ErrorHandler,
    require_human,
    always_challenge,
    block_bots,
    exempt_from_protection,
)

app = Flask(__name__)

# Setup core protection with custom configuration
humanify = Humanify(
    app,
    challenge_type="one_click",
    image_dataset="animals",
    audio_dataset="characters",  # Enable audio accessibility
    retrys=3,
    hardness=2,
    behind_proxy=True,
    use_client_id=True
)

# Protect all API routes with middleware
humanify.register_middleware(
    action="challenge",
    url_patterns="/api/*",
    exclude_patterns="/api/public/*"
)

# Add rate limiting
rate_limiter = RateLimiter(app, default_limit="100/hour")
rate_limiter.set_route_limit("/api/data", "10/minute")

# Add error handling
error_handler = ErrorHandler(app)

@app.route("/")
def index():
    return "Hello, Human!"

@app.route("/api/public/status")
@exempt_from_protection
def public_status():
    return {"status": "ok"}

@app.route("/login")
@always_challenge
def login():
    return "Login page - everyone must solve captcha"

@app.route("/admin")
@block_bots
def admin():
    return "Admin area - bots blocked immediately"

@app.route("/protected")
@require_human(action="challenge")
def protected():
    return "Protected content"

if __name__ == "__main__":
    app.run(debug=True)
```

## Security Best Practices

- **Use HTTPS**: Always enable HTTPS in production for secure cookie transmission
- **Behind Proxy**: Set `behind_proxy=True` when using reverse proxies or load balancers
- **Client IDs**: Consider `use_client_id=True` for better privacy and shared IP handling
- **Rate Limiting**: Combine bot protection with rate limiting for comprehensive defense
- **Retry Limits**: Adjust `retrys` based on your security requirements (lower = stricter)
- **Challenge Difficulty**: Balance `hardness` between security and user experience
- **Pattern Matching**: Use specific patterns in middleware to protect only necessary routes

## License

This project is licensed under the MIT License - see the LICENSE file for details.
