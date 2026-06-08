from prometheus_client import Counter

# Login attempts counter
login_attempts = Counter(
    "auth_login_attempts_total",
    "Total login attempts",
    ["result"]
)

# Account lockouts counter
account_lockouts = Counter(
    "auth_account_lockouts_total",
    "Total account lockouts due to brute force"
)

# Token refresh counter
token_refresh = Counter(
    "auth_token_refresh_total",
    "Total token refresh attempts",
    ["result"]
)

# 2FA attempts counter
two_fa_attempts = Counter(
    "auth_2fa_attempts_total",
    "Total 2FA verification attempts",
    ["result"]
)

# Registration counter
registrations = Counter(
    "auth_registrations_total",
    "Total registration attempts",
    ["result"]
)
