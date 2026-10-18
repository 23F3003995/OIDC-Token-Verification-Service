import jwt

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-ng2d8cvl.apps.exam.local"
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----
"""


def check_token(token, key=PUBLIC_KEY):
    """Return the claims dict if the token is valid, else None."""
    if not isinstance(token, str) or not token.strip():
        return None
    try:
        return jwt.decode(
            token.strip(),
            key,
            algorithms=["RS256"],  # fixed: blocks alg=none and HS256 key-confusion
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iss", "aud"], "verify_signature": True,
                     "verify_exp": True, "verify_aud": True, "verify_iss": True},
        )
    except Exception:
        return None
