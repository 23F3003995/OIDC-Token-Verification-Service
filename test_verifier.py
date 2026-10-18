import time, base64, json, jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import verifier
from verifier import check_token, ISSUER, AUDIENCE

priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub_pem = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
priv_pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
other = rsa.generate_private_key(public_exponent=65537, key_size=2048)

now = int(time.time())
def mint(key=priv_pem, alg="RS256", **over):
    c = {"iss": ISSUER, "aud": AUDIENCE, "sub": "u123", "email": "a@b.c", "iat": now, "exp": now + 300}
    c.update(over)
    c = {k: v for k, v in c.items() if v is not None}
    return jwt.encode(c, key, algorithm=alg)

def chk(t): return check_token(t, pub_pem)

good = mint()
assert chk(good)["email"] == "a@b.c"
assert chk(mint(exp=now - 10)) is None, "expired"
assert chk(mint(aud="other.apps.exam.local")) is None, "wrong aud"
assert chk(mint(iss="https://evil")) is None, "wrong iss"
assert chk(mint(exp=None)) is None, "missing exp"
h, p, s = good.split(".")
claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
claims["email"] = "evil@x.y"
p2 = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
assert chk(f"{h}.{p2}.{s}") is None, "tampered payload"
other_pem = other.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
assert chk(mint(key=other_pem)) is None, "wrong signing key"
# alg=none
none_tok = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode() + "." + p + "."
assert chk(none_tok) is None, "alg none"
# HS256 signed with the public key text (key confusion)
import hmac, hashlib
hh = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
sig = base64.urlsafe_b64encode(hmac.new(pub_pem.encode(), f"{hh}.{p}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
assert chk(f"{hh}.{p}.{sig}") is None, "HS256 confusion"
for bad in [None, "", "abc", "a.b.c", 123, {"x": 1}]:
    assert chk(bad) is None, bad
# the embedded real key parses as a valid RS256 public key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
k = load_pem_public_key(verifier.PUBLIC_KEY.encode()); print("embedded key bits:", k.key_size)
assert check_token(good) is None  # token signed by a different key fails against embedded key
print("ALL OK")
