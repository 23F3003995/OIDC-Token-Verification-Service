from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from verifier import check_token

app = FastAPI(title="JWT verifier")


@app.get("/")
def root():
    return {"status": "ok"}


@app.post("/verify")
async def verify(request: Request):
    try:
        body = await request.json()
        token = body.get("token") if isinstance(body, dict) else None
    except Exception:
        token = None
    claims = check_token(token)
    if claims is None:
        return JSONResponse(status_code=401, content={"valid": False})
    return {
        "valid": True,
        "email": claims.get("email"),
        "sub": claims.get("sub"),
        "aud": claims.get("aud"),
    }
