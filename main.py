from fastapi import FastAPI, UploadFile, Form, Request
from fastapi.responses import StreamingResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305
from io import BytesIO
import secrets
import base64

app = FastAPI()

# Serve templates and static files
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Show main page
@app.get("/", response_class=HTMLResponse)
def get_home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/encrypt")
async def encrypt(file: UploadFile):
    contents = await file.read()

    # Generate key and nonce
    key = XChaCha20Poly1305.generate_key()
    nonce = secrets.token_bytes(24)

    aead = XChaCha20Poly1305(key)
    encrypted = aead.encrypt(nonce, contents, None)

    # Output: nonce + encrypted
    result = nonce + encrypted
    file_out = BytesIO(result)
    file_out.seek(0)

    # Send file + key
    headers = {
        "X-Key": base64.urlsafe_b64encode(key).decode()
    }

    return StreamingResponse(file_out, media_type="application/octet-stream", headers=headers)


@app.post("/decrypt")
async def decrypt(file: UploadFile, key: str = Form(...)):
    contents = await file.read()

    try:
        key_bytes = base64.urlsafe_b64decode(key.encode())
        nonce = contents[:24]
        ciphertext = contents[24:]

        aead = XChaCha20Poly1305(key_bytes)
        decrypted = aead.decrypt(nonce, ciphertext, None)

        file_out = BytesIO(decrypted)
        file_out.seek(0)

        return StreamingResponse(file_out, media_type="application/octet-stream")
    except Exception:
        return HTMLResponse(content="Invalid key or file", status_code=400)
