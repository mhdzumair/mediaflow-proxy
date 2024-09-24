import base64
import json
import logging
import time
from urllib.parse import urlencode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from mediaflow_proxy.configs import settings


class EncryptionHandler:
    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode("utf-8").ljust(32)[:32]

    def encrypt_data(self, data: dict, expiration: int = None, ip: str = None) -> str:
        if expiration:
            data["exp"] = int(time.time()) + expiration
        if ip:
            data["ip"] = ip
        json_data = json.dumps(data).encode("utf-8")
        iv = get_random_bytes(16)
        cipher = AES.new(self.secret_key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(json_data, AES.block_size))
        return base64.urlsafe_b64encode(iv + encrypted_data).decode("utf-8")

    def decrypt_data(self, token: str, client_ip: str) -> dict:
        try:
            encrypted_data = base64.urlsafe_b64decode(token.encode("utf-8"))
            iv = encrypted_data[:16]
            cipher = AES.new(self.secret_key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
            data = json.loads(decrypted_data)

            if "exp" in data:
                if data["exp"] < time.time():
                    raise HTTPException(status_code=401, detail="Token has expired")
                del data["exp"]  # Remove expiration from the data

            if "ip" in data:
                if data["ip"] != client_ip:
                    raise HTTPException(status_code=403, detail="IP address mismatch")
                del data["ip"]  # Remove IP from the data

            return data
        except Exception as e:
            raise HTTPException(status_code=401, detail="Invalid or expired token")


class EncryptionMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.encryption_handler = encryption_handler

    async def dispatch(self, request: Request, call_next):
        encrypted_token = request.query_params.get("token")
        if encrypted_token:
            try:
                client_ip = self.get_client_ip(request)
                decrypted_data = self.encryption_handler.decrypt_data(encrypted_token, client_ip)
                # Modify request query parameters with decrypted data
                query_params = dict(request.query_params)
                query_params.pop("token")  # Remove the encrypted token from query params
                query_params.update(decrypted_data)  # Add decrypted data to query params
                query_params["has_encrypted"] = True

                # Create a new request scope with updated query parameters
                new_query_string = urlencode(query_params)
                request.scope["query_string"] = new_query_string.encode()
                request._query_params = query_params
            except HTTPException as e:
                return JSONResponse(content={"error": str(e.detail)}, status_code=e.status_code)

        try:
            response = await call_next(request)
        except Exception as e:
            logging.exception("An error occurred while processing the request")
            return JSONResponse(content={"error": str(e)}, status_code=500)
        return response

    @staticmethod
    def get_client_ip(request: Request) -> str | None:
        """
        Extract the client's real IP address from the request headers or fallback to the client host.
        """
        x_forwarded_for = request.headers.get("X-Forwarded-For")
        if x_forwarded_for:
            # In some cases, this header can contain multiple IPs
            # separated by commas.
            # The first one is the original client's IP.
            return x_forwarded_for.split(",")[0].strip()
        # Fallback to X-Real-IP if X-Forwarded-For is not available
        x_real_ip = request.headers.get("X-Real-IP")
        if x_real_ip:
            return x_real_ip
        return request.client.host if request.client else "127.0.0.1"


encryption_handler = EncryptionHandler(settings.api_password)
