import base64
import json
import logging
import time
import traceback
from typing import Optional
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
        return base64.urlsafe_b64encode(iv + encrypted_data).decode("utf-8").rstrip("=")

    def decrypt_data(self, token: str, client_ip: str) -> dict:
        try:
            padding_needed = (4 - len(token) % 4) % 4
            encrypted_token_b64_padded = token + ("=" * padding_needed)
            encrypted_data = base64.urlsafe_b64decode(encrypted_token_b64_padded.encode("utf-8"))
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
        path = request.url.path
        token_marker = "/_token_"
        encrypted_token = None

        # Check for token in path
        if path.startswith(token_marker) and self.encryption_handler:
            try:
                # Extract token from the beginning of the path
                token_start = len(token_marker)
                token_end = path.find("/", token_start)

                if token_end == -1:  # No trailing slash
                    encrypted_token = path[token_start:]
                    remaining_path = ""
                else:
                    encrypted_token = path[token_start:token_end]
                    remaining_path = path[token_end:]

                # Modify the path to remove the token part
                request.scope["path"] = remaining_path

                # Update the raw path as well
                request.scope["raw_path"] = remaining_path.encode()

            except Exception as e:
                logging.error(f"Error processing token in path: {str(e)}")
                return JSONResponse(content={"error": f"Invalid token in path: {str(e)}"}, status_code=400)

        # Check for token in query parameters (original method)
        if not encrypted_token:  # Only check if we didn't already find a token in the path
            encrypted_token = request.query_params.get("token")

        # Process the token if found (from either source)
        if encrypted_token and self.encryption_handler:
            try:
                client_ip = self.get_client_ip(request)
                decrypted_data = self.encryption_handler.decrypt_data(encrypted_token, client_ip)

                # Modify request query parameters with decrypted data
                query_params = dict(request.query_params)
                if "token" in query_params:
                    query_params.pop("token")  # Remove the encrypted token from query params

                query_params.update(decrypted_data)  # Add decrypted data to query params
                query_params["has_encrypted"] = True

                # Create a new request scope with updated query parameters
                new_query_string = urlencode(query_params)
                request.scope["query_string"] = new_query_string.encode()
                request._query_params = query_params

            except HTTPException as e:
                return JSONResponse(content={"error": str(e.detail)}, status_code=e.status_code)
            except Exception as e:
                logging.error(f"Error decrypting token: {str(e)}")
                return JSONResponse(content={"error": f"Invalid token: {str(e)}"}, status_code=400)

        try:
            response = await call_next(request)
        except Exception:
            exc = traceback.format_exc(chain=False)
            logging.error("An error occurred while processing the request, error: %s", exc)
            return JSONResponse(
                content={"error": "An error occurred while processing the request, check the server for logs"},
                status_code=500,
            )
        return response

    @staticmethod
    def get_client_ip(request: Request) -> Optional[str]:
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


encryption_handler = EncryptionHandler(settings.api_password) if settings.api_password else None
