import logging
from importlib import resources

from fastapi import FastAPI, Depends, Security, HTTPException
from fastapi.security import APIKeyQuery, APIKeyHeader
from starlette.responses import RedirectResponse
from starlette.staticfiles import StaticFiles

from mediaflow_proxy.configs import settings
from mediaflow_proxy.routes import proxy_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
app = FastAPI()
api_password_query = APIKeyQuery(name="api_password", auto_error=False)
api_password_header = APIKeyHeader(name="api_password", auto_error=False)


async def verify_api_key(api_key: str = Security(api_password_query), api_key_alt: str = Security(api_password_header)):
    """
    Verifies the API key for the request.

    Args:
        api_key (str): The API key to validate.
        api_key_alt (str): The alternative API key to validate.

    Raises:
        HTTPException: If the API key is invalid.
    """
    if api_key == settings.api_password or api_key_alt == settings.api_password:
        return

    raise HTTPException(status_code=403, detail="Could not validate credentials")


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


@app.get("/favicon.ico")
async def get_favicon():
    return RedirectResponse(url="/logo.png")


app.include_router(proxy_router, prefix="/proxy", tags=["proxy"], dependencies=[Depends(verify_api_key)])

static_path = resources.files("mediaflow_proxy").joinpath("static")
app.mount("/", StaticFiles(directory=str(static_path), html=True), name="static")


def run():
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8888)


if __name__ == "__main__":
    run()
