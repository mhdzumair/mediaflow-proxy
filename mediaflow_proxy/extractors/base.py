from abc import ABC, abstractmethod
from typing import Dict, Optional, Any

import httpx
from urllib.parse import urlparse

from mediaflow_proxy.configs import settings


class ExtractorError(Exception):
    """Base exception for all extractors."""
    pass


class BaseExtractor(ABC):
    """Base class for all URL extractors."""

    def __init__(self, request_headers: dict):
        # Header base dell’app
        self.base_headers = {
            "user-agent": settings.user_agent,
        }
        self.mediaflow_endpoint = "proxy_stream_endpoint"
        self.base_headers.update(request_headers)

        # Client HTTPX persistenti:
        # - Nessun verify per-request: la verifica certificati si configura a livello di client
        # - Redirect automatici attivi per seguire 301/302 (es. daddylive.sx -> thedaddy.top)
        # - Timeout ragionevole; aggiungere altri parametri se servono (http2, proxies, ecc.)
        self._default_client = httpx.AsyncClient(
            timeout=httpx.Timeout(20.0),
            follow_redirects=True,  # segue 3xx automaticamente [5][6]
        )  # verify=True di default [3][2]

        # Client "insecure" per domini con certificati problematici (es. newkso.ru)
        # Valuta di sostituire verify=False con un SSLContext dedicato per maggiore sicurezza.
        self._insecure_client = httpx.AsyncClient(
            timeout=httpx.Timeout(20.0),
            verify=False,
            follow_redirects=True,  # segue 3xx anche qui [5][6]
        )  # [2][1]

    async def _make_request(
        self, url: str, method: str = "GET", headers: Optional[Dict] = None, **kwargs
    ) -> httpx.Response:
        """Make HTTP request with error handling."""
        try:
            netloc = urlparse(url).netloc
            # Seleziona il client in base al dominio
            client = self._insecure_client if "newkso.ru" in netloc else self._default_client  # [2][4]

            # Costruisci gli header effettivi
            request_headers = self.base_headers.copy()
            request_headers.update(headers or {})

            # Rimuovi 'verify' dai kwargs per evitare TypeError con httpx async
            kwargs.pop("verify", None)  # [1]

            response = await client.request(
                method,
                url,
                headers=request_headers,
                **kwargs,
            )
            # raise_for_status solleva per 4xx/5xx; i 3xx sono già seguiti grazie a follow_redirects=True
            response.raise_for_status()
            return response
        except httpx.HTTPError as e:
            raise ExtractorError(f"HTTP request failed for URL {url}: {str(e)}")
        except Exception as e:
            raise ExtractorError(f"Request failed for URL {url}: {str(e)}")

    async def aclose(self):
        """Chiudere i client su shutdown dell’app."""
        await self._default_client.aclose()
        await self._insecure_client.aclose()

    @abstractmethod
    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract final URL and required headers."""
        pass
