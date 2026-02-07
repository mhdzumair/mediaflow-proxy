from .proxy import proxy_router
from .extractor import extractor_router
from .speedtest import speedtest_router
from .playlist_builder import playlist_builder_router
from .xtream import xtream_root_router
from .acestream import acestream_router
from .telegram import telegram_router

__all__ = [
    "proxy_router",
    "extractor_router",
    "speedtest_router",
    "playlist_builder_router",
    "xtream_root_router",
    "acestream_router",
    "telegram_router",
]
