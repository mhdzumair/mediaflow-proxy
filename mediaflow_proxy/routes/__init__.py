__all__ = [
    "proxy_router",
    "extractor_router",
    "speedtest_router",
    "playlist_builder_router",
    "xtream_root_router",
    "acestream_router",
    "telegram_router",
]


def __getattr__(name: str):
    # Lazy import routers so importing a single route module does not
    # pull in optional integrations (telegram/acestream/transcode) at startup.
    if name == "proxy_router":
        from .proxy import proxy_router

        return proxy_router
    if name == "extractor_router":
        from .extractor import extractor_router

        return extractor_router
    if name == "speedtest_router":
        from .speedtest import speedtest_router

        return speedtest_router
    if name == "playlist_builder_router":
        from .playlist_builder import playlist_builder_router

        return playlist_builder_router
    if name == "xtream_root_router":
        from .xtream import xtream_root_router

        return xtream_root_router
    if name == "acestream_router":
        from .acestream import acestream_router

        return acestream_router
    if name == "telegram_router":
        from .telegram import telegram_router

        return telegram_router
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
