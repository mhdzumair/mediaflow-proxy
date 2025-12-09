from typing import Dict, Type

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError
from mediaflow_proxy.extractors.dlhd import DLHDExtractor
from mediaflow_proxy.extractors.doodstream import DoodStreamExtractor
from mediaflow_proxy.extractors.sportsonline import SportsonlineExtractor
from mediaflow_proxy.extractors.filelions import FileLionsExtractor
from mediaflow_proxy.extractors.filemoon import FileMoonExtractor
from mediaflow_proxy.extractors.F16Px import F16PxExtractor
from mediaflow_proxy.extractors.livetv import LiveTVExtractor
from mediaflow_proxy.extractors.lulustream import LuluStreamExtractor
from mediaflow_proxy.extractors.maxstream import MaxstreamExtractor
from mediaflow_proxy.extractors.mixdrop import MixdropExtractor
from mediaflow_proxy.extractors.okru import OkruExtractor
from mediaflow_proxy.extractors.streamtape import StreamtapeExtractor
from mediaflow_proxy.extractors.streamwish import StreamWishExtractor
from mediaflow_proxy.extractors.supervideo import SupervideoExtractor
from mediaflow_proxy.extractors.turbovidplay import TurboVidPlayExtractor
from mediaflow_proxy.extractors.uqload import UqloadExtractor
from mediaflow_proxy.extractors.vavoo import VavooExtractor
from mediaflow_proxy.extractors.vidmoly import VidmolyExtractor
from mediaflow_proxy.extractors.vidoza import VidozaExtractor
from mediaflow_proxy.extractors.vixcloud import VixCloudExtractor
from mediaflow_proxy.extractors.fastream import FastreamExtractor
from mediaflow_proxy.extractors.voe import VoeExtractor


class ExtractorFactory:
    """Factory for creating URL extractors."""

    _extractors: Dict[str, Type[BaseExtractor]] = {
        "Doodstream": DoodStreamExtractor,
        "FileLions": FileLionsExtractor,
        "FileMoon": FileMoonExtractor,
        "F16Px": F16PxExtractor,
        "Uqload": UqloadExtractor,
        "Mixdrop": MixdropExtractor,
        "Streamtape": StreamtapeExtractor,
        "StreamWish": StreamWishExtractor,
        "Supervideo": SupervideoExtractor,
        "TurboVidPlay": TurboVidPlayExtractor,
        "VixCloud": VixCloudExtractor,
        "Okru": OkruExtractor,
        "Maxstream": MaxstreamExtractor,
        "LiveTV": LiveTVExtractor,
        "LuluStream": LuluStreamExtractor,
        "DLHD": DLHDExtractor,
        "Vavoo": VavooExtractor,
        "Vidmoly": VidmolyExtractor,
        "Vidoza": VidozaExtractor,
        "Fastream": FastreamExtractor,
        "Voe": VoeExtractor,
        "Sportsonline": SportsonlineExtractor,
    }

    @classmethod
    def get_extractor(cls, host: str, request_headers: dict) -> BaseExtractor:
        """Get appropriate extractor instance for the given host."""
        extractor_class = cls._extractors.get(host)
        if not extractor_class:
            raise ExtractorError(f"Unsupported host: {host}")
        return extractor_class(request_headers)
