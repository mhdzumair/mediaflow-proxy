from enum import Enum
from typing import Dict, Optional

from pydantic import BaseModel, HttpUrl


class SpeedTestProvider(str, Enum):
    REAL_DEBRID = "real_debrid"
    ALL_DEBRID = "all_debrid"


class ServerInfo(BaseModel):
    url: str
    name: str


class UserInfo(BaseModel):
    ip: Optional[str] = None
    isp: Optional[str] = None
    country: Optional[str] = None


class MediaFlowServer(BaseModel):
    url: HttpUrl
    api_password: Optional[str] = None
    name: Optional[str] = None


class BrowserSpeedTestConfig(BaseModel):
    provider: SpeedTestProvider
    test_urls: Dict[str, str]
    test_duration: int = 10
    user_info: Optional[UserInfo] = None


class BrowserSpeedTestRequest(BaseModel):
    provider: SpeedTestProvider
    api_key: Optional[str] = None
    current_api_password: Optional[str] = None
