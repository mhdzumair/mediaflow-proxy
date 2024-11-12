from datetime import datetime
from enum import Enum
from typing import Dict, Optional

from pydantic import BaseModel, Field


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


class SpeedTestResult(BaseModel):
    speed_mbps: float = Field(..., description="Speed in Mbps")
    duration: float = Field(..., description="Test duration in seconds")
    data_transferred: int = Field(..., description="Data transferred in bytes")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class LocationResult(BaseModel):
    result: Optional[SpeedTestResult] = None
    error: Optional[str] = None
    server_name: str
    server_url: str


class SpeedTestTask(BaseModel):
    task_id: str
    provider: SpeedTestProvider
    results: Dict[str, LocationResult] = {}
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str = "running"
    user_info: Optional[UserInfo] = None
    current_location: Optional[str] = None
