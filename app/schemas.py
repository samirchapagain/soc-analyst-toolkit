from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IOCRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=2048)

    @field_validator("indicator")
    @classmethod
    def clean_indicator(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Indicator cannot be blank")
        return value


class IOCBulkRequest(BaseModel):
    indicators: list[str] = Field(min_length=1, max_length=50)

    @field_validator("indicators")
    @classmethod
    def validate_indicators(cls, value: list[str]) -> list[str]:
        cleaned = [indicator.strip() for indicator in value]
        if any(not indicator or len(indicator) > 2048 for indicator in cleaned):
            raise ValueError("Each indicator must contain between 1 and 2048 characters")
        return cleaned


class EmailRequest(BaseModel):
    raw_email: str = Field(min_length=1, max_length=10_000_000)


Severity = Literal["low", "medium", "high", "critical"]
AlertStatus = Literal["open", "in_progress", "closed"]


class AlertBase(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    severity: Severity = "medium"
    status: AlertStatus = "open"
    mitre: str | None = Field(default=None, max_length=100)
    source: str | None = Field(default=None, max_length=255)
    notes: str | None = None


class AlertCreate(AlertBase):
    pass


class AlertUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    severity: Severity | None = None
    status: AlertStatus | None = None
    mitre: str | None = Field(default=None, max_length=100)
    source: str | None = Field(default=None, max_length=255)
    notes: str | None = None


class AlertResponse(AlertBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime


class AlertListResponse(BaseModel):
    items: list[AlertResponse]
    total: int
    limit: int
    offset: int

class DetectRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10_000_000)
    content_type: str = "auto"

class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    email: str
    password: str = Field(min_length=8)

    @field_validator("username", "email")
    @classmethod
    def clean_identity(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Value cannot be blank")
        return value


class UserLogin(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str

    @field_validator("username")
    @classmethod
    def clean_username(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Username cannot be blank")
        return value


PlaybookName = Literal["ioc_triage", "phishing_triage", "brute_force_response"]


class PlaybookRequest(BaseModel):
    playbook: PlaybookName
    input: dict[str, str] = Field(default_factory=dict)
