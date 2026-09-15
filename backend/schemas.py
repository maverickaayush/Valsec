from typing import Literal
from uuid import UUID
from pydantic import BaseModel, SecretStr, Field, field_validator, model_validator
import validators
from input_validation import validate_device_name

def _normalize_email(value: str) -> str:
    value=value.strip().lower()
    if not validators.email(value): raise ValueError('Invalid email address')
    return value

class SignupRequest(BaseModel):
    email: str
    password: str
    @field_validator('email')
    @classmethod
    def validate_email(cls,value): return _normalize_email(value)

class LoginRequest(SignupRequest): pass
class OTPVerifyRequest(BaseModel):
    email: str
    code: str
    @field_validator('email')
    @classmethod
    def validate_email(cls,value): return _normalize_email(value)
class ResendOTPRequest(BaseModel):
    email: str
    @field_validator('email')
    @classmethod
    def validate_email(cls,value): return _normalize_email(value)
class OTPChallengeResponse(BaseModel):
    email: str
    expires_in: int
    resend_in: int
class AuthUserResponse(BaseModel):
    id: UUID
    email: str
    email_verified: bool
    next_step: Literal['verify_email','ready']
    audits_this_month: int=0
    audit_limit: int=0


class DevicePullRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    username: str | None = Field(default=None, min_length=1, max_length=128)
    password: SecretStr | None = None
    vendor: str = Field(min_length=1, max_length=64)
    framework: str
    device_name: str
    use_stored_credential: bool = False
    device_id: UUID | None = None

    @field_validator("host", "vendor")
    @classmethod
    def trim_printable(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(ord(character) < 32 for character in normalized):
            raise ValueError("Value must contain printable characters")
        return normalized

    @field_validator("username")
    @classmethod
    def trim_optional_username(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized or any(ord(character) < 32 for character in normalized):
            raise ValueError("Value must contain printable characters")
        return normalized

    @field_validator("device_name")
    @classmethod
    def device_name_is_valid(cls, value: str) -> str:
        return validate_device_name(value)

    @model_validator(mode="after")
    def validate_credential_source(self):
        if self.use_stored_credential:
            if self.device_id is None:
                raise ValueError("device_id is required when use_stored_credential is true")
        elif self.username is None or self.password is None:
            raise ValueError("username and password are required for a manual pull")
        return self


class SeedDiscoveryRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr
    vendor: str = Field(default="OpenWrt", min_length=1, max_length=64)

    @field_validator("host", "username", "vendor")
    @classmethod
    def trim_seed_value(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(ord(character) < 32 for character in normalized):
            raise ValueError("Value must contain printable characters")
        return normalized


class DiscoveredDevicePullRequest(BaseModel):
    seed: SeedDiscoveryRequest
    address: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr
    transport: Literal["ssh", "telnet"] = "ssh"
    vendor: str = Field(default="auto", min_length=1, max_length=64)
    framework: str
    device_name: str

    @field_validator("address", "username", "vendor")
    @classmethod
    def trim_neighbor_value(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(ord(character) < 32 for character in normalized):
            raise ValueError("Value must contain printable characters")
        return normalized

    @field_validator("device_name")
    @classmethod
    def discovered_device_name_is_valid(cls, value: str) -> str:
        return validate_device_name(value)


class DiscoverySessionRequest(BaseModel):
    seed: SeedDiscoveryRequest
    framework: str = "nist_sp_800_53_rev5"
    max_depth: int = Field(default=1, ge=1, le=10)
    max_devices: int = Field(default=25, ge=1, le=100)
    reuse_seed_credentials: bool = False


class DiscoveryDeviceProcessRequest(BaseModel):
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr
    transport: Literal["ssh", "telnet"] = "ssh"
    vendor: str = Field(min_length=1, max_length=64)
    framework: str = "nist_sp_800_53_rev5"
    device_name: str

    @field_validator("username", "vendor")
    @classmethod
    def trim_process_value(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(ord(character) < 32 for character in normalized):
            raise ValueError("Value must contain printable characters")
        return normalized

    @field_validator("device_name")
    @classmethod
    def process_device_name_is_valid(cls, value: str) -> str:
        return validate_device_name(value)


class RemediationApprovalResponse(BaseModel):
    action_id: UUID
    finding_id: UUID
    status: Literal["approved"]
    risky: bool
    remediation_text: str


class RemediationApplyRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr
    confirm_risky: bool = False

    @field_validator("host", "username")
    @classmethod
    def trim_connection_value(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(ord(character) < 32 for character in normalized):
            raise ValueError("Value must contain printable characters")
        return normalized
