import re
from typing import Literal
from pydantic import BaseModel, field_validator


# A text rule may overlap a URL rule. Apply the same evidence policy to all findings.
_PRIVATE_FRAGMENT = re.compile(
    r"https?://|\bbearer\s+[A-Za-z0-9._~+/=-]+|"
    r"(?:api[_-]?key|access[_-]?token|token|password|passwd|secret|otp|验证码|密码)\s*[:=：]|"
    r"-----BEGIN [^-]{0,32}PRIVATE KEY-----",
    re.I,
)


class Finding(BaseModel):
    type: str
    reason: str
    field: str
    evidence: str
    start: int
    end: int
    severity: Literal["MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"

    @field_validator("evidence")
    @classmethod
    def minimize_evidence(cls, value):
        if len(value) > 256 or _PRIVATE_FRAGMENT.search(value):
            return "[片段已隐藏，请按位置查看原文]"
        return value


class Report(BaseModel):
    version: str = "0.2.0"
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    risk_types: list[str]
    findings: list[Finding]
    recommendations: list[str]
    uncertainty: list[str]
