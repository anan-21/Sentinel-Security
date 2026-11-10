from typing import Literal
from pydantic import BaseModel, Field
class Finding(BaseModel):
    type: str
    reason: str
    field: str
    evidence: str
    start: int
    end: int
    severity: Literal['MEDIUM','HIGH','CRITICAL'] = 'MEDIUM'
class Report(BaseModel):
    version: str = '0.1.0'
    risk_level: Literal['LOW','MEDIUM','HIGH','CRITICAL']
    risk_types: list[str]
    findings: list[Finding]
    recommendations: list[str]
    uncertainty: list[str]
