# schemas.py (nuevo archivo)
from pydantic import BaseModel, Field, validator
from typing import Optional
import re

class AgentRegister(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    hostname: str = Field(..., max_length=255)
    ip: str
    hash: Optional[str] = None

    @validator('ip')
    def validate_ip(cls, v):
        # Validar formato IP
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, v):
            raise ValueError('Invalid IP address')
        return v

class Command(BaseModel):
    action: str = Field(..., pattern="^(start|stop|configure)$")
    module: str = Field(..., min_length=1)
    config: Optional[dict] = None

    @validator('config', always=True)
    def validate_config(cls, v, values):
        if values.get('action') == 'configure' and v is None:
            raise ValueError('Config required for configure action')
        return v