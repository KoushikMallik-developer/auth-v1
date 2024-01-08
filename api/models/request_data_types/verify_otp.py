from typing import Optional

from pydantic import BaseModel


class VerifyOTPRequestType(BaseModel):
    email: Optional[str]
    otp: Optional[str]
