import random
import string
from typing import Optional

from api.services.helpers import get_environment


class OTPGenerator:
    def __init__(self):
        self.length: int = 6

    def generate_otp(self, length: Optional[int] = None) -> str:
        if get_environment() in ["STAGING", "DEV"]:
            return "555555"
        if length:
            self.length = length
        digits = string.digits
        otp = "".join(random.choice(digits) for _ in range(self.length))
        return otp
