import logging
from typing import Optional

from api.auth_exceptions.base_exception import AUTHBaseException


class UserNotFoundError(AUTHBaseException):
    def __init__(self, msg: Optional[str] = None):
        if not msg:
            self.msg = "This user is not registered. Please register as new user."
        else:
            super().__init__(msg)
        logging.error(self.msg)


class UserAlreadyVerifiedError(AUTHBaseException):
    def __init__(self, msg: Optional[str] = None):
        if not msg:
            self.msg = "This user is already verified."
        else:
            super().__init__(msg)
        logging.error(self.msg)


class UserNotVerifiedError(AUTHBaseException):
    def __init__(self, msg: Optional[str] = None):
        if not msg:
            self.msg = "This user is not verified. Please verify your email first."
        else:
            super().__init__(msg)
        logging.error(self.msg)


class EmailNotSentError(AUTHBaseException):
    def __init__(self, msg: Optional[str] = None):
        if not msg:
            self.msg = "Verification Email could not be sent."
        else:
            super().__init__(msg)
        logging.error(self.msg)


class OTPNotVerifiedError(AUTHBaseException):
    def __init__(self, msg: Optional[str] = None):
        if not msg:
            self.msg = "OTP did not match."
        else:
            super().__init__(msg)
        logging.error(self.msg)


class UserAuthenticationFailedError(AUTHBaseException):
    def __init__(self, msg: Optional[str] = None):
        if not msg:
            self.msg = "Password is invalid."
        else:
            super().__init__(msg)
        logging.error(self.msg)
