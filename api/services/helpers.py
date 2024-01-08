import os
import re
from datetime import datetime

import dns
from dotenv import load_dotenv
from rest_framework_simplejwt.tokens import AccessToken

from api.models.user_models.user import ECOMUser
from api.models.export_types.validation_types.validation_result import ValidationResult
from api.services.definitions import EnvironmentSettings
from dateutil.parser import parse


def validate_email(email: str) -> ValidationResult:
    if validate_email_format(email):
        existing_account = (
            True if ECOMUser.objects.filter(email=email).count() > 0 else False
        )
        if existing_account:
            return ValidationResult(
                is_validated=False,
                error="An account with this email id is already existed.",
            )
        return ValidationResult(is_validated=True, error=None)
    else:
        return ValidationResult(is_validated=False, error="Email format is not correct")


def validate_user_email(email: str) -> ValidationResult:
    if validate_email_format(email):
        existing_account = (
            True if ECOMUser.objects.filter(email=email).count() > 0 else False
        )
        if existing_account:
            return ValidationResult(
                is_validated=True,
                error=None,
            )
        return ValidationResult(is_validated=False, error="User does not exists.")
    else:
        return ValidationResult(is_validated=False, error="Email format is not correct")


def validate_user_uid(uid: str) -> ValidationResult:
    existing_account = True if ECOMUser.objects.filter(id=uid).count() > 0 else False
    if existing_account:
        return ValidationResult(
            is_validated=True,
            error=None,
        )
    return ValidationResult(is_validated=False, error="User does not exists.")


def validate_email_format(email: str) -> bool:
    regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
    if re.fullmatch(regex, email):
        if get_environment() != "DEV":
            domain = email.split("@")[1]
            result = dns.resolver.resolve(domain, "MX")
            if result:
                return True
            return False
        else:
            return True
    else:
        return False


def validate_name(name: str) -> ValidationResult:
    if name.lower().isalpha():
        return ValidationResult(is_validated=True, error=None)
    else:
        return ValidationResult(
            is_validated=False, error="First name or Last name can only have alphabets"
        )


def validate_username(username: str) -> ValidationResult:
    """Checks if the received username matches the required conditions."""
    # Usernames can't be shorter than minlen
    if len(username) < 6:
        return ValidationResult(
            is_validated=False, error="Usernames can't be shorter than 6 characters"
        )
    # Usernames can only use letters, numbers, dots and underscores
    if not re.match("^[a-z0-9._]*$", username):
        return ValidationResult(
            is_validated=False,
            error="Usernames can only use letters, numbers, dots and underscores",
        )
    # Usernames can't begin with a number
    if username[0].isnumeric():
        return ValidationResult(
            is_validated=False, error="Usernames can't begin with a number"
        )
    return ValidationResult(is_validated=True, error=None)


def validate_password(password1: str, password2: str) -> ValidationResult:
    if password1 == password2:
        if len(password1) >= 6:
            return ValidationResult(is_validated=True, error=None)
        return ValidationResult(
            is_validated=False, error="Password must be minimum of 6 characters"
        )
    else:
        return ValidationResult(is_validated=False, error="Passwords did not match")


def decode_jwt_token(request) -> str:
    token = request.headers.get("Authorization", "").split(" ")[1]
    token = AccessToken(token)
    payload = token.payload
    user_id = payload.get("user_id")
    return user_id


def get_environment() -> str:
    load_dotenv()
    env = os.environ.get("ENVIRONMENT_SETTINGS")
    return EnvironmentSettings[env].value


def string_to_datetime(date_str: str) -> datetime:
    return parse(date_str)


def validate_dob(dob: datetime) -> ValidationResult:
    if calculate_age(dob) > 13:
        return ValidationResult(is_validated=True, error=None)
    return ValidationResult(
        is_validated=False, error="Your age cannot be less than 13 years."
    )


def calculate_age(dob: datetime) -> int:
    try:
        today = datetime.today()
        age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        return age
    except Exception as e:
        print(f"Error parsing date: {e}")
        return None


def validate_phone(phone: str) -> ValidationResult:
    pattern = re.compile(r"^\+?[0-9]+\s?[0-9]*$")
    if pattern.match(phone):
        return ValidationResult(is_validated=True, error=None)
    else:
        return ValidationResult(
            is_validated=False, error="Phone number is not in valid format."
        )


def validate_pin(pincode: str) -> ValidationResult:
    if re.match(r"^\d{6}$", pincode):
        first_digit = int(pincode[0])
        if 1 <= first_digit <= 9:
            return ValidationResult(is_validated=True, error=None)
        else:
            return ValidationResult(
                is_validated=False,
                error="Invalid PIN code. The first digit should be between 1 and 9.",
            )
    else:
        print("Invalid PIN code. It should be a 6-digit number.")
        return ValidationResult(
            is_validated=False, error="Invalid PIN code. It should be a 6-digit number."
        )


def validate_gstin(gstin: str) -> ValidationResult:
    if gstin.isalnum() and len(gstin) == 15:
        return ValidationResult(is_validated=True, error=None)
    else:
        return ValidationResult(
            is_validated=False,
            error="Invalid GSTIN Number. It should be a 15 digit number.",
        )
