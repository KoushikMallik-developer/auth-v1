from typing import Optional
from rest_framework import serializers

from api.models.definitions import ACCOUNT_TYPE_CHOICES
from api.models.user_models.user import ECOMUser
from api.models.export_types.validation_types.validation_result import ValidationResult
from api.services.encryption_services.encryption_service import EncryptionServices
from api.services.helpers import (
    validate_email,
    validate_name,
    validate_username,
    validate_password,
    validate_gstin,
)


class ECOMUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = ECOMUser
        fields = "__all__"

    def validate(self, data: Optional[dict] = None) -> Optional[bool]:
        is_validated_email = False
        is_validated_name = False
        is_validated_username = False
        is_validated_password = False

        gstin = data.get("gstin")
        account_type = data.get("account_type")
        email = data.get("email")
        fname = data.get("fname")
        lname = data.get("lname")
        username = data.get("username")
        password1 = data.get("password1")
        password2 = data.get("password2")

        # Email Validation
        if email and isinstance(email, str):
            validation_result_email: ValidationResult = validate_email(email)
            is_validated_email = validation_result_email.is_validated
            if not is_validated_email:
                raise serializers.ValidationError(detail=validation_result_email.error)

        # Name and Username Validation
        if (
            fname
            and lname
            and username
            and isinstance(fname, str)
            and isinstance(lname, str)
            and isinstance(username, str)
        ):
            validation_result_name: ValidationResult = validate_name(fname + lname)
            is_validated_name = validation_result_name.is_validated
            if not is_validated_name:
                raise serializers.ValidationError(detail=validation_result_name.error)
            validation_result_username: ValidationResult = validate_username(username)
            is_validated_username = validation_result_username.is_validated
            if not is_validated_username:
                raise serializers.ValidationError(validation_result_username.error)
        # Password Validation
        if (
            password1
            and password2
            and isinstance(password1, str)
            and isinstance(password2, str)
        ):
            validation_result_password: ValidationResult = validate_password(
                password1, password2
            )
            is_validated_password = validation_result_password.is_validated
            if not is_validated_password:
                raise serializers.ValidationError(validation_result_password.error)

        # Account Type Validation
        if account_type and isinstance(account_type, str):
            if account_type == "Seller":
                if gstin and isinstance(gstin, str):
                    validation_result_gstin: ValidationResult = validate_gstin(gstin)
                    is_validated_gstin = validation_result_gstin.is_validated
                    is_validated_account_type = is_validated_gstin
                    if not is_validated_gstin:
                        raise serializers.ValidationError(validation_result_gstin.error)
                else:
                    raise serializers.ValidationError(
                        "GSTIN Number is needed for Seller type account."
                    )
            elif account_type in ACCOUNT_TYPE_CHOICES:
                is_validated_account_type = True
                is_validated_gstin = True
            else:
                raise serializers.ValidationError(
                    "AccountType entered is not supported."
                )
        else:
            is_validated_account_type = True
            is_validated_gstin = True

        if (
            is_validated_email
            and is_validated_password
            and is_validated_username
            and is_validated_name
            and is_validated_gstin
            and is_validated_account_type
        ):
            return True

    def create(self, data: dict) -> ECOMUser:
        email = data.get("email")
        fname = data.get("fname")
        lname = data.get("lname")
        username = data.get("username")
        password1 = data.get("password1")
        account_type = data.get("account_type")
        if self.validate(data):
            if account_type:
                user = ECOMUser(
                    email=email,
                    username=username,
                    fname=fname,
                    lname=lname,
                    password=EncryptionServices().encrypt(password1),
                    account_type=account_type,
                )
            else:
                user = ECOMUser(
                    email=email,
                    username=username,
                    fname=fname,
                    lname=lname,
                    password=EncryptionServices().encrypt(password1),
                )
            user.save()
            return user
