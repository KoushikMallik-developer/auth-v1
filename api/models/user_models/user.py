from api.auth_exceptions.user_exceptions import (
    UserNotFoundError,
    UserNotVerifiedError,
    UserAuthenticationFailedError,
)
from api.models.request_data_types.sign_in import SignInRequestType
from api.models.user_models.abstract_user import AbstractUser
from api.models.export_types.export_user import ExportECOMUser
from api.services.encryption_services.encryption_service import EncryptionServices
from api.services.token_services.token_generator import TokenGenerator


class ECOMUser(AbstractUser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

    @staticmethod
    def authenticate_user(request_data: SignInRequestType) -> dict:
        if (
            request_data.email
            and request_data.password
            and len(request_data.password) >= 6
        ):
            user_exists = (
                True
                if ECOMUser.objects.filter(email=request_data.email).count() > 0
                else False
            )
            if user_exists:
                user = ECOMUser.objects.get(email=request_data.email)
                if user and user.get_is_regular:
                    if (
                        EncryptionServices().decrypt(user.password)
                        == request_data.password
                    ):
                        if user.is_active:
                            token = TokenGenerator().get_tokens_for_user(
                                ExportECOMUser(**user.model_to_dict())
                            )
                            return {
                                "token": token,
                                "errorMessage": None,
                            }
                        else:
                            raise UserNotVerifiedError()
                    else:
                        raise UserAuthenticationFailedError()
                else:
                    raise UserNotFoundError()
            else:
                raise UserNotFoundError()
        else:
            raise ValueError("Email or password is invalid.")

    @staticmethod
    def authenticate_seller(request_data: SignInRequestType) -> dict:
        if request_data.email and request_data.password:
            user_exists = (
                True
                if ECOMUser.objects.filter(email=request_data.email).count() > 0
                else False
            )
            if user_exists:
                user = ECOMUser.objects.get(email=request_data.email)
                if user and user.get_is_seller:
                    if user.is_active:
                        if (
                            EncryptionServices().decrypt(user.password)
                            == request_data.password
                        ):
                            token = TokenGenerator().get_tokens_for_user(
                                ExportECOMUser(**user.model_to_dict())
                            )
                            return {
                                "token": token,
                                "errorMessage": None,
                            }
                        else:
                            raise UserAuthenticationFailedError()
                    else:
                        raise UserNotVerifiedError()
                else:
                    raise UserNotFoundError()
            else:
                raise UserNotFoundError()
        else:
            raise ValueError("Email and password are not in correct format.")
