import logging

from pydantic import ValidationError
from rest_framework import status
from rest_framework.renderers import JSONRenderer
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from drf_yasg import openapi
from drf_yasg.openapi import Schema
from drf_yasg.utils import swagger_auto_schema

from api.auth_exceptions.user_exceptions import (
    UserNotFoundError,
    UserAlreadyVerifiedError,
    OTPNotVerifiedError,
    EmailNotSentError,
)
from api.models.request_data_types.verify_otp import VerifyOTPRequestType
from api.services.user_services.user_services import UserServices


class ValidateOTPView(APIView):
    renderer_classes = [JSONRenderer]

    @swagger_auto_schema(
        operation_summary="Verify OTP",
        operation_description="Verify OTP",
        request_body=Schema(
            title="Verify-OTP Request",
            type=openapi.TYPE_OBJECT,
            properties={
                "email": Schema(
                    name="email",
                    in_=openapi.IN_BODY,
                    type=openapi.TYPE_STRING,
                    format=openapi.FORMAT_EMAIL,
                ),
                "otp": Schema(
                    name="otp",
                    in_=openapi.IN_BODY,
                    type=openapi.TYPE_STRING,
                ),
            },
        ),
        responses={
            200: Schema(
                title="Verify-OTP Response",
                type=openapi.TYPE_OBJECT,
                properties={
                    "successMessage": Schema(
                        name="successMessage",
                        in_=openapi.IN_BODY,
                        type=openapi.TYPE_STRING,
                    ),
                    "errorMessage": Schema(
                        name="errorMessage",
                        in_=openapi.IN_BODY,
                        type=openapi.TYPE_STRING,
                    ),
                },
            ),
            201: None,
            "default": Schema(
                title="Verify-OTP Response",
                type=openapi.TYPE_OBJECT,
                properties={
                    "successMessage": Schema(
                        name="successMessage",
                        in_=openapi.IN_BODY,
                        type=openapi.TYPE_STRING,
                    ),
                    "errorMessage": Schema(
                        name="errorMessage",
                        in_=openapi.IN_BODY,
                        type=openapi.TYPE_STRING,
                    ),
                },
            ),
        },
    )
    def post(self, request: Request):
        try:
            token = UserServices().verify_user_with_otp(
                request_data=VerifyOTPRequestType(**request.data)
            )
            return Response(
                data={
                    "token": token,
                    "errorMessage": None,
                },
                status=status.HTTP_200_OK,
                content_type="application/json",
            )
        except EmailNotSentError as e:
            return Response(
                data={
                    "successMessage": None,
                    "errorMessage": f"EmailNotSentError: {e.msg}",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content_type="application/json",
            )
        except UserAlreadyVerifiedError as e:
            return Response(
                data={
                    "successMessage": None,
                    "errorMessage": f"UserAlreadyVerifiedError: {e.msg}",
                },
                status=status.HTTP_403_FORBIDDEN,
                content_type="application/json",
            )
        except UserNotFoundError as e:
            return Response(
                data={
                    "successMessage": None,
                    "errorMessage": f"UserNotFoundError: {e.msg}",
                },
                status=status.HTTP_401_UNAUTHORIZED,
                content_type="application/json",
            )
        except ValidationError as e:
            logging.error(
                f"PydanticValidationError: Error Occured while converting to Pydantic object: {e}"
            )
            return Response(
                data={
                    "data": None,
                    "errorMessage": f"PydanticValidationError: Error Occured while converting to Pydantic object: {e}",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content_type="application/json",
            )
        except ValueError as e:
            logging.error(f"ValueError: {e}")
            return Response(
                data={"successMessage": None, "errorMessage": f"ValueError: {e}"},
                status=status.HTTP_400_BAD_REQUEST,
                content_type="application/json",
            )
        except NotImplementedError as e:
            logging.warning(f"NotImplementedError: {e}")
            return Response(
                data={
                    "successMessage": None,
                    "errorMessage": f"NotImplementedError: {e}",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content_type="application/json",
            )
        except OTPNotVerifiedError as e:
            logging.warning(f"OTPNotVerifiedError: {e.msg}")
            return Response(
                data={
                    "successMessage": None,
                    "errorMessage": f"OTPNotVerifiedError: {e.msg}",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content_type="application/json",
            )
        except Exception as e:
            logging.warning(f"InternalServerError: {e}")
            return Response(
                data={
                    "successMessage": None,
                    "errorMessage": f"InternalServerError: {e}",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content_type="application/json",
            )
