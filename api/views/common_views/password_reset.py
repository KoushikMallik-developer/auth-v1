import logging

from psycopg2 import DatabaseError
from drf_yasg import openapi
from drf_yasg.openapi import Schema
from drf_yasg.utils import swagger_auto_schema
from pydantic import ValidationError
from rest_framework.renderers import JSONRenderer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, serializers


from api.auth_exceptions.user_exceptions import (
    EmailNotSentError,
    UserNotFoundError,
    UserAuthenticationFailedError,
    UserNotVerifiedError,
)
from api.services.user_services.user_services import UserServices


class PasswordResetView(APIView):
    renderer_classes = [JSONRenderer]

    @swagger_auto_schema(
        operation_summary="Reset User Password",
        operation_description="Reset User Password",
        request_body=Schema(
            title="Reset-Password Request",
            type=openapi.TYPE_OBJECT,
            properties={
                "email": Schema(
                    name="email",
                    in_=openapi.IN_BODY,
                    type=openapi.TYPE_STRING,
                    format=openapi.FORMAT_EMAIL,
                ),
            },
        ),
        responses={
            200: Schema(
                title="Reset-Password Response",
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
            "default": Schema(
                title="Reset-Password Response",
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
    def post(self, request):
        try:
            email = request.data.get("email")
            if email:
                result = UserServices().reset_password(email=email)
                return Response(
                    data={
                        "successMessage": result.get("successMessage"),
                        "errorMessage": None,
                    },
                    status=status.HTTP_200_OK,
                    content_type="application/json",
                )
            else:
                raise ValueError("Email format is not correct.")
        except DatabaseError as e:
            logging.error(
                f"DatabaseError: Error Occured While fetching user details: {e}"
            )
            return Response(
                data={
                    "successMessage": None,
                    "errorMessage": f"DatabaseError: Error Occured While fetching user details: {e}",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content_type="application/json",
            )
        except ValidationError as e:
            logging.error(
                f"PydanticValidationError: Error Occured while converting to Pydantic object: {e}"
            )
            return Response(
                data={
                    "successMessage": None,
                    "errorMessage": f"PydanticValidationError: Error Occured while converting to Pydantic object: {e}",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
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
        except UserAuthenticationFailedError as e:
            return Response(
                data={
                    "successMessage": None,
                    "errorMessage": f"UserAuthenticationFailedError: {e.msg}",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
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
        except UserNotVerifiedError as e:
            return Response(
                data={
                    "successMessage": None,
                    "errorMessage": f"UserNotVerifiedError: {e.msg}",
                },
                status=status.HTTP_401_UNAUTHORIZED,
                content_type="application/json",
            )
        except serializers.ValidationError as e:
            logging.warning(f"SerializerValidationError: {e.detail}")
            return Response(
                data={
                    "successMessage": None,
                    "errorMessage": f"SerializerValidationError: {'; '.join([error for error in e.detail])}",
                },
                status=status.HTTP_400_BAD_REQUEST,
                content_type="application/json",
            )
        except ValueError as e:
            logging.warning(f"ValueError: {e}")
            return Response(
                data={"successMessage": None, "errorMessage": f"ValueError: {e}"},
                status=status.HTTP_400_BAD_REQUEST,
                content_type="application/json",
            )
        except NotImplementedError as e:
            logging.warning(f"Internal Server Error: {e}")
            return Response(
                data={
                    "successMessage": None,
                    "errorMessage": f"NotImplementedError: {e}",
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
                status=status.HTTP_400_BAD_REQUEST,
                content_type="application/json",
            )
