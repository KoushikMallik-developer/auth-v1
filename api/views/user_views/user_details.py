import logging

from psycopg2 import DatabaseError
from drf_yasg import openapi
from drf_yasg.openapi import Schema
from drf_yasg.utils import swagger_auto_schema
from pydantic import ValidationError
from rest_framework import serializers, status
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError

from api.auth_exceptions.user_exceptions import (
    EmailNotSentError,
    UserAuthenticationFailedError,
    UserNotFoundError,
    UserNotVerifiedError,
)
from api.services.helpers import decode_jwt_token, validate_user_uid
from api.services.user_services.user_services import UserServices
from api.views.helpers import is_regular_account


class UserDetailView(APIView):
    renderer_classes = [JSONRenderer]

    @swagger_auto_schema(
        operation_summary="Get User Details",
        operation_description="Get User Details",
        responses={
            200: Schema(
                title="Get-User-Details Response",
                type=openapi.TYPE_OBJECT,
                properties={
                    "successMessage": Schema(
                        name="successMessage",
                        in_=openapi.IN_BODY,
                        type=openapi.TYPE_STRING,
                    ),
                    "data": Schema(
                        name="successMessage",
                        in_=openapi.IN_BODY,
                        type=openapi.TYPE_OBJECT,
                    ),
                    "errorMessage": Schema(
                        name="errorMessage",
                        in_=openapi.IN_BODY,
                        type=openapi.TYPE_STRING,
                    ),
                },
            ),
            "default": Schema(
                title="Get-User-Details Response",
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
    def get(self, request):
        try:
            user_id = decode_jwt_token(request=request)
            if validate_user_uid(uid=user_id).is_validated:
                if is_regular_account(uid=user_id):
                    user_details = UserServices().get_user_details(uid=user_id)
                    return Response(
                        data={
                            "successMessage": "User details fetched successfully.",
                            "data": user_details.model_dump(),
                            "errorMessage": None,
                        },
                        status=status.HTTP_200_OK,
                        content_type="application/json",
                    )
                else:
                    raise UserNotFoundError()
            else:
                raise TokenError()
        except TokenError as e:
            logging.error(f"TokenError: {str(e)}")
            return Response(
                data={
                    "successMessage": None,
                    "errorMessage": f"TokenError: {str(e)}",
                },
                status=status.HTTP_401_UNAUTHORIZED,
                content_type="application/json",
            )
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
