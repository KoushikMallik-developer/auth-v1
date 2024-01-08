import logging

from psycopg2 import DatabaseError
from pydantic import ValidationError
from rest_framework import status
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from drf_yasg import openapi
from drf_yasg.openapi import Schema
from drf_yasg.utils import swagger_auto_schema


from api.models.export_types.export_user import ExportECOMUserList
from api.services.user_services.user_services import UserServices


class AllUsersView(APIView):
    renderer_classes = [JSONRenderer]

    @swagger_auto_schema(
        operation_summary="Get All Users",
        operation_description="Get All Users",
        responses={
            200: Schema(
                title="Get All-Users Response",
                type=openapi.TYPE_OBJECT,
                properties={
                    "data": Schema(
                        name="data",
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
                title="Get All-Users Response",
                type=openapi.TYPE_OBJECT,
                properties={
                    "successMessage": Schema(
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
        },
    )
    def get(self, _):
        try:
            all_user_details = UserServices.get_all_users_service()
            if all_user_details and isinstance(all_user_details, ExportECOMUserList):
                return Response(
                    data={"data": all_user_details.model_dump(), "errorMessage": None},
                    status=status.HTTP_200_OK,
                    content_type="application/json",
                )
            else:
                logging.warning("No User found in database.")
                raise Exception("No User found in database.")
        except DatabaseError as e:
            logging.error(
                f"DatabaseError: Error Occured While Fetching all users details: {e}"
            )
            return Response(
                data={
                    "successMessage": None,
                    "errorMessage": f"DatabaseError: Error Occured While Fetching all users details: {e}",
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
            logging.error(f"InternalServerError: {e}")
            return Response(
                data={
                    "successMessage": None,
                    "errorMessage": f"InternalServerError {e}",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content_type="application/json",
            )
