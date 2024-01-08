from django.contrib import admin
from import_export.admin import ImportExportModelAdmin

from api.models.resources.ecomuser_resource import ECOMUserResource
from api.models.user_models.email_verification import ECOMEmailVerification
from api.models.user_models.user import ECOMUser


class ECOMUsers(ImportExportModelAdmin):
    resource_class = ECOMUserResource


admin.site.register(ECOMUser, ECOMUsers)
admin.site.register(ECOMEmailVerification)
