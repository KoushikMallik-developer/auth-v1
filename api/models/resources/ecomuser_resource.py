from import_export import resources

from api.models.user_models.user import ECOMUser


class ECOMUserResource(resources.ModelResource):
    class Meta:
        model = ECOMUser
