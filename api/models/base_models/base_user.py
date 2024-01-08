from django.db import models

from api.models.base_models.base_model import ECOMBaseModel
from api.models.definitions import ACCOUNT_TYPE_CHOICES


class BaseUser(ECOMBaseModel):
    account_type = models.CharField(
        max_length=10,
        choices=ACCOUNT_TYPE_CHOICES,
        default="Regular",
    )

    class Meta:
        abstract = True
