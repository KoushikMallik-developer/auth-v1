from django.db import models

from api.models.base_models.base_model import ECOMBaseModel


class ECOMBaseAddress(ECOMBaseModel):
    address_line1 = models.CharField(max_length=255)
    address_line2 = models.CharField(max_length=255)
    state = models.CharField(max_length=255)
    city = models.CharField(max_length=255)
    pin = models.CharField(max_length=255)
    country = models.CharField(max_length=255)
    landmark = models.CharField(max_length=255)

    class Meta:
        abstract = True
