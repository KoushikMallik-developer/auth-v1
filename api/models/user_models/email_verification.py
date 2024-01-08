from django.db import models
from django.utils import timezone

from api.models.base_models.base_model import ECOMBaseModel
from api.models.user_models.user import ECOMUser


class ECOMEmailVerification(ECOMBaseModel):
    user = models.ForeignKey(ECOMUser, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    expiration_time = models.DateTimeField()

    def save(self, *args, **kwargs):
        self.expiration_time = timezone.now() + timezone.timedelta(minutes=15)
        super().save(*args, **kwargs)
