from django.db import models

from api.models.base_models.base_user import BaseUser


class AbstractUser(BaseUser):
    username = models.CharField(max_length=25)
    email = models.EmailField(
        verbose_name="Email", max_length=255, unique=True, null=False
    )
    fname = models.CharField(max_length=255, null=False)
    lname = models.CharField(max_length=255, null=False)
    password = models.CharField(max_length=255, null=False)
    dob = models.DateField(null=True)
    phone = models.CharField(max_length=15, null=True)
    image = models.CharField(max_length=2555, null=True)
    is_active = models.BooleanField(default=False)

    class Meta:
        abstract = True

    def __str__(self):
        return self.email

    @property
    def get_is_admin(self):
        if self.account_type == "Admin":
            return True
        else:
            return False

    @property
    def get_is_seller(self):
        if self.account_type == "Seller":
            return True
        else:
            return False

    @property
    def get_is_regular(self):
        if self.account_type == "Regular":
            return True
        else:
            return False

    @property
    def get_phone(self):
        """Fetch registered Phone Number of the user"""
        if self.phone:
            return self.phone

    @property
    def get_full_name(self):
        """Fethch registered Phone Number of the user"""
        if self.fname and self.lname:
            return f"{self.fname} {self.lname}"
        else:
            return None

    @property
    def get_is_active(self):
        return self.is_active

    @property
    def get_username(self):
        if self.username:
            return self.username

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
