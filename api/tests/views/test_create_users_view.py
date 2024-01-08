import pytest
from rest_framework import serializers
from rest_framework.test import APIClient

from api.serializers.ecom_user_serializer import ECOMUserSerializer


@pytest.mark.django_db
class TestCreateUsersView:
    def test_create_user(self):
        data = {
            "username": "koushikmallik",
            "email": "abcdef@googls.com",
            "fname": "Koushik",
            "lname": "Google",
            "password1": "1234567",
            "password2": "1234567",
        }

        client = APIClient()
        url = "http://localhost/api/v2/create-users"
        response = client.post(url, data, format="json")
        assert response
        response = response.json()
        if response.get("errorMessage"):
            assert isinstance(response.get("errorMessage"), str)
        else:
            assert response.get("successMessage")
            assert isinstance(response.get("successMessage"), str)

    @pytest.mark.parametrize(
        "username,email,fname,lname,password1,password2",
        [
            (
                "koushikmallik",
                "abcdef@google.com",
                "Koushik123",
                "Google",
                "1234567",
                "1234567",
            ),
            (
                "koushikmallik",
                "abcdefgooglecom",
                "Koushik",
                "Google",
                "1234567",
                "1234567",
            ),
            (
                "koushikmallik",
                "abcdef@google.com",
                "Koushik",
                "Google123",
                "1234567",
                "1234567",
            ),
            ("koushikmallik", "abcdef@google.com", "Koushik", "Google", "1234", "1234"),
            (
                "koushikmallik",
                "abcdef@google.com",
                "Koushik",
                "Google",
                "123456",
                "123467",
            ),
            ("kou", "abcdef@google.com", "Koushik", "Google", "123456", "123456"),
        ],
    )
    def test_create_user_negative(
        self,
        username: str,
        email: str,
        fname: str,
        lname: str,
        password1: str,
        password2: str,
    ):
        data = {
            "username": username,
            "email": email,
            "fname": fname,
            "lname": lname,
            "password1": password1,
            "password2": password2,
        }
        with pytest.raises(serializers.ValidationError):
            serializer = ECOMUserSerializer()
            serializer.create(data)
