import pytest
from rest_framework.test import APIClient


@pytest.mark.django_db
@pytest.mark.usefixtures("create_test_user")
class TestSignInView:
    @pytest.mark.parametrize(
        "email,password, expected",
        [
            ("koushikmallik001@gmail.com", "1234567", "success"),
            (
                "koushikmallik001@gmail.com",
                "1234567778",
                "UserAuthenticationFailedError: Password is invalid.",
            ),
            (
                "abcdef@googlecom",
                "1234567",
                "UserNotFoundError: This user is not registered. Please register as new user.",
            ),
            (
                "animeshece1998@gmail.com",
                "1234567",
                "UserNotVerifiedError: This user is not verified. Please verify your email first.",
            ),
            ("", "123467", "ValueError: Email or Password is not in correct format"),
            (
                "abcdef@google.com",
                "",
                "ValueError: Email or Password is not in correct format",
            ),
        ],
    )
    def test_sign_in(self, email: str, password: str, expected: str):
        data = {
            "email": email,
            "password": password,
        }

        client = APIClient()
        url = "http://localhost/api/v2/sign-in"
        response = client.post(url, data, format="json")
        assert response
        response = response.json()
        if expected == "success":
            assert response.get("token")
            assert isinstance(response.get("token"), dict)
        else:
            assert response.get("errorMessage")
            assert response.get("errorMessage") == expected
