import pytest
from rest_framework.test import APIClient


@pytest.mark.django_db
@pytest.mark.usefixtures("create_test_user")
class TestPasswordResetView:
    @pytest.mark.parametrize(
        "email, response_message",
        [
            ("koushikmallik001@gmail.com", "Password reset link sent successfully."),
        ],
    )
    def test_reset_password_view(self, email: str, response_message: str):
        data = {"email": email}

        client = APIClient()
        url = "http://localhost/api/v2/reset-password"
        response = client.post(url, data, format="json")
        assert response
        response = response.json()
        assert response.get("successMessage") == response_message
