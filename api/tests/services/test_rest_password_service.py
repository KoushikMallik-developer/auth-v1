import pytest

from api.auth_exceptions.user_exceptions import UserNotFoundError
from api.services.user_services import UserServices


@pytest.mark.django_db
@pytest.mark.usefixtures("create_test_user")
class TestSendOTP:
    @pytest.mark.parametrize(
        "email, response_message",
        [
            ("koushikmallik001@gmail.com", "Password reset link sent successfully."),
        ],
    )
    def test_reset_password(self, email: str, response_message: str):
        user_services = UserServices()
        response = user_services.reset_password(email=email)
        assert response
        assert response.get("successMessage") == response_message

    @pytest.mark.parametrize(
        "email",
        [
            "hcvhvcntgcchfe6767gv@gmail.com",
            "",
        ],
    )
    def test_reset_password_negative(self, email: str):
        user_services = UserServices()
        with pytest.raises(UserNotFoundError):
            response = user_services.reset_password(email=email)
            assert response
