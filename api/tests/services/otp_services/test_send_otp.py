import pytest

from api.services.otp_services.otp_services import OTPServices


@pytest.mark.django_db
@pytest.mark.usefixtures("create_test_user")
class TestSendOTP:
    def test_send_otp(self):
        otp_services = OTPServices()
        response = otp_services.send_otp_to_user(
            user_email="koushikmallik001@gmail.com"
        )
        assert response
        assert response == "OK"
