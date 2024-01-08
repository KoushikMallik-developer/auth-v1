from __future__ import annotations

import pytest

from api.models.export_types.export_user import ExportECOMUser
from api.services.email_services import EmailServices
from api.services.otp_services.otp_generator import OTPGenerator


@pytest.mark.django_db
@pytest.mark.usefixtures("create_test_user")
class TestEmailServices:
    @pytest.mark.parametrize(
        "user_email, expected",
        [
            ("koushikmallik001@gmail.com", "OK"),
            ("animeshece1998@gmail.com", "OK"),
        ],
    )
    def test_send_email_to_user_email(self, user_email: str, expected: str):
        email_service = EmailServices()
        generator = OTPGenerator()
        otp = generator.generate_otp()
        assert otp
        assert len(otp) == 6
        assert otp.isdigit()

        response = email_service.send_otp_email_by_user_email(
            user_email=user_email, otp=otp
        )
        assert response
        assert isinstance(response, str)
        assert response == expected

    def test_send_email_to_user_email_negative(self):
        user_email = "abc2323d@gmail.com"
        email_service = EmailServices()
        generator = OTPGenerator()
        otp = generator.generate_otp()
        assert otp
        assert len(otp) == 6
        assert otp.isdigit()
        with pytest.raises(ValueError):
            response = email_service.send_otp_email_by_user_email(
                user_email=user_email, otp=otp
            )
            assert response

    @pytest.mark.parametrize(
        "user_data, expected",
        [
            (
                {
                    "id": "a367c557-8950-4f16-93de-177c5b59775e",
                    "username": "koushikmallik",
                    "email": "abcdef@googls.com",
                    "fname": "Koushik",
                    "lname": "Google",
                    "dob": None,
                    "phone": None,
                    "image": "/images/users/defaultUserImage.png",
                    "is_active": False,
                    "account_type": "Regular",
                },
                "OK",
            ),
        ],
    )
    def test_send_email_to_user(self, user_data: str, expected: str):
        email_service = EmailServices()
        generator = OTPGenerator()

        assert user_data
        assert isinstance(user_data, dict)
        user = ExportECOMUser(**user_data)
        assert user
        assert user.email
        assert isinstance(user.email, str)

        otp = generator.generate_otp()
        assert otp
        assert len(otp) == 6
        assert otp.isdigit()

        response = email_service.send_otp_email_by_user(user=user, otp=otp)
        assert response
        assert isinstance(response, str)
        assert response == expected
