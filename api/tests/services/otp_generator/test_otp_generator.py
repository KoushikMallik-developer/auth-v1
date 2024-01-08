from api.services.otp_services.otp_generator import OTPGenerator


class TestOTPGenerator:
    def test_generate_otp(self):
        generator = OTPGenerator()
        otp = generator.generate_otp()
        assert otp
        assert len(otp) == 6
        assert otp.isdigit()
