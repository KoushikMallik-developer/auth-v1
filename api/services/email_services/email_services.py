from django.core.mail import EmailMessage
from api.models.export_types.email_types.ecom_email import ECOMEmailMessage


class EmailServices:
    @staticmethod
    def send_password_reset_email_by_user_email(user_email: str, reset_url: str) -> str:
        email: ECOMEmailMessage = (
            ECOMEmailMessage.create_password_reset_email_by_user_email(
                user_email=user_email, reset_url=reset_url
            )
        )
        email_message: EmailMessage = EmailMessage(**email.model_dump())
        email_message.content_subtype = "html"
        email_message.send()
        return "OK"

    @staticmethod
    def send_otp_email_by_user_email(user_email: str, otp: str) -> str:
        email: ECOMEmailMessage = ECOMEmailMessage.create_otp_html_email_by_user_email(
            user_email=user_email, otp=otp
        )
        email_message: EmailMessage = EmailMessage(**email.model_dump())
        email_message.content_subtype = "html"
        email_message.send()
        return "OK"
