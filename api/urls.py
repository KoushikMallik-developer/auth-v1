from django.urls import path

from api.views.all_users import AllUsersView
from api.views.clear_server_cache import ClearServerCaches
from api.views.user_views.create_user import CreateUsersView
from api.views.common_views.otp_view import SendOTPView
from api.views.common_views.password_reset import PasswordResetView
from api.views.common_views.remove_user import RemoveUserView
from api.views.user_views.sign_in import SignInView
from api.views.common_views.update_password import UpdatePasswordView
from api.views.user_views.update_profile import UpdateProfileView
from api.views.user_views.user_details import UserDetailView
from api.views.common_views.validate_otp_view import ValidateOTPView

urlpatterns = [
    # User Paths
    path("create-users", CreateUsersView.as_view(), name="Create-Users"),
    path("sign-in", SignInView.as_view(), name="user-sign-in"),
    path("update-profile", UpdateProfileView.as_view(), name="Update-User-profile"),
    path("user-details", UserDetailView.as_view(), name="user-details"),
    # General Paths
    path("all-users", AllUsersView.as_view(), name="All-Users"),
    path("remove-user", RemoveUserView.as_view(), name="Remove-User"),
    path("send-otp", SendOTPView.as_view(), name="send-otp"),
    path("verify-otp", ValidateOTPView.as_view(), name="verify-otp"),
    path(
        "reset-password",
        PasswordResetView.as_view(),
        name="send-reset-password-email",
    ),
    path("update-password", UpdatePasswordView.as_view(), name="Change-User-Password"),
    path("clear-caches", ClearServerCaches.as_view(), name="clear-caches"),
]
