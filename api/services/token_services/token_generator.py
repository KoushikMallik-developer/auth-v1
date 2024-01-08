from django.core.cache import cache
from rest_framework_simplejwt.tokens import RefreshToken

from api.models.export_types.export_user import ExportECOMUser


class TokenGenerator:
    expiration_time = 24 * 60 * 60

    def get_tokens_for_user(self, user: ExportECOMUser) -> dict:
        cache_keyword = f"Split-It_User_{user.id}"
        if cache.get(cache_keyword):
            cached_data = cache.get(cache_keyword)
            return cached_data
        else:
            refresh = RefreshToken.for_user(user)
            cache.set(
                cache_keyword,
                {"refresh": str(refresh), "access": str(refresh.access_token)},
                self.expiration_time,
            )
            return {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            }
