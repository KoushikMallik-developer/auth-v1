from api.models.user_models.user import ECOMUser
from api.services.definitions import (
    SELLER_ACCOUNT_TYPE_IDENTIFIER,
    USER_ACCOUNT_TYPE_IDENTIFIER,
    ADMIN_ACCOUNT_TYPE_IDENTIFIER,
)


def get_account_type_by_id(uid: str) -> str:
    user: ECOMUser = ECOMUser.objects.get(id=uid)
    if user:
        return user.account_type


def is_seller_account(uid: str) -> bool:
    if get_account_type_by_id(uid=uid) == SELLER_ACCOUNT_TYPE_IDENTIFIER:
        return True
    else:
        return False


def is_regular_account(uid: str) -> bool:
    if get_account_type_by_id(uid=uid) == USER_ACCOUNT_TYPE_IDENTIFIER:
        return True
    else:
        return False


def is_admin_account(uid: str) -> bool:
    if get_account_type_by_id(uid=uid) == ADMIN_ACCOUNT_TYPE_IDENTIFIER:
        return True
    else:
        return False
