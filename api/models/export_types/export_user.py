import datetime
import typing
from typing import Optional
from uuid import UUID

from pydantic import BaseModel


class ExportECOMUser(BaseModel):
    id: Optional[UUID]
    username: str
    email: str
    fname: str
    lname: str
    dob: Optional[datetime.datetime]
    phone: Optional[str]
    image: Optional[str]
    is_active: bool
    account_type: str
    created_at: datetime.datetime
    updated_at: datetime.datetime

    def __init__(self, with_id: bool = True, **kwargs):
        if not with_id:
            kwargs["id"] = None
        super().__init__(**kwargs)


class ExportECOMUserList(BaseModel):
    user_list: typing.List[ExportECOMUser]
