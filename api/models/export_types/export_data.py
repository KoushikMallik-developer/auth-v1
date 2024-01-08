from typing import Optional, Any

from pydantic import BaseModel


class ExportData(BaseModel):
    data: Any
    errorMessage: Optional[str]
