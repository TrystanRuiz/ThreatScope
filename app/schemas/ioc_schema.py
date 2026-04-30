from pydantic import BaseModel
from typing import Optional

class IOC(BaseModel):
    value: str
    defanged: Optional[str] = None
    type: Optional[str] = None

class IOCCollection(BaseModel):
    urls: list[IOC] = []
    domains: list[IOC] = []
    ips: list[IOC] = []
    hashes: list[IOC] = []
    cves: list[str] = []
    emails: list[str] = []
