from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, EmailStr

class URLRequest(BaseModel):
    url: str
    api_key: str

class BatchURLRequest(BaseModel):
    urls: List[str]
    api_key: str

class PhishingResponse(BaseModel):
    is_phishing: bool
    confidence_level: float
    reason: str = ""

class AppHistoryRequest(BaseModel):
    token: str 
    start_dt: Optional[datetime] = None
    end_dt: Optional[datetime] = None 


class AppHistory(BaseModel):
    app_name: str
    all_urls: int
    phishing_urls: int
    day_limit: int
    day_limit_remaining: int
    history_urls: List[str]
    history_results: List[PhishingResponse]
    history_ts: List[datetime]   

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = None

class User(UserBase):
    id: int
    is_active: bool
    
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class CreateApp(BaseModel):
    app_name: str

class UpdateApp(BaseModel):
    app_token: str
    new_name: str

class DeleteApp(BaseModel):
    app_token: str

class AppInfo(BaseModel):
    app_name: str
    token: str
    day_limit: int
    url_count_on_day: int

class AppToken(BaseModel):
    token: str


