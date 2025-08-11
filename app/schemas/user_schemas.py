from builtins import ValueError, any, bool, str
from pydantic import BaseModel, EmailStr, Field, validator, root_validator
from typing import Optional, List
from datetime import datetime
import uuid
import re
import html
from app.models.user_model import UserRole
from app.utils.nickname_gen import generate_nickname
from app.schemas.link_schema import Link


def validate_url(url: Optional[str]) -> Optional[str]:
    """
    Validates URL format with a more permissive regex that accepts common URL patterns.
    """
    if url is None:
        return url
    url_regex = (
        r"^https?:\/\/[a-zA-Z0-9]"
        r"([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"
        r"(:[0-9]{1,5})?(\/.*)?$"
    )
    if not re.match(url_regex, url):
        raise ValueError("Invalid URL format")
    return url


class UserBase(BaseModel):
    email: EmailStr = Field(..., example="john.doe@example.com")
    nickname: Optional[str] = Field(
        None, min_length=3, max_length=50, pattern=r"^[\w-]+$", example=generate_nickname()
    )
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(
        None, example="Experienced software developer specializing in web applications."
    )
    profile_picture_url: Optional[str] = Field(None, example="https://example.com/profiles/john.jpg")
    linkedin_profile_url: Optional[str] = Field(None, example="https://linkedin.com/in/johndoe")
    github_profile_url: Optional[str] = Field(None, example="https://github.com/johndoe")
    role: UserRole

    _validate_urls = validator(
        "profile_picture_url", "linkedin_profile_url", "github_profile_url",
        pre=True, allow_reuse=True
    )(validate_url)

    @validator("nickname", "first_name", "last_name", "bio", pre=True)
    def sanitize_string_fields(cls, v):
        """Sanitize string fields to prevent XSS attacks"""
        if v is not None:
            return html.escape(str(v))
        return v

    class Config:
        from_attributes = True


class UserCreate(UserBase):
    email: EmailStr = Field(..., example="john.doe@example.com")
    password: str = Field(..., example="Secure*1234")
    role: UserRole = Field(default=UserRole.AUTHENTICATED)


class UserUpdate(UserBase):
    email: Optional[EmailStr] = Field(None, example="john.doe@example.com")
    nickname: Optional[str] = Field(
        None, min_length=3, max_length=50, pattern=r"^[\w-]+$", example="john_doe123"
    )
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(
        None, example="Experienced software developer specializing in web applications."
    )
    profile_picture_url: Optional[str] = Field(None, example="https://example.com/profiles/john.jpg")
    linkedin_profile_url: Optional[str] = Field(None, example="https://linkedin.com/in/johndoe")
    github_profile_url: Optional[str] = Field(None, example="https://github.com/johndoe")
    role: Optional[UserRole] = Field(None, example=UserRole.AUTHENTICATED)
    password: Optional[str] = Field(None, example="NewSecure*1234")

    @root_validator(pre=True)
    def check_at_least_one_value(cls, values):
        if not any(values.values()):
            raise ValueError("At least one field must be provided for update")
        return values


class UserResponse(UserBase):
    id: uuid.UUID = Field(..., example=uuid.uuid4())
    email: EmailStr = Field(..., example="john.doe@example.com")
    nickname: Optional[str] = Field(
        None, min_length=3, max_length=50, pattern=r"^[\w-]+$", example=generate_nickname()
    )
    is_professional: Optional[bool] = Field(default=False, example=True)
    role: UserRole
    last_login_at: Optional[datetime] = Field(None, example=datetime.now())
    created_at: Optional[datetime] = Field(None, example=datetime.now())
    updated_at: Optional[datetime] = Field(None, example=datetime.now())
    links: Optional[List[Link]] = Field(default=None, description="HATEOAS navigation links")


# NEW PROFILE MANAGEMENT SCHEMAS
class UserProfileUpdate(BaseModel):
    """Schema for updating user profile information"""
    first_name: Optional[str] = Field(None, max_length=100, description="User's first name")
    last_name: Optional[str] = Field(None, max_length=100, description="User's last name")
    bio: Optional[str] = Field(None, max_length=500, description="User's bio")
    profile_picture_url: Optional[str] = Field(None, description="URL to user's profile picture")
    linkedin_profile_url: Optional[str] = Field(None, description="User's LinkedIn profile URL")
    github_profile_url: Optional[str] = Field(None, description="User's GitHub profile URL")

    _validate_urls = validator(
        "profile_picture_url", "linkedin_profile_url", "github_profile_url",
        pre=True, allow_reuse=True
    )(validate_url)

    @validator("first_name", "last_name", "bio", pre=True)
    def sanitize_string_fields(cls, v):
        """Sanitize string fields to prevent XSS attacks"""
        if v is not None:
            return html.escape(str(v))
        return v

    class Config:
        from_attributes = True


class ProfessionalStatusUpdate(BaseModel):
    """Schema for professional status updates"""
    user_id: uuid.UUID = Field(..., description="ID of the user to update")
    
    class Config:
        from_attributes = True


class UserProfileResponse(BaseModel):
    """Schema for user profile response"""
    id: uuid.UUID
    nickname: str
    email: EmailStr
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None
    profile_picture_url: Optional[str] = None
    linkedin_profile_url: Optional[str] = None
    github_profile_url: Optional[str] = None
    role: UserRole
    is_professional: bool
    professional_status_updated_at: Optional[datetime] = None
    email_verified: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class UserSearchResponse(BaseModel):
    """Schema for user search results"""
    id: uuid.UUID
    nickname: str
    email: EmailStr
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: UserRole
    is_professional: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    # Accept either 'username' or 'email' for compatibility with OAuth2PasswordRequestForm
    email: Optional[EmailStr] = Field(None, example="john.doe@example.com")
    username: Optional[str] = Field(None, example="john.doe@example.com")
    password: str = Field(..., example="Secure*1234")

    @root_validator(pre=True)
    def normalize_username_email(cls, values):
        if not values.get("email") and values.get("username"):
            values["email"] = values["username"]
        return values


class ErrorResponse(BaseModel):
    error: str = Field(..., example="Not Found")
    details: Optional[str] = Field(None, example="The requested resource was not found.")


class UserListResponse(BaseModel):
    items: List[UserResponse] = Field(
        ..., example=[{
            "id": str(uuid.uuid4()),
            "nickname": generate_nickname(),
            "email": "john.doe@example.com",
            "first_name": "John",
            "last_name": "Doe",
            "bio": "Experienced developer",
            "role": "AUTHENTICATED",
            "profile_picture_url": "https://example.com/profiles/john.jpg",
            "linkedin_profile_url": "https://linkedin.com/in/johndoe",
            "github_profile_url": "https://github.com/johndoe"
        }]
    )
    total: int = Field(..., example=100)
    page: int = Field(..., example=1)
    size: int = Field(..., example=10)
    links: Optional[List[Link]] = Field(default=None, description="Pagination links")