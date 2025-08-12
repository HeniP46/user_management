from typing import Generator, Dict, Any, List
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from functools import lru_cache
import jwt as pyjwt  # Use this alias to avoid conflicts
from app.config_loader import settings, Settings
from app.database import Database
from app.utils.template_manager import TemplateManager
from app.services.email_service import EmailService
from app.models.user_model import User, UserRole

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

@lru_cache()
def get_settings() -> Settings:
    return settings

def get_email_service(settings: Settings = Depends(get_settings)) -> EmailService:
    template_manager = TemplateManager()
    return EmailService(template_manager=template_manager)

async def get_db() -> Generator[AsyncSession, None, None]:
    async_session_factory = Database.get_session_factory()
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"DB error: {e}")
        finally:
            await session.close()

def get_current_user_data(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    try:
        payload = pyjwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm]
        )
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired", headers={"WWW-Authenticate": "Bearer"})
    except pyjwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token", headers={"WWW-Authenticate": "Bearer"})
    
    user_email = payload.get("sub")
    user_role = payload.get("role")
    user_id = payload.get("id")  # Add user ID to payload when creating token
    
    if not user_email or not user_role:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token", headers={"WWW-Authenticate": "Bearer"})
    
    return {"user_email": user_email, "role": user_role, "id": user_id}

async def get_current_user(
    user_data: Dict[str, Any] = Depends(get_current_user_data),
    db: AsyncSession = Depends(get_db)
) -> User:
    from app.services.user_service import UserService  # Import here to avoid circular import
    user = await UserService.get_by_email(db, user_data["user_email"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    if user.is_locked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is locked")
    
    if not user.email_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not verified")
    
    # Add user ID to the return data for convenience
    return {"id": user.id, "email": user.email, "role": user.role, "user": user}

def require_role(allowed_roles: List[UserRole]):
    def check_role(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_role = current_user["role"]
        if user_role not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return current_user
    return check_role

def require_manager_or_admin(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    user_role = current_user["role"]
    if user_role not in [UserRole.MANAGER, UserRole.ADMIN]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Manager or Admin role required")
    return current_user

def require_admin(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    user_role = current_user["role"]
    if user_role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return current_user