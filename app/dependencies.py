from typing import Generator, Dict, Any, List
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from functools import lru_cache

from app.database import Database
from app.utils.template_manager import TemplateManager
from app.services.email_service import EmailService
from app.services.jwt_service import decode_token
from settings.config import Settings


@lru_cache()
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()


def get_email_service(settings: Settings = Depends(get_settings)) -> EmailService:
    """Get email service with template manager."""
    template_manager = TemplateManager()
    return EmailService(template_manager=template_manager)


async def get_db() -> Generator[AsyncSession, None, None]:
    """
    Dependency that provides a database session for each request.
    Properly handles async context management and error handling.
    """
    async_session_factory = Database.get_session_factory()
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error: {str(e)}"
            )
        finally:
            await session.close()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    """
    Extract and validate user information from JWT token.
    
    Args:
        token: JWT token from Authorization header
        
    Returns:
        Dict containing user_id and role
        
    Raises:
        HTTPException: If token is invalid or missing required fields
    """
    import jwt as pyjwt
    
    settings = get_settings()
    
    try:
        # Decode token directly with PyJWT to catch specific exceptions
        payload = pyjwt.decode(
            token, 
            settings.jwt_secret_key,  # Use jwt_secret_key from your settings
            algorithms=[settings.jwt_algorithm]  # Use jwt_algorithm from your settings
        )
        
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except pyjwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id: str = payload.get("sub")
    user_role: str = payload.get("role")
    
    if not user_id or not user_role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    return {"user_id": user_id, "role": user_role}


def require_role(required_roles: List[str]):
    """
    Create a dependency that checks if user has required role(s).
    
    Args:
        required_roles: List of roles that are allowed
        
    Returns:
        Dependency function that validates user role
    """
    def role_checker(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_role = current_user.get("role")
        
        if user_role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted"
            )
        return current_user
    
    return role_checker


def require_admin():
    """Convenience dependency for admin-only routes."""
    return require_role(["admin"])


def require_user_or_admin():
    """Convenience dependency for user or admin access."""
    return require_role(["user", "admin"])


async def get_current_active_user(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """
    Get current user and verify they are active (optional enhancement).
    You would need to implement user status checking in your database.
    """
    # Example: Check if user is active in database
    # user = await get_user_by_id(db, current_user["user_id"])
    # if not user or not user.is_active:
    #     raise HTTPException(
    #         status_code=status.HTTP_400_BAD_REQUEST,
    #         detail="Inactive user"
    #     )
    
    return current_user