from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from uuid import UUID

from app.database import get_async_session
from app.dependencies import get_db, get_current_user, require_role, get_email_service
from app.services.user_service import UserService
from app.schemas.user_schemas import (
    UserProfileUpdate, 
    UserProfileResponse, 
    ProfessionalStatusUpdate, 
    UserSearchResponse,
    UserResponse
)
from app.models.user_model import User, UserRole
from app.services.email_service import EmailService
from app.utils.link_generation import create_user_links
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/profile", tags=["Profile Management"])

@router.get("/me", response_model=UserProfileResponse)
async def get_my_profile(
    current_user: User = Depends(get_current_user)
):
    """Get current user's profile"""
    return UserProfileResponse(
        id=current_user.id,
        nickname=current_user.nickname,
        email=current_user.email,
        first_name=current_user.first_name,
        last_name=current_user.last_name,
        bio=current_user.bio,
        profile_picture_url=current_user.profile_picture_url,
        linkedin_profile_url=current_user.linkedin_profile_url,
        github_profile_url=current_user.github_profile_url,
        role=current_user.role,
        is_professional=current_user.is_professional,
        professional_status_updated_at=current_user.professional_status_updated_at,
        email_verified=current_user.email_verified,
        created_at=current_user.created_at
    )

@router.put("/me", response_model=UserProfileResponse)
async def update_my_profile(
    profile_data: UserProfileUpdate,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
    email_service: EmailService = Depends(get_email_service)
):
    """Update current user's profile"""
    updated_user = await UserService.update_profile(
        session, 
        current_user.id, 
        profile_data.model_dump(exclude_unset=True)
    )
    
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to update profile"
        )
    
    # Send optional confirmation email (you can make this configurable)
    try:
        await email_service.send_profile_update_confirmation(updated_user)
    except Exception as e:
        logger.warning(f"Failed to send profile update confirmation email: {e}")
    
    return UserProfileResponse(
        id=updated_user.id,
        nickname=updated_user.nickname,
        email=updated_user.email,
        first_name=updated_user.first_name,
        last_name=updated_user.last_name,
        bio=updated_user.bio,
        profile_picture_url=updated_user.profile_picture_url,
        linkedin_profile_url=updated_user.linkedin_profile_url,
        github_profile_url=updated_user.github_profile_url,
        role=updated_user.role,
        is_professional=updated_user.is_professional,
        professional_status_updated_at=updated_user.professional_status_updated_at,
        email_verified=updated_user.email_verified,
        created_at=updated_user.created_at
    )

@router.get("/user/{user_id}", response_model=UserProfileResponse)
async def get_user_profile(
    user_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get any user's profile (public information)"""
    user = await UserService.get_by_id(session, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserProfileResponse(
        id=user.id,
        nickname=user.nickname,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        bio=user.bio,
        profile_picture_url=user.profile_picture_url,
        linkedin_profile_url=user.linkedin_profile_url,
        github_profile_url=user.github_profile_url,
        role=user.role,
        is_professional=user.is_professional,
        professional_status_updated_at=user.professional_status_updated_at,
        email_verified=user.email_verified,
        created_at=user.created_at
    )

@router.post("/upgrade-professional", status_code=status.HTTP_200_OK)
async def upgrade_user_to_professional(
    upgrade_data: ProfessionalStatusUpdate,
    current_user: User = Depends(require_role([UserRole.MANAGER, UserRole.ADMIN])),
    session: AsyncSession = Depends(get_db),
    email_service: EmailService = Depends(get_email_service)
):
    """Upgrade a user to professional status (Managers and Admins only)"""
    success = await UserService.upgrade_to_professional(
        session, 
        upgrade_data.user_id, 
        current_user.id
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to upgrade user to professional status"
        )
    
    # Send notification email to the upgraded user
    upgraded_user = await UserService.get_by_id(session, upgrade_data.user_id)
    if upgraded_user:
        try:
            await email_service.send_professional_upgrade_notification(upgraded_user)
        except Exception as e:
            # Log the error but don't fail the upgrade
            logger.warning(f"Failed to send upgrade notification email: {e}")
    
    return {"message": "User successfully upgraded to professional status"}

@router.post("/downgrade-professional", status_code=status.HTTP_200_OK)
async def downgrade_user_from_professional(
    downgrade_data: ProfessionalStatusUpdate,
    current_user: User = Depends(require_role([UserRole.ADMIN])),
    session: AsyncSession = Depends(get_db),
    email_service: EmailService = Depends(get_email_service)
):
    """Downgrade a user from professional status (Admins only)"""
    success = await UserService.downgrade_from_professional(
        session, 
        downgrade_data.user_id, 
        current_user.id
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to downgrade user from professional status"
        )
    
    # Send notification email to the downgraded user
    downgraded_user = await UserService.get_by_id(session, downgrade_data.user_id)
    if downgraded_user:
        try:
            await email_service.send_professional_downgrade_notification(downgraded_user)
        except Exception as e:
            logger.warning(f"Failed to send downgrade notification email: {e}")
    
    return {"message": "User successfully downgraded from professional status"}

@router.get("/search-users", response_model=List[UserSearchResponse])
async def search_users_for_upgrade(
    search: str = Query("", description="Search term for nickname, email, or name"),
    skip: int = Query(0, ge=0, description="Number of users to skip"),
    limit: int = Query(10, ge=1, le=100, description="Number of users to return"),
    current_user: User = Depends(require_role([UserRole.MANAGER, UserRole.ADMIN])),
    session: AsyncSession = Depends(get_db)
):
    """Search for users that can be upgraded to professional status"""
    users = await UserService.search_users_for_upgrade(session, search, skip, limit)
    
    return [
        UserSearchResponse(
            id=user.id,
            nickname=user.nickname,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            role=user.role,
            is_professional=user.is_professional,
            created_at=user.created_at
        ) for user in users
    ]

@router.get("/professional-users", response_model=List[UserSearchResponse])
async def get_professional_users(
    skip: int = Query(0, ge=0, description="Number of users to skip"),
    limit: int = Query(10, ge=1, le=100, description="Number of users to return"),
    current_user: User = Depends(require_role([UserRole.MANAGER, UserRole.ADMIN])),
    session: AsyncSession = Depends(get_db)
):
    """Get list of professional users (for managers/admins)"""
    users = await UserService.get_users_by_professional_status(session, True, skip, limit)
    
    return [
        UserSearchResponse(
            id=user.id,
            nickname=user.nickname,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            role=user.role,
            is_professional=user.is_professional,
            created_at=user.created_at
        ) for user in users
    ]

@router.get("/non-professional-users", response_model=List[UserSearchResponse])
async def get_non_professional_users(
    skip: int = Query(0, ge=0, description="Number of users to skip"),
    limit: int = Query(10, ge=1, le=100, description="Number of users to return"),
    current_user: User = Depends(require_role([UserRole.MANAGER, UserRole.ADMIN])),
    session: AsyncSession = Depends(get_db)
):
    """Get list of non-professional users (for managers/admins)"""
    users = await UserService.get_users_by_professional_status(session, False, skip, limit)
    
    return [
        UserSearchResponse(
            id=user.id,
            nickname=user.nickname,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            role=user.role,
            is_professional=user.is_professional,
            created_at=user.created_at
        ) for user in users
    ]