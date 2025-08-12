from builtins import Exception, bool, classmethod, int, str
from datetime import datetime, timezone, timedelta
import secrets
from typing import Optional, Dict, List, Union, Any
from pydantic import ValidationError
from sqlalchemy import func, select, and_, or_, update, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
import logging

from app.config_loader import get_settings
from app.models.user_model import User, UserRole
from app.schemas.user_schemas import UserCreate, UserUpdate
from app.utils.nickname_gen import generate_nickname
from app.utils.security import generate_verification_token, hash_password, verify_password
from app.services.email_service import EmailService

settings = get_settings()
logger = logging.getLogger(__name__)

class UserService:
    @classmethod
    async def _execute_query(cls, session: AsyncSession, query):
        try:
            result = await session.execute(query)
            return result
        except SQLAlchemyError as e:
            logger.error(f"Database error: {e}")
            await session.rollback()
            return None

    @classmethod
    async def _fetch_user(cls, session: AsyncSession, **filters) -> Optional[User]:
        query = select(User).filter_by(**filters)
        result = await cls._execute_query(session, query)
        return result.scalars().first() if result else None

    @classmethod
    async def get_by_id(cls, session: AsyncSession, user_id: UUID) -> Optional[User]:
        return await cls._fetch_user(session, id=user_id)

    @classmethod
    async def get_by_nickname(cls, session: AsyncSession, nickname: str) -> Optional[User]:
        return await cls._fetch_user(session, nickname=nickname)

    @classmethod
    async def get_by_email(cls, session: AsyncSession, email: str) -> Optional[User]:
        return await cls._fetch_user(session, email=email)

    @classmethod
    async def count(cls, session: AsyncSession) -> int:
        result = await cls._execute_query(session, select(func.count(User.id)))
        return result.scalar_one() if result else 0

    @classmethod
    async def create(cls, session: AsyncSession, user_data: Dict[str, str], email_service: EmailService) -> Optional[User]:
        try:
            validated_data = UserCreate(**user_data).model_dump()
            existing_user = await cls.get_by_email(session, validated_data['email'])
            if existing_user:
                logger.error("User with given email already exists.")
                return None

            validated_data['hashed_password'] = hash_password(validated_data.pop('password'))
            new_user = User(**validated_data)

            new_nickname = generate_nickname()
            while await cls.get_by_nickname(session, new_nickname):
                new_nickname = generate_nickname()
            new_user.nickname = new_nickname

            logger.info(f"User Role: {new_user.role}")
            user_count = await cls.count(session)
            new_user.role = UserRole.ADMIN if user_count == 0 else UserRole.ANONYMOUS            

            if new_user.role == UserRole.ADMIN:
                new_user.email_verified = True
            else:
                new_user.verification_token = generate_verification_token()
                await email_service.send_verification_email(new_user)

            session.add(new_user)
            await session.commit()
            await session.refresh(new_user)
            return new_user
        except ValidationError as e:
            logger.error(f"Validation error during user creation: {e}")
            await session.rollback()
            return None
        except Exception as e:
            logger.error(f"Error during user creation: {e}")
            await session.rollback()
            return None

    @classmethod
    async def register_user(cls, session: AsyncSession, user_data: Dict[str, str], email_service: EmailService = None) -> Optional[User]:
        """Register a new user (alias for create with default email service)"""
        if email_service is None:
            email_service = EmailService()
        return await cls.create(session, user_data, email_service)

    @classmethod
    async def update(cls, session: AsyncSession, user_or_id: Union[User, UUID], update_data: Dict[str, str]) -> Optional[User]:
        """
        Update user partially with validated data.
        If 'password' is present, hash it.
        """
        try:
            if isinstance(user_or_id, User):
                user = user_or_id
                user_id = user.id
            else:
                user_id = user_or_id
                user = await cls.get_by_id(session, user_id)
                if not user:
                    logger.error(f"User {user_id} not found.")
                    return None

            validated_data = UserUpdate(**update_data).model_dump(exclude_unset=True)

            if 'password' in validated_data:
                validated_data['hashed_password'] = hash_password(validated_data.pop('password'))

            for key, value in validated_data.items():
                if hasattr(user, key):
                    setattr(user, key, value)

            session.add(user)
            await session.commit()
            await session.refresh(user)
            logger.info(f"User {user_id} updated successfully.")
            return user
        except ValidationError as e:
            logger.error(f"Validation error during user update: {e}")
            await session.rollback()
            return None
        except Exception as e:
            logger.error(f"Error during user update: {e}")
            await session.rollback()
            return None

    @classmethod
    async def update_profile(cls, session: AsyncSession, user_id: UUID, profile_data: Dict[str, Any]) -> Optional[User]:
        """Update user profile with filtered fields"""
        try:
            user = await cls.get_by_id(session, user_id)
            if not user:
                logger.error(f"User {user_id} not found.")
                return None

            allowed_fields = {
                'first_name', 'last_name', 'bio', 'profile_picture_url', 
                'linkedin_profile_url', 'github_profile_url'
            }
            filtered_data = {k: v for k, v in profile_data.items() if k in allowed_fields}

            for field, value in filtered_data.items():
                if hasattr(user, field):
                    setattr(user, field, value)

            user.updated_at = datetime.now(timezone.utc)
            session.add(user)
            await session.commit()
            await session.refresh(user)
            logger.info(f"User {user_id} profile updated successfully.")
            return user
        except Exception as e:
            logger.error(f"Error during profile update: {e}")
            await session.rollback()
            return None

    @classmethod
    async def delete(cls, session: AsyncSession, user: User) -> bool:
        """Delete a user"""
        try:
            await session.delete(user)
            await session.commit()
            logger.info(f"User {user.id} deleted successfully.")
            return True
        except Exception as e:
            logger.error(f"Error during user deletion: {e}")
            await session.rollback()
            return False

    @classmethod
    async def list_users(cls, session: AsyncSession, skip: int = 0, limit: int = 10) -> List[User]:
        """List users with pagination"""
        try:
            query = select(User).offset(skip).limit(limit)
            result = await cls._execute_query(session, query)
            return result.scalars().all() if result else []
        except Exception as e:
            logger.error(f"Error listing users: {e}")
            return []

    @classmethod
    async def authenticate_user(cls, session: AsyncSession, email: str, password: str) -> Optional[User]:
        """Authenticate user with email and password"""
        try:
            user = await cls.get_by_email(session, email)
            if not user:
                return None
            
            if not verify_password(password, user.hashed_password):
                await cls.increment_failed_login(session, email)
                return None
                
            await cls.update_last_login(session, user.id)
            return user
        except Exception as e:
            logger.error(f"Error during authentication: {e}")
            return None

    @classmethod
    async def is_account_locked(cls, session: AsyncSession, email: str) -> bool:
        """Check if account is locked due to failed login attempts"""
        try:
            user = await cls.get_by_email(session, email)
            if not user:
                return False
                
            if hasattr(user, 'is_locked') and user.is_locked:
                return True
                
            if hasattr(user, 'failed_login_attempts') and user.failed_login_attempts >= getattr(settings, 'max_login_attempts', 5):
                if hasattr(user, 'last_login_attempt') and user.last_login_attempt:
                    lock_duration = timedelta(minutes=30)
                    if datetime.now(timezone.utc) - user.last_login_attempt < lock_duration:
                        return True
                    else:
                        user.failed_login_attempts = 0
                        await session.commit()
                        
            return False
        except Exception as e:
            logger.error(f"Error checking account lock status: {e}")
            return False

    @classmethod
    async def upgrade_to_professional(cls, session: AsyncSession, user_id: UUID, upgrader_id: UUID = None) -> Union[bool, User]:
        try:
            user = await cls.get_by_id(session, user_id)
            if not user:
                logger.error(f"User {user_id} not found.")
                return False if upgrader_id else None

            if upgrader_id is not None:
                upgrader = await cls.get_by_id(session, upgrader_id)
                if not upgrader or upgrader.role not in [UserRole.MANAGER, UserRole.ADMIN]:
                    logger.error(f"Insufficient permissions for user {upgrader_id}")
                    return False

            if user.role == UserRole.PROFESSIONAL:
                logger.warning(f"User {user_id} is already a professional")
                return True if upgrader_id else user

            user.role = UserRole.PROFESSIONAL if hasattr(UserRole, 'PROFESSIONAL') else UserRole.AUTHENTICATED
            user.is_professional = True
            user.professional_status_updated_at = datetime.now(timezone.utc)
            user.updated_at = datetime.now(timezone.utc)
            session.add(user)
            await session.commit()
            await session.refresh(user)
            logger.info(f"User {user_id} upgraded to professional.")
            
            return True if upgrader_id else user
        except Exception as e:
            logger.error(f"Error upgrading user to professional: {e}")
            await session.rollback()
            return False if upgrader_id else None

    @classmethod
    async def downgrade_from_professional(cls, session: AsyncSession, user_id: UUID, downgrader_id: UUID = None) -> Union[bool, User]:
        try:
            user = await cls.get_by_id(session, user_id)
            if not user:
                logger.error(f"User {user_id} not found.")
                return False if downgrader_id else None

            if downgrader_id is not None:
                downgrader = await cls.get_by_id(session, downgrader_id)
                if not downgrader or downgrader.role != UserRole.ADMIN:
                    logger.error(f"Insufficient permissions for user {downgrader_id}")
                    return False

            if not user.is_professional:
                logger.warning(f"User {user_id} is not a professional")
                return True if downgrader_id else user

            user.role = UserRole.AUTHENTICATED
            user.is_professional = False
            user.professional_status_updated_at = datetime.now(timezone.utc)
            user.updated_at = datetime.now(timezone.utc)
            session.add(user)
            await session.commit()
            await session.refresh(user)
            logger.info(f"User {user_id} downgraded from professional.")
            
            return True if downgrader_id else user
        except Exception as e:
            logger.error(f"Error downgrading user from professional: {e}")
            await session.rollback()
            return False if downgrader_id else None

    @classmethod
    async def search_users_for_upgrade(cls, session: AsyncSession, query: str = "", skip: int = 0, limit: int = 10) -> List[User]:
        """Search users eligible for professional upgrade"""
        try:
            conditions = [User.role == UserRole.AUTHENTICATED, User.is_professional == False]
            
            if hasattr(User, 'email_verified'):
                conditions.append(User.email_verified == True)
            elif hasattr(User, 'is_verified'):
                conditions.append(User.is_verified == True)
                
            if query:
                search_conditions = []
                search_conditions.append(User.nickname.ilike(f"%{query}%"))
                search_conditions.append(User.email.ilike(f"%{query}%"))
                
                if hasattr(User, 'first_name'):
                    search_conditions.append(User.first_name.ilike(f"%{query}%"))
                if hasattr(User, 'last_name'):
                    search_conditions.append(User.last_name.ilike(f"%{query}%"))
                    
                conditions.append(or_(*search_conditions))

            stmt = select(User).where(and_(*conditions)).offset(skip).limit(limit)
            result = await cls._execute_query(session, stmt)
            if result:
                scalars_result = result.scalars()
                return scalars_result.all()
            return []
        except Exception as e:
            logger.error(f"Error searching users for upgrade: {e}")
            return []

    @classmethod
    async def get_users_by_professional_status(cls, session: AsyncSession, is_professional: bool = True, skip: int = 0, limit: int = 10) -> List[User]:
        """Get users by professional status"""
        try:
            query = select(User).where(User.is_professional == is_professional).offset(skip).limit(limit)
            result = await cls._execute_query(session, query)
            if result:
                scalars_result = result.scalars()
                return scalars_result.all()
            return []
        except Exception as e:
            logger.error(f"Error getting users by professional status: {e}")
            return []

    @classmethod
    async def verify_email(cls, session: AsyncSession, user_id: UUID) -> Optional[User]:
        """Verify user email"""
        try:
            user = await cls.get_by_id(session, user_id)
            if not user:
                logger.error(f"User {user_id} not found.")
                return None

            if hasattr(user, 'email_verified'):
                user.email_verified = True
            elif hasattr(user, 'is_verified'):
                user.is_verified = True
                
            user.updated_at = datetime.now(timezone.utc)
            session.add(user)
            await session.commit()
            await session.refresh(user)
            logger.info(f"User {user_id} email verified.")
            return user
        except Exception as e:
            logger.error(f"Error verifying email: {e}")
            await session.rollback()
            return None

    @classmethod
    async def update_last_login(cls, session: AsyncSession, user_id: UUID) -> None:
        """Update user's last login timestamp"""
        try:
            user = await cls.get_by_id(session, user_id)
            if user:
                if hasattr(user, 'last_login_at'):
                    user.last_login_at = datetime.now(timezone.utc)
                if hasattr(user, 'failed_login_attempts'):
                    user.failed_login_attempts = 0
                session.add(user)
                await session.commit()
        except Exception as e:
            logger.error(f"Error updating last login: {e}")
            await session.rollback()

    @classmethod
    async def increment_failed_login(cls, session: AsyncSession, email: str) -> None:
        """Increment failed login attempts"""
        try:
            user = await cls.get_by_email(session, email)
            if user and hasattr(user, 'failed_login_attempts'):
                user.failed_login_attempts = getattr(user, 'failed_login_attempts', 0) + 1
                if hasattr(user, 'last_login_attempt'):
                    user.last_login_attempt = datetime.now(timezone.utc)
                session.add(user)
                await session.commit()
        except Exception as e:
            logger.error(f"Error incrementing failed login: {e}")
            await session.rollback()

    @classmethod
    async def update_password(cls, session: AsyncSession, user_id: UUID, new_password: str) -> Optional[User]:
        """Update user password"""
        try:
            user = await cls.get_by_id(session, user_id)
            if not user:
                logger.error(f"User {user_id} not found.")
                return None

            user.hashed_password = hash_password(new_password)
            user.updated_at = datetime.now(timezone.utc)
            session.add(user)
            await session.commit()
            await session.refresh(user)
            logger.info(f"User {user_id} password updated.")
            return user
        except Exception as e:
            logger.error(f"Error updating password: {e}")
            await session.rollback()
            return None

    @classmethod
    async def login_user(cls, session: AsyncSession, email: str, password: str) -> Optional[User]:
        """
        Login user with email and password (alias for authenticate_user)
        """
        return await cls.authenticate_user(session, email, password)

    @classmethod
    async def verify_email_with_token(cls, session: AsyncSession, user_id: UUID, token: str) -> bool:
        """Verify user email with verification token"""
        try:
            user = await cls.get_by_id(session, user_id)
            if not user:
                logger.error(f"User {user_id} not found.")
                return False

            if hasattr(user, 'verification_token') and user.verification_token == token:
                user.email_verified = True
                user.verification_token = None
                user.updated_at = datetime.now(timezone.utc)
                session.add(user)
                await session.commit()
                logger.info(f"User {user_id} email verified with token.")
                return True
            
            logger.warning(f"Invalid verification token for user {user_id}")
            return False
        except Exception as e:
            logger.error(f"Error verifying email with token: {e}")
            await session.rollback()
            return False

    @classmethod
    async def delete_by_id(cls, session: AsyncSession, user_id: UUID) -> bool:
        """Delete a user by their ID"""
        try:
            user = await cls.get_by_id(session, user_id)
            if not user:
                logger.error(f"User {user_id} not found.")
                return False
            
            return await cls.delete(session, user)
        except Exception as e:
            logger.error(f"Error during user deletion by ID: {e}")
            return False
