from builtins import Exception, bool, classmethod, int, str
from datetime import datetime, timezone
import secrets
from typing import Optional, Dict, List, Union
from pydantic import ValidationError
from sqlalchemy import func, select
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

            # Use Pydantic UserUpdate model for validation and partial update
            validated_data = UserUpdate(**update_data).model_dump(exclude_unset=True)

            if 'password' in validated_data:
                validated_data['hashed_password'] = hash_password(validated_data.pop('password'))

            # Update only fields provided
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
