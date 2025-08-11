from builtins import range
import pytest
from sqlalchemy import select
from app.dependencies import get_settings
from app.models.user_model import User, UserRole
from app.services.user_service import UserService
from app.utils.nickname_gen import generate_nickname

pytestmark = pytest.mark.asyncio

# Test creating a user with valid data
async def test_create_user_with_valid_data(db_session, email_service):
    user_data = {
        "nickname": generate_nickname(),
        "email": "valid_user@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ADMIN.name
    }
    user = await UserService.create(db_session, user_data, email_service)
    assert user is not None
    assert user.email == user_data["email"]

# Test creating a user with invalid data
async def test_create_user_with_invalid_data(db_session, email_service):
    user_data = {
        "nickname": "",  # Invalid nickname
        "email": "invalidemail",  # Invalid email
        "password": "short",  # Invalid password
    }
    user = await UserService.create(db_session, user_data, email_service)
    assert user is None

# Test fetching a user by ID when the user exists
async def test_get_by_id_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_id(db_session, user.id)
    assert retrieved_user.id == user.id

# Test fetching a user by ID when the user does not exist
async def test_get_by_id_user_does_not_exist(db_session):
    non_existent_user_id = "non-existent-id"
    retrieved_user = await UserService.get_by_id(db_session, non_existent_user_id)
    assert retrieved_user is None

# Test fetching a user by nickname when the user exists
async def test_get_by_nickname_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_nickname(db_session, user.nickname)
    assert retrieved_user.nickname == user.nickname

# Test fetching a user by nickname when the user does not exist
async def test_get_by_nickname_user_does_not_exist(db_session):
    retrieved_user = await UserService.get_by_nickname(db_session, "non_existent_nickname")
    assert retrieved_user is None

# Test fetching a user by email when the user exists
async def test_get_by_email_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_email(db_session, user.email)
    assert retrieved_user.email == user.email

# Test fetching a user by email when the user does not exist
async def test_get_by_email_user_does_not_exist(db_session):
    retrieved_user = await UserService.get_by_email(db_session, "nonexistent@example.com")
    assert retrieved_user is None

# Test updating user data
async def test_update_user(db_session, user):
    update_data = {"nickname": "UpdatedNickname"}
    updated_user = await UserService.update(db_session, user, update_data)  # Pass User object directly
    assert updated_user is not None
    assert updated_user.nickname == "UpdatedNickname"

# Test deleting a user
async def test_delete_user(db_session, user):
    result = await UserService.delete(db_session, user)  # Pass User object directly
    assert result is True

# ===========================
# ADDITIONAL STRATEGIC TESTS
# ===========================

async def test_user_service_database_connection_error(db_session, email_service, monkeypatch):
    """Test user service behavior when database connection fails"""
    async def mock_failing_commit():
        raise Exception("Database connection lost")
    
    monkeypatch.setattr(db_session, "commit", mock_failing_commit)
    
    user_data = {
        "nickname": generate_nickname(),
        "email": "test_db_error@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ADMIN.name
    }
    
    # This should fail due to mocked commit failure
    user = await UserService.create(db_session, user_data, email_service)
    assert user is None

async def test_concurrent_user_creation_same_email(db_session, email_service):
    """Test handling concurrent user creation attempts with same email"""
    user_data = {
        "nickname": generate_nickname(),
        "email": "concurrent_test@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ADMIN.name
    }
    
    user1 = await UserService.create(db_session, user_data, email_service)
    assert user1 is not None
    
    user_data["nickname"] = generate_nickname()
    user2 = await UserService.create(db_session, user_data, email_service)
    assert user2 is None  # Should fail due to duplicate email