import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
from datetime import datetime, timezone

from app.services.user_service import UserService
from app.models.user_model import User, UserRole
from app.schemas.user_schemas import UserProfileUpdate, ProfessionalStatusUpdate


class TestUserProfileManagement:
    
    @pytest.mark.asyncio
    async def test_update_profile_success(self):
        """Test successful profile update"""
        # Setup
        user_id = uuid4()
        mock_session = AsyncMock()
        mock_user = User(
            id=user_id,
            nickname="testuser",
            email="test@example.com",
            role=UserRole.AUTHENTICATED,
            hashed_password="hashed123"
        )
        
        # Mock the get_by_id method
        with patch.object(UserService, 'get_by_id', new=AsyncMock(return_value=mock_user)):
            profile_data = {
                "first_name": "John",
                "last_name": "Doe",
                "bio": "Software developer"
            }
            
            # Execute
            result = await UserService.update_profile(mock_session, user_id, profile_data)
            
            # Assert
            assert result is not None
            assert result.first_name == "John"
            assert result.last_name == "Doe"
            assert result.bio == "Software developer"
            mock_session.add.assert_called_once()
            mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_profile_user_not_found(self):
        """Test profile update when user doesn't exist"""
        # Setup
        user_id = uuid4()
        mock_session = AsyncMock()
        
        with patch.object(UserService, 'get_by_id', new=AsyncMock(return_value=None)):
            # Execute
            result = await UserService.update_profile(mock_session, user_id, {})
            
            # Assert
            assert result is None

    @pytest.mark.asyncio
    async def test_update_profile_filters_invalid_fields(self):
        """Test that profile update only allows certain fields"""
        # Setup
        user_id = uuid4()
        mock_session = AsyncMock()
        mock_user = User(
            id=user_id,
            nickname="testuser",
            email="test@example.com",
            role=UserRole.AUTHENTICATED,
            hashed_password="hashed123",
            is_professional=False
        )
        
        with patch.object(UserService, 'get_by_id', new=AsyncMock(return_value=mock_user)):
            profile_data = {
                "first_name": "John",
                "email": "newemail@example.com",  # Should be filtered out
                "role": UserRole.ADMIN,  # Should be filtered out
                "is_professional": True,  # Should be filtered out
                "hashed_password": "newpass"  # Should be filtered out
            }
            
            # Execute
            result = await UserService.update_profile(mock_session, user_id, profile_data)
            
            # Assert
            assert result is not None
            assert result.first_name == "John"
            # These fields should not have changed
            assert result.email == "test@example.com"
            assert result.role == UserRole.AUTHENTICATED
            assert result.is_professional == False

    @pytest.mark.asyncio
    async def test_upgrade_to_professional_success(self):
        """Test successful professional upgrade"""
        # Setup
        user_id = uuid4()
        manager_id = uuid4()
        mock_session = AsyncMock()
        
        mock_user = User(
            id=user_id,
            nickname="testuser",
            email="test@example.com",
            role=UserRole.AUTHENTICATED,
            is_professional=False,
            hashed_password="hashed123"
        )
        
        mock_manager = User(
            id=manager_id,
            nickname="manager",
            email="manager@example.com",
            role=UserRole.MANAGER,
            hashed_password="hashed123"
        )
        
        def get_by_id_side_effect(session, uid):
            if uid == user_id:
                return mock_user
            elif uid == manager_id:
                return mock_manager
            return None
        
        with patch.object(UserService, 'get_by_id', new=AsyncMock(side_effect=get_by_id_side_effect)):
            # Execute
            result = await UserService.upgrade_to_professional(mock_session, user_id, manager_id)
            
            # Assert
            assert result is True
            assert mock_user.is_professional is True
            assert mock_user.professional_status_updated_at is not None
            mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_upgrade_to_professional_insufficient_permissions(self):
        """Test professional upgrade with insufficient permissions"""
        # Setup
        user_id = uuid4()
        regular_user_id = uuid4()
        mock_session = AsyncMock()
        
        mock_user = User(
            id=user_id,
            nickname="testuser",
            email="test@example.com",
            role=UserRole.AUTHENTICATED,
            is_professional=False,
            hashed_password="hashed123"
        )
        
        mock_regular_user = User(
            id=regular_user_id,
            nickname="regularuser",
            email="regular@example.com",
            role=UserRole.AUTHENTICATED,  # Not manager or admin
            hashed_password="hashed123"
        )
        
        def get_by_id_side_effect(session, uid):
            if uid == user_id:
                return mock_user
            elif uid == regular_user_id:
                return mock_regular_user
            return None
        
        with patch.object(UserService, 'get_by_id', new=AsyncMock(side_effect=get_by_id_side_effect)):
            # Execute
            result = await UserService.upgrade_to_professional(mock_session, user_id, regular_user_id)
            
            # Assert
            assert result is False
            assert mock_user.is_professional is False

    @pytest.mark.asyncio
    async def test_upgrade_already_professional_user(self):
        """Test upgrading user who is already professional"""
        # Setup
        user_id = uuid4()
        admin_id = uuid4()
        mock_session = AsyncMock()
        
        mock_user = User(
            id=user_id,
            nickname="testuser",
            email="test@example.com",
            role=UserRole.AUTHENTICATED,
            is_professional=True,  # Already professional
            hashed_password="hashed123"
        )
        
        mock_admin = User(
            id=admin_id,
            nickname="admin",
            email="admin@example.com",
            role=UserRole.ADMIN,
            hashed_password="hashed123"
        )
        
        def get_by_id_side_effect(session, uid):
            if uid == user_id:
                return mock_user
            elif uid == admin_id:
                return mock_admin
            return None
        
        with patch.object(UserService, 'get_by_id', new=AsyncMock(side_effect=get_by_id_side_effect)):
            # Execute
            result = await UserService.upgrade_to_professional(mock_session, user_id, admin_id)
            
            # Assert
            assert result is True  # Should return True but not do anything

    @pytest.mark.asyncio
    async def test_downgrade_from_professional_admin_only(self):
        """Test professional downgrade requires admin role"""
        # Setup
        user_id = uuid4()
        manager_id = uuid4()
        mock_session = AsyncMock()
        
        mock_user = User(
            id=user_id,
            nickname="testuser",
            email="test@example.com",
            role=UserRole.AUTHENTICATED,
            is_professional=True,
            hashed_password="hashed123"
        )
        
        mock_manager = User(
            id=manager_id,
            nickname="manager",
            email="manager@example.com",
            role=UserRole.MANAGER,  # Manager, not admin
            hashed_password="hashed123"
        )
        
        def get_by_id_side_effect(session, uid):
            if uid == user_id:
                return mock_user
            elif uid == manager_id:
                return mock_manager
            return None
        
        with patch.object(UserService, 'get_by_id', new=AsyncMock(side_effect=get_by_id_side_effect)):
            # Execute
            result = await UserService.downgrade_from_professional(mock_session, user_id, manager_id)
            
            # Assert
            assert result is False  # Should fail because manager is not admin

    @pytest.mark.asyncio
    async def test_downgrade_from_professional_success(self):
        """Test successful professional downgrade by admin"""
        # Setup
        user_id = uuid4()
        admin_id = uuid4()
        mock_session = AsyncMock()
        
        mock_user = User(
            id=user_id,
            nickname="testuser",
            email="test@example.com",
            role=UserRole.AUTHENTICATED,
            is_professional=True,
            hashed_password="hashed123"
        )
        
        mock_admin = User(
            id=admin_id,
            nickname="admin",
            email="admin@example.com",
            role=UserRole.ADMIN,
            hashed_password="hashed123"
        )
        
        def get_by_id_side_effect(session, uid):
            if uid == user_id:
                return mock_user
            elif uid == admin_id:
                return mock_admin
            return None
        
        with patch.object(UserService, 'get_by_id', new=AsyncMock(side_effect=get_by_id_side_effect)):
            # Execute
            result = await UserService.downgrade_from_professional(mock_session, user_id, admin_id)
            
            # Assert
            assert result is True
            assert mock_user.is_professional is False
            assert mock_user.professional_status_updated_at is not None
            mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_search_users_for_upgrade(self):
        """Test searching users for upgrade"""
        # Setup
        mock_session = AsyncMock()
        mock_users = [
            User(id=uuid4(), nickname="user1", email="user1@example.com", 
                 role=UserRole.AUTHENTICATED, is_professional=False, hashed_password="hash1"),
            User(id=uuid4(), nickname="user2", email="user2@example.com", 
                 role=UserRole.AUTHENTICATED, is_professional=False, hashed_password="hash2"),
        ]
        
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = mock_users
        
        with patch.object(UserService, '_execute_query', new=AsyncMock(return_value=mock_result)):
            # Execute
            result = await UserService.search_users_for_upgrade(mock_session, "user", 0, 10)
            
            # Assert
            assert len(result) == 2
            assert all(not user.is_professional for user in result)
            assert all(user.role == UserRole.AUTHENTICATED for user in result)

    @pytest.mark.asyncio
    async def test_get_users_by_professional_status(self):
        """Test getting users filtered by professional status"""
        # Setup
        mock_session = AsyncMock()
        mock_professional_users = [
            User(id=uuid4(), nickname="pro1", email="pro1@example.com", 
                 role=UserRole.AUTHENTICATED, is_professional=True, hashed_password="hash1"),
            User(id=uuid4(), nickname="pro2", email="pro2@example.com", 
                 role=UserRole.AUTHENTICATED, is_professional=True, hashed_password="hash2"),
        ]
        
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = mock_professional_users
        
        with patch.object(UserService, '_execute_query', new=AsyncMock(return_value=mock_result)):
            # Execute
            result = await UserService.get_users_by_professional_status(mock_session, True, 0, 10)
            
            # Assert
            assert len(result) == 2
            assert all(user.is_professional for user in result)


class TestUserModelMethods:
    
    def test_update_professional_status(self):
        """Test the update_professional_status method"""
        # Setup
        user = User(
            id=uuid4(),
            nickname="testuser",
            email="test@example.com",
            role=UserRole.AUTHENTICATED,
            hashed_password="hashed123",
            is_professional=False,
            professional_status_updated_at=None
        )
        
        # Execute
        user.update_professional_status(True)
        
        # Assert
        assert user.is_professional is True
        assert user.professional_status_updated_at is not None
        assert isinstance(user.professional_status_updated_at, datetime)

    def test_update_professional_status_downgrade(self):
        """Test downgrading professional status"""
        # Setup
        user = User(
            id=uuid4(),
            nickname="testuser",
            email="test@example.com",
            role=UserRole.AUTHENTICATED,
            hashed_password="hashed123",
            is_professional=True,
            professional_status_updated_at=datetime.now(timezone.utc)
        )
        
        old_timestamp = user.professional_status_updated_at
        
        # Execute
        user.update_professional_status(False)
        
        # Assert
        assert user.is_professional is False
        assert user.professional_status_updated_at != old_timestamp

    def test_has_role_method(self):
        """Test the has_role method"""
        # Setup
        user = User(
            id=uuid4(),
            nickname="manager",
            email="manager@example.com",
            role=UserRole.MANAGER,
            hashed_password="hashed123"
        )
        
        # Execute & Assert
        assert user.has_role(UserRole.MANAGER) is True
        assert user.has_role(UserRole.ADMIN) is False
        assert user.has_role(UserRole.AUTHENTICATED) is False


class TestProfileAPIEndpoints:
    """
    These would be integration tests that test the actual API endpoints.
    You would use FastAPI's TestClient for these.
    """
    
    @pytest.fixture
    def mock_current_user(self):
        return User(
            id=uuid4(),
            nickname="testuser",
            email="test@example.com",
            role=UserRole.AUTHENTICATED,
            hashed_password="hashed123",
            is_professional=False
        )
    
    @pytest.fixture
    def mock_manager_user(self):
        return User(
            id=uuid4(),
            nickname="manager",
            email="manager@example.com",
            role=UserRole.MANAGER,
            hashed_password="hashed123",
            is_professional=True
        )
    
    def test_profile_schema_validation(self):
        """Test UserProfileUpdate schema validation"""
        # Valid data
        valid_data = {
            "first_name": "John",
            "last_name": "Doe",
            "bio": "Software developer",
            "linkedin_profile_url": "https://linkedin.com/in/johndoe"
        }
        
        profile_update = UserProfileUpdate(**valid_data)
        assert profile_update.first_name == "John"
        assert profile_update.last_name == "Doe"
        
        # Invalid URL should raise validation error
        with pytest.raises(ValueError):
            UserProfileUpdate(
                first_name="John",
                linkedin_profile_url="invalid-url"
            )

    def test_professional_status_update_schema(self):
        """Test ProfessionalStatusUpdate schema"""
        user_id = uuid4()
        update_data = ProfessionalStatusUpdate(user_id=user_id)
        assert update_data.user_id == user_id


# Integration Tests
class TestProfileManagementIntegration:
    
    @pytest.mark.asyncio
    async def test_complete_professional_upgrade_flow(self):
        """Test the complete flow of upgrading a user to professional status"""
        # Setup mock database session and email service
        mock_session = AsyncMock()
        mock_email_service = AsyncMock()
        
        # Create test users
        regular_user = User(
            id=uuid4(),
            nickname="regularuser",
            email="regular@example.com",
            role=UserRole.AUTHENTICATED,
            is_professional=False,
            hashed_password="hash123"
        )
        
        manager_user = User(
            id=uuid4(),
            nickname="manager",
            email="manager@example.com",
            role=UserRole.MANAGER,
            hashed_password="hash123"
        )
        
        # Mock service methods
        def get_by_id_side_effect(session, uid):
            if uid == regular_user.id:
                return regular_user
            elif uid == manager_user.id:
                return manager_user
            return None
        
        with patch.object(UserService, 'get_by_id', new=AsyncMock(side_effect=get_by_id_side_effect)):
            with patch.object(UserService, 'search_users_for_upgrade', new=AsyncMock(return_value=[regular_user])):
                mock_email_service.send_professional_upgrade_notification = AsyncMock(return_value=True)
                
                # Execute the flow
                # 1. Search for users
                search_results = await UserService.search_users_for_upgrade(mock_session, "regular", 0, 10)
                assert len(search_results) == 1
                assert search_results[0].id == regular_user.id
                
                # 2. Upgrade user
                upgrade_success = await UserService.upgrade_to_professional(
                    mock_session, 
                    regular_user.id, 
                    manager_user.id
                )
                assert upgrade_success is True
                assert regular_user.is_professional is True
                
                # 3. Send notification
                notification_sent = await mock_email_service.send_professional_upgrade_notification(regular_user)
                assert notification_sent is True
                
                # Verify session operations
                mock_session.commit.assert_called()

    @pytest.mark.asyncio
    async def test_profile_update_validation_flow(self):
        """Test profile update with various validation scenarios"""
        # Setup
        mock_session = AsyncMock()
        user = User(
            id=uuid4(),
            nickname="testuser",
            email="test@example.com",
            role=UserRole.AUTHENTICATED,
            hashed_password="hash123"
        )
        
        with patch.object(UserService, 'get_by_id', new=AsyncMock(return_value=user)):
            # Test valid profile data
            valid_data = {
                "first_name": "John",
                "last_name": "Doe",
                "bio": "Software developer with 5 years experience",
                "linkedin_profile_url": "https://linkedin.com/in/johndoe"
            }
            
            result = await UserService.update_profile(mock_session, user.id, valid_data)
            assert result is not None
            assert result.first_name == "John"
            
            # Test with invalid fields (should be filtered out)
            invalid_data = {
                "first_name": "Jane",
                "email": "newemail@example.com",  # Should be filtered out
                "role": "ADMIN",  # Should be filtered out
                "is_professional": True  # Should be filtered out
            }
            
            result = await UserService.update_profile(mock_session, user.id, invalid_data)
            assert result is not None
            assert result.first_name == "Jane"
            # Email, role, and is_professional should not have changed through profile update
            assert result.email == "test@example.com"
        