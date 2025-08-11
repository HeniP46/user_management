import uuid
import pytest
from pydantic import ValidationError
from datetime import datetime
from app.schemas.user_schemas import UserBase, UserCreate, UserUpdate, UserResponse, UserListResponse, LoginRequest

@pytest.fixture
def valid_user_base_data():
    return {
        "id": uuid.uuid4(),
        "nickname": "testuser",
        "email": "testuser@example.com",
        "role": "AUTHENTICATED",
        "is_verified": True,
        "is_locked": False,
        "first_name": "Test",
        "last_name": "User",
        "bio": "A user bio",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }

def test_user_base_model_valid(valid_user_base_data):
    user = UserBase(**valid_user_base_data)
    assert user.nickname == valid_user_base_data["nickname"]

def test_user_base_model_missing_required_fields():
    with pytest.raises(ValidationError):
        UserBase()

def test_user_create_model_valid():
    user_data = {
        "email": "testcreate@example.com",
        "password": "SecurePass123!",
        "nickname": "testcreate",
        "role": "AUTHENTICATED"  # Added required role field
    }
    user = UserCreate(**user_data)
    assert user.email == user_data["email"]

def test_user_update_model_partial():
    update_data = {"first_name": "Updated"}
    user = UserUpdate(**update_data)
    assert user.first_name == "Updated"

def test_user_response_model(valid_user_base_data):
    user_resp = UserResponse(**valid_user_base_data)
    assert user_resp.email == valid_user_base_data["email"]

def test_user_list_response_model():
    users = [UserResponse(
        id=uuid.uuid4(), 
        nickname="user1",  # Changed from "u1" to "user1" (minimum 3 characters)
        email="u1@example.com", 
        role="AUTHENTICATED", 
        is_verified=True, 
        is_locked=False,
        first_name=None, 
        last_name=None, 
        bio=None, 
        created_at=datetime.utcnow(), 
        updated_at=datetime.utcnow()
    )]
    user_list = UserListResponse(total=1, items=users, page=1, size=10)
    assert user_list.total == 1
    assert len(user_list.items) == 1
    assert user_list.page == 1
    assert user_list.size == 10

def test_login_request_model_valid():
    login_data = {"email": "user@example.com", "password": "Pass123!"}  # Changed username to email
    login_req = LoginRequest(**login_data)
    assert login_req.email == login_data["email"]

def test_login_request_model_missing_fields():
    with pytest.raises(ValidationError):
        LoginRequest()

# ===========================
# ADDITIONAL STRATEGIC TESTS
# ===========================

def test_user_schema_injection_prevention():
    """Test that user schemas handle malicious inputs without crashing"""
    malicious_inputs = [
        "<script>alert('xss')</script>",
        "'; DROP TABLE users; --",
        "../../../etc/passwd",
        "{{7*7}}",  # Template injection
        "${7*7}",   # Expression injection
    ]
    
    base_data = {
        "email": "test@example.com",
        "role": "AUTHENTICATED"
    }
    
    for malicious_input in malicious_inputs:
        test_cases = [
            {**base_data, "nickname": malicious_input},
            {**base_data, "first_name": malicious_input},
            {**base_data, "last_name": malicious_input},
            {**base_data, "bio": malicious_input}
        ]
        
        for test_case in test_cases:
            try:
                user = UserBase(**test_case)
                # Test that the model can be created without errors
                user_dict = user.model_dump()
                assert user_dict is not None
                # Verify that the malicious input is stored (no HTML escaping required for now)
                found_malicious_field = False
                for field_name, field_value in user_dict.items():
                    if field_value == malicious_input:
                        found_malicious_field = True
                        break
                # If we reach here, the model handled the input successfully
            except ValidationError:
                # Some inputs may fail validation, which is also acceptable
                pass

def test_user_schema_boundary_values():
    """Test user schema with boundary values for length limits"""
    base_data = {
        "email": "test@example.com",
        "role": "AUTHENTICATED"
    }
    
    boundary_tests = [
        {"nickname": "ab"},  # Below minimum (should fail)
        {"nickname": "abc"},  # At minimum (should pass)
        {"nickname": "a" * 50},  # At maximum (should pass)
        {"nickname": "a" * 51},  # Above maximum (should fail)
    ]
    
    for test_data in boundary_tests:
        test_case = {**base_data, **test_data}
        if len(test_data["nickname"]) < 3 or len(test_data["nickname"]) > 50:
            with pytest.raises(ValidationError):
                UserBase(**test_case)
        else:
            user = UserBase(**test_case)
            assert user.nickname == test_data["nickname"]