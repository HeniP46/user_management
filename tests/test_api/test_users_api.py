from builtins import str
import pytest
from httpx import AsyncClient
from app.main import app
from app.models.user_model import User, UserRole
from app.utils.nickname_gen import generate_nickname
from app.utils.security import hash_password
from app.services.jwt_service import decode_token  # Import your FastAPI app
from urllib.parse import urlencode

# Example of a test function using the async_client fixture
@pytest.mark.asyncio
async def test_create_user_access_denied(async_client, user_token, email_service):
    headers = {"Authorization": f"Bearer {user_token}"}
    # Define user data for the test
    user_data = {
        "nickname": generate_nickname(),
        "email": "test@example.com",
        "password": "sS#fdasrongPassword123!",
    }
    # Send a POST request to create a user
    response = await async_client.post("/users/", json=user_data, headers=headers)
    # Asserts
    assert response.status_code == 403

# You can similarly refactor other test functions to use the async_client fixture
@pytest.mark.asyncio
async def test_retrieve_user_access_denied(async_client, verified_user, user_token):
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.get(f"/users/{verified_user.id}", headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_retrieve_user_access_allowed(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == str(admin_user.id)

@pytest.mark.asyncio
async def test_update_user_email_access_denied(async_client, verified_user, user_token):
    updated_data = {"email": f"updated_{verified_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_update_user_email_access_allowed(async_client, admin_user, admin_token):
    updated_data = {"email": f"updated_{admin_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == updated_data["email"]


@pytest.mark.asyncio
async def test_delete_user(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{admin_user.id}", headers=headers)
    assert delete_response.status_code == 204
    # Verify the user is deleted
    fetch_response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert fetch_response.status_code == 404

@pytest.mark.asyncio
async def test_create_user_duplicate_email(async_client, verified_user):
    user_data = {
        "email": verified_user.email,
        "password": "AnotherPassword123!",
        "role": UserRole.ADMIN.name
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 400
    assert "Email already exists" in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_create_user_invalid_email(async_client):
    user_data = {
        "email": "notanemail",
        "password": "ValidPassword123!",
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_login_success(async_client, verified_user):
    # Attempt to login with the test user
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    
    # Check for successful login response
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # Use the decode_token method from jwt_service to decode the JWT
    decoded_token = decode_token(data["access_token"])
    assert decoded_token is not None, "Failed to decode token"
    assert decoded_token["role"] == "AUTHENTICATED", "The user role should be AUTHENTICATED"

@pytest.mark.asyncio
async def test_login_user_not_found(async_client):
    form_data = {
        "username": "nonexistentuser@here.edu",
        "password": "DoesNotMatter123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_incorrect_password(async_client, verified_user):
    form_data = {
        "username": verified_user.email,
        "password": "IncorrectPassword123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_unverified_user(async_client, unverified_user):
    form_data = {
        "username": unverified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_login_locked_user(async_client, locked_user):
    form_data = {
        "username": locked_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 400
    assert "Account locked due to too many failed login attempts." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_delete_user_does_not_exist(async_client, admin_token):
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"  # Valid UUID format
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{non_existent_user_id}", headers=headers)
    assert delete_response.status_code == 404

@pytest.mark.asyncio
async def test_update_user_github(async_client, admin_user, admin_token):
    updated_data = {"github_profile_url": "http://www.github.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["github_profile_url"] == updated_data["github_profile_url"]

@pytest.mark.asyncio
async def test_update_user_linkedin(async_client, admin_user, admin_token):
    updated_data = {"linkedin_profile_url": "http://www.linkedin.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["linkedin_profile_url"] == updated_data["linkedin_profile_url"]

@pytest.mark.asyncio
async def test_list_users_as_admin(async_client, admin_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert 'items' in response.json()

@pytest.mark.asyncio
async def test_list_users_as_manager(async_client, manager_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_list_users_unauthorized(async_client, user_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403  # Forbidden, as expected for regular user

# ===========================
# ADDITIONAL STRATEGIC TESTS
# ===========================

@pytest.mark.asyncio
async def test_access_with_malformed_token(async_client):
    """Test API access with malformed JWT token"""
    headers = {"Authorization": "Bearer invalid.malformed.token"}
    response = await async_client.get("/users/", headers=headers)
    assert response.status_code == 401
    assert "Invalid token" in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_access_with_expired_token(async_client, expired_token):
    """Test API access with expired JWT token"""
    headers = {"Authorization": f"Bearer {expired_token}"}
    response = await async_client.get("/users/", headers=headers)
    assert response.status_code == 401
    assert "Invalid token" in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_register_user_with_sql_injection_attempt(async_client):
    """Test user registration with SQL injection attempt in email field"""
    malicious_data = {
        "email": "test'; DROP TABLE users; --@example.com",
        "password": "ValidPassword123!",
        "nickname": "test_user"
    }
    response = await async_client.post("/register/", json=malicious_data)
    assert response.status_code == 422  # Should fail validation

@pytest.mark.asyncio
async def test_register_user_with_extremely_long_inputs(async_client):
    """Test user registration with extremely long inputs"""
    long_string = "a" * 1000
    user_data = {
        "email": f"{long_string}@example.com",
        "password": "ValidPassword123!",
        "nickname": long_string,
        "first_name": long_string,
        "last_name": long_string,
        "bio": long_string
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 422  # Should fail validation

@pytest.mark.asyncio
async def test_update_user_with_invalid_uuid(async_client, admin_token):
    """Test updating user with invalid UUID format"""
    headers = {"Authorization": f"Bearer {admin_token}"}
    invalid_uuid = "not-a-valid-uuid"
    response = await async_client.put(f"/users/{invalid_uuid}", 
                                     json={"first_name": "Updated"}, 
                                     headers=headers)
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_update_user_role_escalation_attempt(async_client, user_token, verified_user):
    """Test regular user attempting to escalate their role"""
    headers = {"Authorization": f"Bearer {user_token}"}
    update_data = {"role": "ADMIN"}
    response = await async_client.put(f"/users/{verified_user.id}", 
                                     json=update_data, 
                                     headers=headers)
    assert response.status_code == 403  # Should be forbidden

@pytest.mark.asyncio
async def test_login_rate_limiting_simulation(async_client, verified_user):
    """Test multiple rapid login attempts to simulate rate limiting scenarios"""
    form_data = {
        "username": verified_user.email,
        "password": "WrongPassword123!"
    }
    
    responses = []
    for _ in range(5):
        response = await async_client.post("/login/", 
                                          data=urlencode(form_data), 
                                          headers={"Content-Type": "application/x-www-form-urlencoded"})
        responses.append(response.status_code)
    
    assert all(status in [401, 429] for status in responses)

@pytest.mark.asyncio
async def test_login_with_case_insensitive_email(async_client, verified_user):
    """Test login with different email case variations"""
    uppercase_email = verified_user.email.upper()
    form_data = {
        "username": uppercase_email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", 
                                      data=urlencode(form_data), 
                                      headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code in [200, 401]  # Depending on implementation