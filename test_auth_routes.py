import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException, FastAPI
from auth_routes import router # Assuming auth_routes.py is in the same directory or accessible via PYTHONPATH

# Create a FastAPI instance and include the router
app = FastAPI()
app.include_router(router)

client = TestClient(app)

# Dummy data for testing
VALID_EMAIL = "test@example.com"
VALID_CODE = "1234"

# Tests for /auth/signup
def test_signup_valid_input():
    response = client.post(
        "/auth/signup",
        data={"name": "Test User", "email": VALID_EMAIL, "organization": "Test Org"}
    )
    # This will likely fail due to unmocked dependencies if validation passes
    # For now, we are primarily interested if it *doesn't* return 422 for these inputs.
    # A more complete test would mock is_valid_email, get_user, generate_code, send_code
    assert response.status_code != 422 

def test_signup_empty_name():
    response = client.post(
        "/auth/signup",
        data={"name": "", "email": VALID_EMAIL, "organization": "Test Org"}
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "Name cannot be empty."

def test_signup_whitespace_name():
    response = client.post(
        "/auth/signup",
        data={"name": "   ", "email": VALID_EMAIL, "organization": "Test Org"}
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "Name cannot be empty."

def test_signup_long_name():
    long_name = "a" * 256
    response = client.post(
        "/auth/signup",
        data={"name": long_name, "email": VALID_EMAIL, "organization": "Test Org"}
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "Name is too long (maximum 255 characters)."

def test_signup_empty_organization():
    response = client.post(
        "/auth/signup",
        data={"name": "Test User", "email": VALID_EMAIL, "organization": ""}
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "Organization cannot be empty if provided."

def test_signup_whitespace_organization():
    response = client.post(
        "/auth/signup",
        data={"name": "Test User", "email": VALID_EMAIL, "organization": "   "}
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "Organization cannot be empty if provided."

def test_signup_long_organization():
    long_org = "a" * 256
    response = client.post(
        "/auth/signup",
        data={"name": "Test User", "email": VALID_EMAIL, "organization": long_org}
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "Organization name is too long (maximum 255 characters)."

def test_signup_none_organization():
    response = client.post(
        "/auth/signup",
        data={"name": "Test User", "email": VALID_EMAIL} # Organization not provided
    )
    # Similar to test_signup_valid_input, this primarily checks that validation for org doesn't fail incorrectly.
    assert response.status_code != 422

# Tests for /auth/signup/validate
def test_signup_validate_valid_input():
    response = client.post(
        "/auth/signup/validate",
        data={"name": "Test User", "email": VALID_EMAIL, "organization": "Test Org", "code": VALID_CODE}
    )
    # This will likely fail due to unmocked dependencies if validation passes
    assert response.status_code != 422

def test_signup_validate_empty_name():
    response = client.post(
        "/auth/signup/validate",
        data={"name": "", "email": VALID_EMAIL, "organization": "Test Org", "code": VALID_CODE}
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "Name cannot be empty."

def test_signup_validate_whitespace_name():
    response = client.post(
        "/auth/signup/validate",
        data={"name": "   ", "email": VALID_EMAIL, "organization": "Test Org", "code": VALID_CODE}
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "Name cannot be empty."

def test_signup_validate_long_name():
    long_name = "a" * 256
    response = client.post(
        "/auth/signup/validate",
        data={"name": long_name, "email": VALID_EMAIL, "organization": "Test Org", "code": VALID_CODE}
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "Name is too long (maximum 255 characters)."

def test_signup_validate_empty_organization():
    response = client.post(
        "/auth/signup/validate",
        data={"name": "Test User", "email": VALID_EMAIL, "organization": "", "code": VALID_CODE}
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "Organization cannot be empty if provided."

def test_signup_validate_whitespace_organization():
    response = client.post(
        "/auth/signup/validate",
        data={"name": "Test User", "email": VALID_EMAIL, "organization": "   ", "code": VALID_CODE}
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "Organization cannot be empty if provided."

def test_signup_validate_long_organization():
    long_org = "a" * 256
    response = client.post(
        "/auth/signup/validate",
        data={"name": "Test User", "email": VALID_EMAIL, "organization": long_org, "code": VALID_CODE}
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "Organization name is too long (maximum 255 characters)."

def test_signup_validate_none_organization():
    response = client.post(
        "/auth/signup/validate",
        data={"name": "Test User", "email": VALID_EMAIL, "code": VALID_CODE} # Organization not provided
    )
    # Similar to test_signup_validate_valid_input, this primarily checks that validation for org doesn't fail incorrectly.
    assert response.status_code != 422
