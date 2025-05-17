import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.main import app
from app.models import User
from app.schemas import UserCreate
from app.config import settings
from app.database import Base

client = TestClient(app)

@pytest.fixture(scope="module")
def test_db():
    SQLALCHEMY_DATABASE_URL = "sqlite:///./test_auth.db"
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    
    yield db
    
    Base.metadata.drop_all(bind=engine)
    db.close()

def test_user_registration(test_db: Session):
    user_data = {
        "email": "auth_test@example.com",
        "password": "testpassword"
    }
    response = client.post("/users/", json=user_data)
    assert response.status_code == 200
    assert response.json()["email"] == "auth_test@example.com"
    
    user = test_db.query(User).filter(User.email == "auth_test@example.com").first()
    assert user is not None
    assert user.email == "auth_test@example.com"
    
    response = client.post("/users/", json=user_data)
    assert response.status_code == 400
    assert "Email already registered" in response.json()["detail"]

def test_user_login(test_db: Session):
    user_data = UserCreate(email="login_test@example.com", password="loginpass")
    db_user = User(
        email=user_data.email,
        hashed_password="$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"  # "secret"
    )
    test_db.add(db_user)
    test_db.commit()
    
    login_data = {
        "username": "login_test@example.com",
        "password": "secret"
    }
    response = client.post("/users/token", data=login_data)
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"
    
    login_data["password"] = "wrong"
    response = client.post("/users/token", data=login_data)
    assert response.status_code == 401
    assert "Incorrect email or password" in response.json()["detail"]
    
    login_data["username"] = "nonexistent@example.com"
    response = client.post("/users/token", data=login_data)
    assert response.status_code == 401
    assert "Incorrect email or password" in response.json()["detail"]

def test_token_expiry(test_db: Session):
    user_data = {
        "email": "expiry_test@example.com",
        "password": "expirypass"
    }
    client.post("/users/", json=user_data)
    
    login_data = {
        "username": "expiry_test@example.com",
        "password": "expirypass"
    }
    
    settings.ACCESS_TOKEN_EXPIRE_MINUTES = 0.01
    
    response = client.post("/users/token", data=login_data)
    token = response.json()["access_token"]
    
    import time
    time.sleep(1)
    
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/users/me", headers=headers)
    assert response.status_code == 401
    assert "Token expired" in response.json()["detail"]

def test_user_update(test_db: Session):
    user_data = {
        "email": "update_test@example.com",
        "password": "updatepass"
    }
    client.post("/users/", json=user_data)
    
    login_data = {
        "username": "update_test@example.com",
        "password": "updatepass"
    }
    token = client.post("/users/token", data=login_data).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    update_data = {"email": "updated@example.com"}
    response = client.put("/users/me", json=update_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == "updated@example.com"
    
    update_data = {"password": "newpassword"}
    response = client.put("/users/me", json=update_data, headers=headers)
    assert response.status_code == 200
    
    login_data["password"] = "newpassword"
    response = client.post("/users/token", data=login_data)
    assert response.status_code == 200

def test_user_delete(test_db: Session):
    user_data = {
        "email": "delete_test@example.com",
        "password": "deletepass"
    }
    client.post("/users/", json=user_data)
    
    login_data = {
        "username": "delete_test@example.com",
        "password": "deletepass"
    }
    token = client.post("/users/token", data=login_data).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.delete("/users/me", headers=headers)
    assert response.status_code == 204
    
    login_response = client.post("/users/token", data=login_data)
    assert login_response.status_code == 401
