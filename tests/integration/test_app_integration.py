from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from datetime import timedelta

from app.main import app
from app.models import User
from app.schemas import  PhishingResponse
from app.config import settings
from app.utils import create_access_token
from app.database import Base

client = TestClient(app)

@pytest.fixture(scope="module")
def test_db():
    # Setup test database
    SQLALCHEMY_DATABASE_URL = "sqlite:///./test_integration.db"
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    
    test_user = User(
        email="test@example.com",
        hashed_password="$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "secret"
        is_active=True
    )
    db.add(test_user)
    db.commit()
    db.refresh(test_user)
    
    yield db
    
    Base.metadata.drop_all(bind=engine)
    db.close()

@pytest.fixture
def test_user_token(test_db: Session):
    user = test_db.query(User).filter(User.email == "test@example.com").first()
    return create_access_token(data={"sub": user.email})

def test_full_user_flow(test_db: Session):
    user_data = {
        "email": "newuser@example.com",
        "password": "newpassword"
    }
    response = client.post("/users/", json=user_data)
    assert response.status_code == 200
    assert response.json()["email"] == "newuser@example.com"
    
    login_data = {
        "username": "newuser@example.com",
        "password": "newpassword"
    }
    response = client.post("/users/token", data=login_data)
    assert response.status_code == 200
    token = response.json()["access_token"]
    assert token is not None
    
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/users/me", headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == "newuser@example.com"

def test_full_app_flow(test_db: Session, test_user_token: str):
    headers = {"Authorization": f"Bearer {test_user_token}"}
    
    app_data = {"app_name": "integration_test_app"}
    response = client.post("/apps/", json=app_data, headers=headers)
    assert response.status_code == 200
    app_token = response.json()["token"]
    assert app_token is not None
    
    response = client.get("/apps/all", headers=headers)
    assert response.status_code == 200
    apps = response.json()
    assert len(apps) == 1
    assert apps[0]["app_name"] == "integration_test_app"
    
    update_data = {"app_token": app_token, "new_name": "updated_app_name"}
    response = client.put("/apps/", json=update_data, headers=headers)
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    
    response = client.get("/apps/all", headers=headers)
    assert response.json()[0]["app_name"] == "updated_app_name"
    
    delete_data = {"app_token": app_token}
    response = client.delete("/apps/", json=delete_data, headers=headers)
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    
    response = client.get("/apps/all", headers=headers)
    assert len(response.json()) == 0

def test_url_check_flow(test_db: Session, test_user_token: str):
    headers = {"Authorization": f"Bearer {test_user_token}"}
    
    app_data = {"app_name": "url_checker_app"}
    response = client.post("/apps/", json=app_data, headers=headers)
    app_token = response.json()["token"]
    
    with patch("app.routes.urls.get_phishing_detector") as mock_detector:
        mock_detector.return_value.check_url.return_value = PhishingResponse(
            is_phishing=False,
            confidence_level=0.1,
            reason="Safe URL"
        )
        
        url_data = {"url": "http://safe.com", "api_key": app_token}
        response = client.post("/urls/one", json=url_data)
        assert response.status_code == 200
        assert response.json()["is_phishing"] is False
        
        batch_data = {
            "urls": ["http://safe1.com", "http://safe2.com"],
            "api_key": app_token
        }
        response = client.post("/urls/list", json=batch_data)
        assert response.status_code == 200
        assert len(response.json()) == 2
        assert all(not item["is_phishing"] for item in response.json())
    
    history_data = {"token": app_token}
    response = client.post("/urls/history", json=history_data)
    assert response.status_code == 200
    history = response.json()
    assert history["app_name"] == "url_checker_app"
    assert history["all_urls"] == 3  # 1 single + 2 batch
    assert history["phishing_urls"] == 0

def test_url_check_limit(test_db: Session, test_user_token: str):
    headers = {"Authorization": f"Bearer {test_user_token}"}
    
    app_data = {"app_name": "limited_app", "day_limit": 1}
    response = client.post("/apps/", json=app_data, headers=headers)
    app_token = response.json()["token"]
    
    with patch("app.routes.urls.get_phishing_detector") as mock_detector:
        mock_detector.return_value.check_url.return_value = PhishingResponse(
            is_phishing=False,
            confidence_level=0.1,
            reason="Safe URL"
        )
        
        url_data = {"url": "http://safe.com", "api_key": app_token}
        response = client.post("/urls/one", json=url_data)
        assert response.status_code == 200
        
        response = client.post("/urls/one", json=url_data)
        assert response.status_code == 429
        assert "Daily URL limit exceeded" in response.json()["detail"]

def test_batch_url_limit(test_db: Session, test_user_token: str):
    headers = {"Authorization": f"Bearer {test_user_token}"}
    
    app_data = {"app_name": "batch_test_app"}
    response = client.post("/apps/", json=app_data, headers=headers)
    app_token = response.json()["token"]
    
    batch_data = {
        "urls": ["http://test.com"] * (settings.MAX_URLS_IN_BATCH + 1),
        "api_key": app_token
    }
    response = client.post("/urls/list", json=batch_data)
    assert response.status_code == 429
    assert "Batch URL limit exceeded" in response.json()["detail"]

def test_protected_routes(test_db: Session):
    response = client.get("/users/me")
    assert response.status_code == 401
    assert "Not authenticated" in response.json()["detail"]
    
    headers = {"Authorization": "Bearer invalid_token"}
    response = client.get("/users/me", headers=headers)
    assert response.status_code == 401
    assert "Could not validate credentials" in response.json()["detail"]
    
    expired_token = create_access_token(
        data={"sub": "test@example.com"},
        expires_delta=timedelta(minutes=-1)
    )
    headers = {"Authorization": f"Bearer {expired_token}"}
    response = client.get("/users/me", headers=headers)
    assert response.status_code == 401
    assert "Token expired" in response.json()["detail"]
