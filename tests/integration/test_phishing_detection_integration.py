import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from unittest.mock import patch

from app.main import app
from app.models import User, App
from app.schemas import PhishingResponse
from app.database import Base
from app.utils import create_access_token

client = TestClient(app)

@pytest.fixture(scope="module")
def test_db():
    # Setup test database
    SQLALCHEMY_DATABASE_URL = "sqlite:///./test_phishing.db"
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    
    test_user = User(
        email="phishing_test@example.com",
        hashed_password="$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "secret"
        is_active=True
    )
    db.add(test_user)
    db.commit()
    db.refresh(test_user)
    
    # Create test app
    test_app = App(
        app_name="phishing_test_app",
        token="test_phishing_token",
        owner_id=test_user.id,
        day_limit=1000
    )
    db.add(test_app)
    db.commit()
    
    yield db
    
    Base.metadata.drop_all(bind=engine)
    db.close()

@pytest.fixture
def test_user_token(test_db: Session):
    user = test_db.query(User).filter(User.email == "phishing_test@example.com").first()
    return create_access_token(data={"sub": user.email})

def test_phishing_detection_blacklist(test_db: Session):
    with patch("app.routes.urls.get_phishing_detector") as mock_detector:
        mock_detector.return_value.check_url.return_value = PhishingResponse(
            is_phishing=True,
            confidence_level=1.0,
            reason="URL in blacklist!"
        )
        
        url_data = {"url": "http://malicious.com", "api_key": "test_phishing_token"}
        response = client.post("/urls/one", json=url_data)
        
        assert response.status_code == 200
        assert response.json()["is_phishing"] is True
        assert response.json()["confidence_level"] == 1.0
        assert "blacklist" in response.json()["reason"]

def test_phishing_detection_rnn(test_db: Session):
    with patch("app.routes.urls.get_phishing_detector") as mock_detector:
        mock_detector.return_value.check_url.return_value = PhishingResponse(
            is_phishing=True,
            confidence_level=0.95,
            reason="Checking in RNN."
        )
        
        url_data = {"url": "http://suspicious.com", "api_key": "test_phishing_token"}
        response = client.post("/urls/one", json=url_data)
        
        assert response.status_code == 200
        assert response.json()["is_phishing"] is True
        assert 0.9 < response.json()["confidence_level"] <= 1.0
        assert "RNN" in response.json()["reason"]

def test_safe_url_detection(test_db: Session):
    with patch("app.routes.urls.get_phishing_detector") as mock_detector:
        mock_detector.return_value.check_url.return_value = PhishingResponse(
            is_phishing=False,
            confidence_level=0.1,
            reason="All checks are ok!"
        )
        
        url_data = {"url": "http://safe.com", "api_key": "test_phishing_token"}
        response = client.post("/urls/one", json=url_data)
        
        assert response.status_code == 200
        assert response.json()["is_phishing"] is False
        assert response.json()["confidence_level"] <= 0.2
        assert "ok" in response.json()["reason"]

def test_batch_phishing_detection(test_db: Session):
    with patch("app.routes.urls.get_phishing_detector") as mock_detector:
        mock_detector.return_value.check_url.side_effect = [
            PhishingResponse(is_phishing=True, confidence_level=0.9, reason="Phishing"),
            PhishingResponse(is_phishing=False, confidence_level=0.1, reason="Safe")
        ]
        
        # Test batch URL check
        batch_data = {
            "urls": ["http://phishing.com", "http://safe.com"],
            "api_key": "test_phishing_token"
        }
        response = client.post("/urls/list", json=batch_data)
        
        assert response.status_code == 200
        results = response.json()
        assert len(results) == 2
        assert results[0]["is_phishing"] is True
        assert results[1]["is_phishing"] is False

def test_history_after_checks(test_db: Session):
    with patch("app.routes.urls.get_phishing_detector") as mock_detector:
        mock_detector.return_value.check_url.return_value = PhishingResponse(
            is_phishing=False,
            confidence_level=0.1,
            reason="Safe"
        )
        
        url_data = {"url": "http://history-test.com", "api_key": "test_phishing_token"}
        client.post("/urls/one", json=url_data)
    
    history_data = {"token": "test_phishing_token"}
    response = client.post("/urls/history", json=history_data)
    
    assert response.status_code == 200
    history = response.json()
    assert history["all_urls"] >= 1
    assert "history-test.com" in history["history_urls"][0]
    assert history["history_results"][0]["is_phishing"] is False
    