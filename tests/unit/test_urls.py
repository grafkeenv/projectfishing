import pytest
from unittest.mock import MagicMock
from fastapi import HTTPException, status
from datetime import datetime
from sqlalchemy.orm import Session

from app.routes.urls import router
from app.schemas import URLRequest, BatchURLRequest, PhishingResponse, AppHistoryRequest
from app.models import App, UrlStat
from app.crud import (
    get_app_db,
    check_url_counts_limit,
)
from app.phishing_detect import PhishingDetector
from app.config import settings

@pytest.fixture
def mock_db():
    return MagicMock(spec=Session)

@pytest.fixture
def mock_app():
    app = MagicMock(spec=App)
    app.id = 1
    app.day_limit = 1000
    app.url_count_on_day = 0
    return app

@pytest.fixture
def mock_detector():
    detector = MagicMock(spec=PhishingDetector)
    detector.check_url.return_value = PhishingResponse(
        is_phishing=True,
        confidence_level=0.95,
        reason="Test reason"
    )
    return detector

def test_check_one_url_success(mock_db, mock_app, mock_detector):
    # Arrange
    request = URLRequest(url="http://test.com", api_key="test_key")
    mock_db.query.return_value.filter.return_value.first.return_value = mock_app
    
    # Act
    response = router.check_one_url(request, mock_db, mock_detector)
    
    # Assert
    assert isinstance(response, PhishingResponse)
    assert response.is_phishing is True
    mock_detector.check_url.assert_called_once_with("http://test.com")
    mock_db.commit.assert_called_once()

def test_check_one_url_limit_exceeded(mock_db, mock_app, mock_detector):
    # Arrange
    request = URLRequest(url="http://test.com", api_key="test_key")
    mock_app.url_count_on_day = 1000
    mock_db.query.return_value.filter.return_value.first.return_value = mock_app
    
    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        router.check_one_url(request, mock_db, mock_detector)
    
    assert exc_info.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "Daily URL limit exceeded" in str(exc_info.value.detail)

def test_check_url_list_success(mock_db, mock_app, mock_detector):
    # Arrange
    request = BatchURLRequest(urls=["http://test1.com", "http://test2.com"], api_key="test_key")
    mock_db.query.return_value.filter.return_value.first.return_value = mock_app
    
    # Act
    response = router.check_url_list(request, mock_db, mock_detector)
    
    # Assert
    assert isinstance(response, list)
    assert len(response) == 2
    assert all(isinstance(item, PhishingResponse) for item in response)
    assert mock_detector.check_url.call_count == 2
    mock_db.commit.assert_called_once()

def test_check_url_list_batch_limit_exceeded(mock_db, mock_detector):
    # Arrange
    urls = ["http://test.com"] * (settings.MAX_URLS_IN_BATCH + 1)
    request = BatchURLRequest(urls=urls, api_key="test_key")
    
    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        router.check_url_list(request, mock_db, mock_detector)
    
    assert exc_info.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert f"Batch URL limit exceeded! Max count urls in batch: {settings.MAX_URLS_IN_BATCH}" in str(exc_info.value.detail)

def test_history_success(mock_db):
    # Arrange
    request = AppHistoryRequest(token="test_token")
    mock_app = MagicMock(spec=App)
    mock_app.id = 1
    mock_app.app_name = "test_app"
    mock_app.day_limit = 1000
    mock_app.url_count_on_day = 100
    
    mock_url_stat = MagicMock(spec=UrlStat)
    mock_url_stat.url = "http://test.com"
    mock_url_stat.is_phishing = True
    mock_url_stat.confidence_level = 0.95
    mock_url_stat.reason = "Test reason"
    mock_url_stat.accessed_at = datetime.now()
    mock_url_stat.app_id = 1
    
    mock_db.query.return_value.filter.return_value.first.return_value = mock_app
    mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [mock_url_stat]
    
    # Act
    response = router.history(request, mock_db)
    
    # Assert
    assert response.app_name == "test_app"
    assert response.all_urls == 1
    assert response.phishing_urls == 1
    assert response.day_limit_remaining == 900
    assert len(response.history_urls) == 1

def test_get_app_db_found(mock_db, mock_app):
    # Arrange
    mock_db.query.return_value.filter.return_value.first.return_value = mock_app
    
    # Act
    result = get_app_db(mock_db, "test_token")
    
    # Assert
    assert result == mock_app

def test_get_app_db_not_found(mock_db):
    # Arrange
    mock_db.query.return_value.filter.return_value.first.return_value = None
    
    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        get_app_db(mock_db, "invalid_token")
    
    assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
    assert "App doesn't find!" in str(exc_info.value.detail)

def test_check_url_counts_limit_true(mock_db, mock_app):
    # Arrange
    mock_app.url_count_on_day = 999
    mock_db.query.return_value.filter.return_value.first.return_value = mock_app
    
    # Act
    result = check_url_counts_limit(mock_db, 1)
    
    # Assert
    assert result is True

def test_check_url_counts_limit_false(mock_db, mock_app):
    # Arrange
    mock_app.url_count_on_day = 1000
    mock_db.query.return_value.filter.return_value.first.return_value = mock_app
    
    # Act
    result = check_url_counts_limit(mock_db, 1)
    
    # Assert
    assert result is False
    
