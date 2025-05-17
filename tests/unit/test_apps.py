import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.routes.apps import router
from app.schemas import CreateApp, AppToken, AppInfo, DeleteApp, UpdateApp
from app.models import User, App
from app.crud import check_app_counts_limit
from app.config import settings

@pytest.fixture
def mock_db():
    return MagicMock(spec=Session)

@pytest.fixture
def mock_user():
    user = MagicMock(spec=User)
    user.id = 1
    user.email = "test@example.com"
    return user

@pytest.fixture
def mock_app():
    app = MagicMock(spec=App)
    app.id = 1
    app.app_name = "test_app"
    app.token = "test_token"
    app.owner_id = 1
    app.day_limit = 1000
    app.url_count_on_day = 0
    return app

def test_create_new_app_success(mock_db, mock_user):
    # Arrange
    app_data = CreateApp(app_name="test_app")
    mock_db.query.return_value.filter.return_value.count.return_value = 0
    mock_db.add.return_value = None
    mock_db.commit.return_value = None
    mock_db.refresh.return_value = None
    
    # Act
    with patch('app.pass_utils.generate_api_key', return_value="test_token"):
        response = router.create_new_app(app_data, mock_db, mock_user)
    
    # Assert
    assert isinstance(response, AppToken)
    assert response.token == "test_token"
    mock_db.add.assert_called_once()
    mock_db.commit.assert_called_once()

def test_create_new_app_limit_reached(mock_db, mock_user):
    # Arrange
    app_data = CreateApp(app_name="test_app")
    mock_db.query.return_value.filter.return_value.count.return_value = settings.USER_APP_LIMITS
    
    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        router.create_new_app(app_data, mock_db, mock_user)
    
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert f"Maximum app limit reached ({settings.USER_APP_LIMITS} apps per user)" in str(exc_info.value.detail)

def test_create_new_app_db_error(mock_db, mock_user):
    # Arrange
    app_data = CreateApp(app_name="test_app")
    mock_db.query.return_value.filter.return_value.count.side_effect = Exception("DB error")
    
    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        router.create_new_app(app_data, mock_db, mock_user)
    
    assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert "Database error occurred" in str(exc_info.value.detail)

def test_delete_app_success(mock_db, mock_user, mock_app):
    # Arrange
    app_data = DeleteApp(app_token="test_token")
    mock_db.query.return_value.filter.return_value.first.return_value = mock_app
    
    # Act
    response = router.delete_app(app_data, mock_db, mock_user)
    
    # Assert
    assert response == {'status': 'ok'}
    mock_db.delete.assert_called_once_with(mock_app)
    mock_db.commit.assert_called_once()

def test_delete_app_not_found(mock_db, mock_user):
    # Arrange
    app_data = DeleteApp(app_token="invalid_token")
    mock_db.query.return_value.filter.return_value.first.return_value = None
    
    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        router.delete_app(app_data, mock_db, mock_user)
    
    assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
    assert "App doesn't find!" in str(exc_info.value.detail)

def test_update_app_success(mock_db, mock_user, mock_app):
    # Arrange
    app_data = UpdateApp(app_token="test_token", new_name="new_name")
    mock_db.query.return_value.filter.return_value.first.return_value = mock_app
    
    # Act
    response = router.put_app(app_data, mock_db, mock_user)
    
    # Assert
    assert response == {'status': 'ok'}
    assert mock_app.app_name == "new_name"
    mock_db.commit.assert_called_once()

def test_list_app_success(mock_db, mock_user, mock_app):
    # Arrange
    mock_db.query.return_value.filter.return_value.all.return_value = [mock_app]
    
    # Act
    response = router.list_app(mock_db, mock_user)
    
    # Assert
    assert isinstance(response, list)
    assert len(response) == 1
    assert isinstance(response[0], AppInfo)
    assert response[0].app_name == "test_app"

def test_check_app_counts_limit_true(mock_db):
    # Arrange
    mock_db.query.return_value.filter.return_value.count.return_value = 5
    
    # Act
    result = check_app_counts_limit(mock_db, 1, 10)
    
    # Assert
    assert result is True

def test_check_app_counts_limit_false(mock_db):
    # Arrange
    mock_db.query.return_value.filter.return_value.count.return_value = 10
    
    # Act
    result = check_app_counts_limit(mock_db, 1, 10)
    
    # Assert
    assert result is False

