import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.routes.users import router
from app.schemas import UserCreate, Token, UserUpdate
from app.models import User as UserModel
from app.crud import get_user_by_email, create_user
from app.pass_utils import get_password_hash

@pytest.fixture
def mock_db():
    return MagicMock(spec=Session)

@pytest.fixture
def mock_user():
    user = MagicMock(spec=UserModel)
    user.id = 1
    user.email = "test@example.com"
    user.hashed_password = get_password_hash("password")
    user.is_active = True
    return user

def test_get_user_by_email_found(mock_db, mock_user):
    # Arrange
    mock_db.query.return_value.filter.return_value.first.return_value = mock_user
    
    # Act
    result = get_user_by_email(mock_db, "test@example.com")
    
    # Assert
    assert result == mock_user

def test_get_user_by_email_not_found(mock_db):
    # Arrange
    mock_db.query.return_value.filter.return_value.first.return_value = None
    
    # Act
    result = get_user_by_email(mock_db, "nonexistent@example.com")
    
    # Assert
    assert result is None

def test_create_user_success(mock_db):
    # Arrange
    user_data = UserCreate(email="new@example.com", password="password")
    mock_db.query.return_value.filter.return_value.first.return_value = None
    
    # Act
    result = create_user(mock_db, user_data)
    
    # Assert
    assert result.email == "new@example.com"
    assert hasattr(result, "hashed_password")
    mock_db.add.assert_called_once()
    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once()

def test_create_user_email_exists(mock_db, mock_user):
    # Arrange
    user_data = UserCreate(email="test@example.com", password="password")
    mock_db.query.return_value.filter.return_value.first.return_value = mock_user
    
    # Act & Assert
    with pytest.raises(HTTPException) as exc_info:
        create_user(mock_db, user_data)
    
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert "Email already registered" in str(exc_info.value.detail)

def test_login_for_access_token_success(mock_db, mock_user):
    # Arrange
    form_data = MagicMock()
    form_data.username = "test@example.com"
    form_data.password = "password"
    
    with patch('app.crud.get_user_by_email', return_value=mock_user):
        with patch('app.pass_utils.verify_password', return_value=True):
            # Act
            response = router.login_for_access_token(form_data, mock_db)
    
    # Assert
    assert isinstance(response, Token)
    assert response.token_type == "bearer"

def test_login_for_access_token_invalid_credentials(mock_db):
    # Arrange
    form_data = MagicMock()
    form_data.username = "wrong@example.com"
    form_data.password = "wrong"
    
    with patch('app.crud.get_user_by_email', return_value=None):
        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            router.login_for_access_token(form_data, mock_db)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Incorrect email or password" in str(exc_info.value.detail)

def test_read_users_me(mock_user):
    # Arrange
    current_user = mock_user
    
    # Act
    response = router.read_users_me(current_user)
    
    # Assert
    assert response.email == "test@example.com"

def test_update_user_me_success(mock_db, mock_user):
    # Arrange
    user_update = UserUpdate(email="new@example.com", password="newpassword")
    mock_db.query.return_value.filter.return_value.first.return_value = None
    
    # Act
    response = router.update_user_me(user_update, mock_db, mock_user)
    
    # Assert
    assert response.email == "new@example.com"
    mock_db.commit.assert_called_once()

def test_delete_user_me_success(mock_db, mock_user):
    # Act
    response = router.delete_user_me(mock_db, mock_user)
    
    # Assert
    assert response is None
    mock_db.delete.assert_called_once_with(mock_user)
    mock_db.commit.assert_called_once()
    