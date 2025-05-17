from fastapi import APIRouter, Depends, HTTPException, status
from typing import List

from sqlalchemy.orm import Session
from sqlalchemy import exc

from app import crud, schemas
from app.database import get_db
from app.utils import get_current_user
from app.models import User
from app.config import settings

router = APIRouter(prefix="/apps")

@router.post("/", response_model=schemas.AppToken)
def create_new_app(
    app_data: schemas.CreateApp,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Регистрация нового приложения с получением токена. Требует регистрации пользователя."""
    try:
        if not crud.check_app_counts_limit(db, current_user.id, settings.USER_APP_LIMITS):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, 
                                detail=f"Maximum app limit reached ({settings.USER_APP_LIMITS} apps per user)")
        token = crud.create_app(db, app_data, current_user.id)
        return schemas.AppToken(token=token)
    except exc.SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error occurred"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.delete("/")
def delete_app(
    app_data: schemas.DeleteApp,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Удаление приложения. Требует реггистрации."""
    try:
        crud.delete_app(db, app_data, current_user.id)
        return {'status': 'ok'}
    except exc.SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error occurred"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.put("/")
def put_app(
    app_data: schemas.UpdateApp,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Изменение названия приложения. Требует регистрации."""
    try:
        crud.update_app(db, app_data, current_user.id)
        return {'status': 'ok'}  
    except exc.SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error occurred"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get("/all", response_model = List[schemas.AppInfo])
def list_app(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Отображение информации по всем приложениям пользователя."""
    try:
        results = crud.list_app(db, current_user.id)
        return [schemas.AppInfo(app_name=app.app_name,
                                token=app.token, 
                                day_limit=app.day_limit, 
                                url_count_on_day=app.url_count_on_day) for app in results]
    except exc.SQLAlchemyError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error occurred"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
