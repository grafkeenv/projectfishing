from typing import List
from fastapi import APIRouter, Depends, HTTPException, status

from sqlalchemy.orm import Session
from sqlalchemy import exc

from app import crud, schemas, models
from app.database import get_db
from app.phishing_detect import PhishingDetector, get_phishing_detector
from app.config import settings

router = APIRouter(prefix="/urls")

@router.post("/one", response_model=schemas.PhishingResponse)
def check_one_url(
    request: schemas.URLRequest,
    db: Session = Depends(get_db),
    detector: PhishingDetector = Depends(get_phishing_detector)
):
    """Проверка одиночной ссылки на фишинг."""
    url = request.url
    api_key = request.api_key
    try:
        app_db: models.App = crud.get_app_db(db, api_key)
        if not crud.check_url_counts_limit(db, app_db.id):
            raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Daily URL limit exceeded")
        result = detector.check_url(url)
        crud.add_url_count(db, app_db.id, 1)
        crud.create_url_stat(db, url, result.is_phishing, result.confidence_level, result.reason, app_db.id)
        return result
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

@router.post("/list", response_model=List[schemas.PhishingResponse])
def check_url_list(
    request: schemas.BatchURLRequest,
    db: Session = Depends(get_db),
    detector: PhishingDetector = Depends(get_phishing_detector)
):
    """Проверка ссылок в пакетном  режиме."""
    api_key = request.api_key
    urls = request.urls
    if len(urls) > settings.MAX_URLS_IN_BATCH:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Batch URL limit exceeded! Max count urls in batch: {settings.MAX_URLS_IN_BATCH}")
    try:
        app_db: models.App = crud.get_app_db(db, api_key)
        if not crud.check_url_counts_limit(db, app_db.id):
            raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Daily URL limit exceeded")
        results = [detector.check_url(url) for url in urls]
        for url, result in zip(urls, results):
            crud.create_url_stat(db, url, result.is_phishing, result.confidence_level, result.reason, app_db.id)
        crud.add_url_count(db, app_db.id, 1)
        return results
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

@router.post("/history", response_model=schemas.AppHistory)
def history(request: schemas.AppHistoryRequest,
            db: Session = Depends(get_db)):
    """Получение истории проверки ссылок для приложения."""
    try:
        token = request.token
        start_dt = request.start_dt
        end_dt = request.end_dt
        return crud.get_app_history(db, token, start_dt, end_dt)
    except exc.SQLAlchemyError as e:
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