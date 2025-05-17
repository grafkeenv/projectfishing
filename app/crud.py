from datetime import datetime
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import and_, func
from fastapi import status, HTTPException

from app import models, schemas
from app.pass_utils import generate_api_key, get_password_hash


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = get_password_hash(user.password)
    db_user = models.User(
        email=user.email,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def update_user(db: Session, user_id: int, user_update: schemas.UserUpdate):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        return None
    
    update_data = user_update.dict(exclude_unset=True)
    if "password" in update_data:
        update_data["hashed_password"] = get_password_hash(update_data.pop("password"))
    
    for field, value in update_data.items():
        setattr(db_user, field, value)
    
    db.commit()
    db.refresh(db_user)
    return db_user

def delete_user(db: Session, user_id: int):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        return False
    
    db.delete(db_user)
    db.commit()
    return True

def create_app(db: Session, app: schemas.CreateApp, owner_id: int) -> str:
    token = generate_api_key()
    db_app = models.App(
        app_name=app.app_name,
        token=token,
        owner_id=owner_id,
        day_limit=app.day_limit if hasattr(app, 'day_limit') else 1000,
        url_count_on_day=0
    )
    db.add(db_app)
    db.commit()
    return token

def get_app_db(db: Session, token: str) -> bool:
    app_db = db.query(models.App).filter(
        models.App.token == token
    ).first()
    if not app_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="App doesn't find!"
        )
    return app_db

def list_app(db: Session, user_id: int) -> List[models.App]:
    return db.query(models.App).filter(models.App.owner_id==user_id).all() 
    
def delete_app(db: Session, app: schemas.DeleteApp, 
               owner_id: int) -> int:
    app_db: models.App = get_app_db(db, app.app_token)
    if app_db.owner_id != owner_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, 
                              detail="Not authorized!")
    db.delete(app_db)
    db.commit()

def update_app(db: Session, app: schemas.UpdateApp, 
               owner_id: int) -> int:
    app_db: models.App = get_app_db(db, app.app_token)
    if app_db.owner_id != owner_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, 
                              detail="Not authorized!")
    app_db.app_name = app.new_name
    db.commit()

def check_app_counts_limit(db: Session, user_id: int, max_app_counts) -> bool:
    current_app_count = db.query(func.count(models.App.id)).filter(
        models.App.owner_id == user_id
    ).scalar()
    return current_app_count < max_app_counts

def check_owner_app(db: Session, token: str, owner_id: int):
    app_db: models.App = get_app_db(db, token)
    if app_db.owner_id != owner_id:
        return False
    return True
    
def check_url_counts_limit(db: Session, app_id: int) -> bool:
    app = db.query(models.App).filter(models.App.id == app_id).first()
    if app.url_count_on_day < app.day_limit:
        return True
    return False

def add_url_count(db: Session, app_id: int, n: int) -> None:
    app = db.query(models.App).filter(models.App.id == app_id).first()
    if not app:
        raise ValueError(f"App with ID {app_id} not found")
    new_count = min(app.url_count_on_day + n, app.day_limit)
    app.url_count_on_day = new_count
    db.commit()

def get_app_history(
    db: Session, 
    token: str, 
    start_dt: Optional[datetime] = None, 
    end_dt: Optional[datetime] = None
) -> schemas.AppHistory:
    app: models.App = get_app_db(db, token)
    query = db.query(models.UrlStat).filter(models.UrlStat.app_id == app.id)
    if start_dt and end_dt:
        query = query.filter(and_(models.UrlStat.accessed_at >= start_dt, models.UrlStat.accessed_at <= end_dt))
    elif start_dt:
        query = query.filter(models.UrlStat.accessed_at >= start_dt)
    elif end_dt:
        query = query.filter(models.UrlStat.accessed_at <= end_dt)
    
    url_stats = query.order_by(models.UrlStat.accessed_at).all()
    
    history_urls = [stat.url for stat in url_stats]
    history_results = [
        schemas.PhishingResponse(
            is_phishing=stat.is_phishing,
            confidence_level=stat.confidence_level,
            reason=stat.reason
        ) for stat in url_stats
    ]
    
    history_ts = [stat.accessed_at for stat in url_stats]
    
    all_urls = len(url_stats)
    phishing_urls = sum(1 for stat in url_stats if stat.is_phishing)
    
    return schemas.AppHistory(
        app_name=app.app_name,
        all_urls=all_urls,
        phishing_urls=phishing_urls,
        day_limit=app.day_limit,
        day_limit_remaining=app.day_limit - app.url_count_on_day,
        history_urls=history_urls,
        history_results=history_results,
        history_ts=history_ts
    )
    
def create_url_stat(
    db: Session,
    url: str,
    is_phishing: bool,
    confidence_level: float,
    reason: str,
    app_id: int
):
    url_stat = models.UrlStat(
        url=url,
        is_phishing=is_phishing,
        confidence_level=confidence_level,
        reason=reason,
        app_id=app_id
    )
    
    db.add(url_stat)
    db.commit()