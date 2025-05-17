from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Float
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from app.database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    apps = relationship("App", back_populates="owner")

class App(Base):
    __tablename__ = 'apps'
    id = Column(Integer, primary_key=True, index=True)
    app_name = Column(String, unique=True, index=True)
    token = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    owner = relationship("User", back_populates="apps")
    day_limit = Column(Integer, nullable=False, default=1000)
    url_count_on_day = Column(Integer, nullable=False, default=0)
    stats = relationship('UrlStat', back_populates='app')
    
class UrlStat(Base):
    __tablename__ = "link_stats"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    accessed_at = Column(DateTime(timezone=True), server_default=func.now())
    is_phishing = Column(Boolean, nullable=False, default=True)
    confidence_level = Column(Float, nullable=False, default=0.0)
    reason = Column(String, nullable=False, default='')
    app_id = Column(Integer, ForeignKey("apps.id"), nullable=True)
    app = relationship("App", back_populates="stats")

