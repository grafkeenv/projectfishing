import os
from urllib.parse import urljoin
import requests
from datetime import datetime
from sqlalchemy import update
from app.database import SessionLocal
from app.models import App
from app.config import settings


session = SessionLocal()

def update_blacklist():
    os.makedirs(settings.DOWNLOAD_DIR, exist_ok=True)
    
    files_to_download = {
        settings.BLACKLIST_DOMAINS_FILE: os.path.join(settings.DOWNLOAD_DIR, 
                                                      settings.BLACKLIST_DOMAINS_FILE),
        settings.BLACKLIST_IPS_FILE: os.path.join(settings.DOWNLOAD_DIR,
                                                  settings.BLACKLIST_IPS_FILE),
        settings.BLACKLIST_URLS_FILE: os.path.join(settings.DOWNLOAD_DIR, 
                                                   settings.BLACKLIST_URLS_FILE)
    }
    
    for filename, save_path in files_to_download.items():
        try:
            file_url = urljoin(settings.BLACKLIST_DOWNLOAD_URL, filename)
            
            response = requests.get(file_url, timeout=settings.TIMEOUT)
            response.raise_for_status()           
            with open(save_path, 'wb') as f:
                f.write(response.content)        
        except requests.exceptions.RequestException as e:
            raise
        except Exception as e:
            raise

def reset_daily_url_count():
    try:
        session.execute(
            update(App)
            .values(url_count_on_day=0)
        )
        session.commit()
        return {"status": "success", "reset_at": datetime.now(), 
                "affected_rows": session.query(App).count()}
    except Exception as e:
        session.rollback()
        raise e
