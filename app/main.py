from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi_utils.tasks import repeat_every
from app.tasks import update_blacklist, reset_daily_url_count
from app.routes import urls, apps,  users
from app.database import engine, Base

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(urls.router)
app.include_router(users.router)
app.include_router(apps.router)

@app.on_event("startup")
@repeat_every(seconds=24 * 60 * 60)
def scheduled_cleanup():
    update_blacklist()
    reset_daily_url_count()


@app.get("/")
def read_root():
    return {"message": "URL Fishing Check Service"}