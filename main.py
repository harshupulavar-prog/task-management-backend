from fastapi import FastAPI
from router.task import router

app = FastAPI()

app.include_router(router)