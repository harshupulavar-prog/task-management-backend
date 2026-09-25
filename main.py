import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from database import engine, Base
from models.task import Task
from models.user import User
from router import task
from router import user

from exceptions import (
    TaskNotFoundException,
    task_not_found_handler
)


logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)


app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://task-management-frontend-m1409xjlp-harshupulavar-prog.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



Base.metadata.create_all(bind=engine)


app.include_router(task.router)
app.include_router(user.router)


app.add_exception_handler(
    TaskNotFoundException,
    task_not_found_handler
)


@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception
):
    logger.error(f"Unexpected error: {exc}")

    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error"
        }
    )


@app.middleware("http")
async def log_requests(request: Request, call_next):

    logger.info(
        f"Incoming request: {request.method} {request.url.path}"
    )

    response = await call_next(request)

    logger.info(
        f"Response status: {response.status_code}"
    )

    return response


@app.get("/")
def home():
    return {
        "message": "Welcome to Task API"
    }