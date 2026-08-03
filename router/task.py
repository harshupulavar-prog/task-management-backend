from fastapi import APIRouter, status
from schemas.task import TaskCreate, TaskResponse

router = APIRouter()

tasks = []

@router.get("/")
def home():
    return {"message": "Welcome to FastAPI"}

@router.get("/tasks")
def get_tasks():
    return tasks

@router.post("/tasks", response_model=TaskResponse, status_code=status.HTTP_201_CREATED)
def create_task(task: TaskCreate):

    new_task = {
        "id": len(tasks) + 1,
        "title": task.title,
        "completed": False
    }

    tasks.append(new_task)

    return new_task