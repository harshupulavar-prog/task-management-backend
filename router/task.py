import logging

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from database import get_db
from models.task import Task
from models.user import User
from schemas.task import TaskCreate, TaskUpdate, TaskPatch, TaskResponse
from auth import get_current_user
from exceptions import TaskNotFoundException



router = APIRouter()
logger = logging.getLogger(__name__)



@router.get("/tasks", response_model=list[TaskResponse])
def get_tasks(
    completed: bool | None = None,
    skip: int = 0,
    limit: int = 5,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    logger.info(
        "Task list requested (completed=%s, skip=%s, limit=%s)",
        completed,
        skip,
        limit,
    )
    user = db.query(User).filter(
        User.email == current_user
    ).first()

    if user is None:
        logger.warning("Task list rejected: authenticated user record not found")
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    query = db.query(Task).filter(
        Task.user_id == user.id
    )

    if completed is not None:
        query = query.filter(
            Task.completed == completed
        )

    tasks = query.offset(skip).limit(limit).all()
    logger.info("Task list returned %s task(s) (user_id=%s)", len(tasks), user.id)
    return tasks

@router.post(
    "/tasks",
    response_model=TaskResponse,
    status_code=201
)
def create_task(
    task: TaskCreate,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    logger.info("Task creation requested")
    user = db.query(User).filter(
        User.email == current_user
    ).first()

    if user is None:
        logger.warning("Task creation rejected: authenticated user record not found")
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    new_task = Task(
        title=task.title,
        description=task.description,
        completed=False,
        user_id=user.id
    )

    db.add(new_task)
    db.commit()
    db.refresh(new_task)

    logger.info("Task created (task_id=%s, user_id=%s)", new_task.id, user.id)
    return new_task


@router.put("/tasks/{task_id}", response_model=TaskResponse)
def update_task(
    task_id: int,
    task: TaskUpdate,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    logger.info(
        "Task update requested (task_id=%s)",
        task_id,
    )
    user = db.query(User).filter(
        User.email == current_user
    ).first()

    if user is None:
        logger.warning("Task update rejected: authenticated user record not found")
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    existing_task = db.query(Task).filter(
        Task.id == task_id,
        Task.user_id == user.id
    ).first()

    if existing_task is None:
        logger.warning(
            "Task update rejected: task not found for owner (task_id=%s, user_id=%s)",
            task_id,
            user.id,
        )
        raise HTTPException(
            status_code=404,
            detail="Task not found"
        )

    existing_task.title = task.title
    existing_task.description = task.description
    existing_task.completed = task.completed

    db.commit()
    db.refresh(existing_task)

    logger.info("Task updated (task_id=%s, user_id=%s)", task_id, user.id)
    return existing_task


@router.patch("/tasks/{task_id}", response_model=TaskResponse)
def patch_task(
    task_id: int,
    task: TaskPatch,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    logger.info(
        "Task patch requested (task_id=%s)",
        task_id,
    )
    user = db.query(User).filter(
        User.email == current_user
    ).first()

    if user is None:
        logger.warning("Task patch rejected: authenticated user record not found")
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    existing_task = db.query(Task).filter(
        Task.id == task_id,
        Task.user_id == user.id
    ).first()

    if existing_task is None:
        logger.warning(
            "Task patch rejected: task not found for owner (task_id=%s, user_id=%s)",
            task_id,
            user.id,
        )
        raise HTTPException(
            status_code=404,
            detail="Task not found"
        )

    if task.title is not None:
        existing_task.title = task.title

    if task.description is not None:
        existing_task.description = task.description

    if task.completed is not None:
        existing_task.completed = task.completed

    db.commit()
    db.refresh(existing_task)

    logger.info("Task patched (task_id=%s, user_id=%s)", task_id, user.id)
    return existing_task


@router.delete("/tasks/{task_id}")
def delete_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    logger.info(
        "Task deletion requested (task_id=%s)",
        task_id,
    )
    user = db.query(User).filter(
        User.email == current_user
    ).first()

    if user is None:
        logger.warning("Task deletion rejected: authenticated user record not found")
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    existing_task = db.query(Task).filter(
        Task.id == task_id,
        Task.user_id == user.id
    ).first()

    if existing_task is None:
        logger.warning(
            "Task deletion rejected: task not found for owner (task_id=%s, user_id=%s)",
            task_id,
            user.id,
        )
        raise HTTPException(
            status_code=404,
            detail="Task not found"
        )

    db.delete(existing_task)
    db.commit()

    logger.info("Task deleted (task_id=%s, user_id=%s)", task_id, user.id)
    return {
        "message": "Task deleted successfully"
    }