from fastapi import Request
from fastapi.responses import JSONResponse


class TaskNotFoundException(Exception):
    def __init__(self, task_id: int):
        self.task_id = task_id


async def task_not_found_handler(
    request: Request,
    exc: TaskNotFoundException
):
    return JSONResponse(
        status_code=404,
        content={
            "success": False,
            "message": f"Task {exc.task_id} not found",
            "status_code": 404
        }
    )