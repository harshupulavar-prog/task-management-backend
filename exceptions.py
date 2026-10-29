import logging

from fastapi import Request
from fastapi.responses import JSONResponse


logger = logging.getLogger(__name__)


class TaskNotFoundException(Exception):
    def __init__(self, task_id: int):
        self.task_id = task_id


async def task_not_found_handler(
    request: Request,
    exc: TaskNotFoundException
):
    logger.warning(
        "Task not found (method=%s, path=%s, task_id=%s)",
        request.method,
        request.url.path,
        exc.task_id,
    )
    return JSONResponse(
        status_code=404,
        content={
            "success": False,
            "message": f"Task {exc.task_id} not found",
            "status_code": 404
        }
    )