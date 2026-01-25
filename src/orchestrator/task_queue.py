"""
Task queue with dependency resolution for orchestrator workflows.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from database import DatabaseManager


TaskAction = Callable[[dict], None]


@dataclass
class Task:
    """Definition for a task in the workflow queue."""

    task_id: str
    name: str
    action: TaskAction
    depends_on: Optional[list[str]] = None


class TaskQueue:
    """Queue runner that enforces task dependencies and status tracking."""

    def __init__(self, db_manager: DatabaseManager, logger: Optional[logging.Logger] = None) -> None:
        self.db_manager = db_manager
        self.logger = logger or logging.getLogger("file_manager")
        self.tasks: list[Task] = []

    def register(self, tasks: Iterable[Task]) -> None:
        """Register tasks and ensure they exist in the state database."""
        for task in tasks:
            self.tasks.append(task)
            self.db_manager.ensure_task(task.task_id, task.name, task.depends_on or [])

    def run(self, context: Optional[dict] = None) -> None:
        """Run tasks in order, enforcing dependency completion."""
        if context is None:
            context = {}
        self.db_manager.reset_in_progress_tasks()
        for task in self.tasks:
            status = self.db_manager.get_task_status(task.task_id)
            if status == "completed":
                self.logger.info("Task already completed: %s", task.name)
                continue
            if not self._dependencies_completed(task):
                self.logger.info("Task blocked by dependencies: %s", task.name)
                continue
            try:
                self.db_manager.update_task_status(task.task_id, "in_progress")
                self.logger.info("Starting task: %s", task.name)
                task.action(context)
                self.db_manager.update_task_status(task.task_id, "completed")
                self.logger.info("Task completed: %s", task.name)
            except Exception as exc:
                self.db_manager.update_task_status(task.task_id, "failed", last_error=str(exc))
                self.logger.exception("Task failed: %s", task.name)
                raise

    def _dependencies_completed(self, task: Task) -> bool:
        if not task.depends_on:
            return True
        for dependency in task.depends_on:
            status = self.db_manager.get_task_status(dependency)
            if status != "completed":
                return False
        return True
