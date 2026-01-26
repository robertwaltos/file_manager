"""
Task queue with dependency resolution for orchestrator workflows.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from config import AppConfig
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

    def __init__(
        self,
        db_manager: DatabaseManager,
        logger: Optional[logging.Logger] = None,
        config: Optional[AppConfig] = None,
    ) -> None:
        self.db_manager = db_manager
        self.logger = logger or logging.getLogger("file_manager")
        self.config = config
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
            if self._requires_approval(task) and not self._is_approved(task):
                env_key = f"FILE_MANAGER_APPROVE_{task.task_id.upper()}"
                self.logger.warning(
                    "Task awaiting approval: %s. Set %s=1 or safety.phase_approvals.%s: true",
                    task.name,
                    env_key,
                    task.task_id,
                )
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

    def _requires_approval(self, task: Task) -> bool:
        if self.config is None:
            return False
        require_approval = bool(
            self.config.get("safety", "require_phase_approval", default=False)
        )
        if not require_approval:
            return False
        approval_tasks = self.config.get("safety", "phase_approval_tasks", default=[])
        if approval_tasks:
            return task.task_id in approval_tasks
        return True

    def _is_approved(self, task: Task) -> bool:
        if os.environ.get("FILE_MANAGER_APPROVE_ALL", "").lower() in {"1", "true", "yes"}:
            return True
        env_key = f"FILE_MANAGER_APPROVE_{task.task_id.upper()}"
        if os.environ.get(env_key, "").lower() in {"1", "true", "yes"}:
            return True
        if self.config is None:
            return False
        approvals = self.config.get("safety", "phase_approvals", default={})
        return bool(approvals.get(task.task_id, False))
