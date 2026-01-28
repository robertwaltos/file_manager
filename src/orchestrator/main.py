
"""
Primary orchestration entry point for the file management system.
"""

from __future__ import annotations

import os
import time
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from ai import AiCategorizationEngine
from cloud import GoogleDriveDedupeEngine, GoogleDriveUploadEngine
from config import AppConfig, ensure_directories
from database import DatabaseManager
from dashboard import DashboardServer
from discovery.scanner import Scanner
from corruption.handler import CorruptionMover
from corruption.validator import CorruptionValidator
from duplicates.engine import DuplicateEngine
from duplicates.plan import DuplicatePlanEngine
from hashing.engine import HashingEngine
from nsfw import NsfwMover
from operations import RollbackManager
from organization import OrganizationPlanEngine
from orchestrator.task_queue import Task, TaskQueue
from thumbnails import ThumbnailCleanupEngine
from tools.merge_folders import run_merge_job
from utils import ActivityTracker, ProgressReporter, ResourceMonitor, StallMonitor, setup_logging


class Orchestrator:
    """Coordinate discovery, hashing, and state persistence workflows."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.db_paths = self._build_db_paths()
        self.db_manager = DatabaseManager(self.db_paths)
        self.loggers = setup_logging(self.config.resolve_path("paths", "logs", default="logs"))
        self.logger = self.loggers["main"]
        self.movement_logger = self.loggers["movement"]
        self.logger.info("Python executable: %s", os.environ.get("PYTHONEXECUTABLE", "") or os.sys.executable)
        self.resource_monitor = ResourceMonitor(
            max_cpu_percent=float(self.config.get("resource_limits", "max_cpu_percent", default=33)),
            max_ram_percent=float(self.config.get("resource_limits", "max_ram_percent", default=33)),
            max_throttle_seconds=float(
                self.config.get("resource_limits", "max_throttle_seconds", default=15)
            ),
            min_check_interval_seconds=float(
                self.config.get("resource_limits", "min_check_interval_seconds", default=0.5)
            ),
        )
        self.activity_tracker = ActivityTracker(
            min_interval_seconds=float(
                self.config.get("safety", "activity_min_interval_seconds", default=2.0)
            )
        )
        self.stall_monitor = StallMonitor(
            tracker=self.activity_tracker,
            logger=self.logger,
            warning_seconds=float(
                self.config.get("safety", "stall_warning_seconds", default=600)
            ),
            abort_seconds=float(
                self.config.get("safety", "stall_abort_seconds", default=0)
            ),
            check_interval_seconds=float(
                self.config.get("safety", "stall_check_interval_seconds", default=30)
            ),
        )
        self.progress_reporter = ProgressReporter(
            self.db_paths,
            logger=self.loggers["performance"],
            interval_seconds=int(self.config.get("dashboard", "interval_seconds", default=30)),
            enabled=bool(self.config.get("dashboard", "enabled", default=True)),
        )
        self.web_dashboard_enabled = bool(self.config.get("dashboard", "web_enabled", default=False))
        self.dashboard_server = DashboardServer(
            self.db_paths,
            host=str(self.config.get("dashboard", "web_host", default="127.0.0.1")),
            port=int(self.config.get("dashboard", "web_port", default=8765)),
            logger=self.logger,
        )
        self.scanner = Scanner(config, self.db_manager)
        self.hashing_engine = HashingEngine(
            config,
            self.db_manager,
            self.logger,
            monitor=self.resource_monitor,
            activity_tracker=self.activity_tracker,
        )
        self.corruption_mover = CorruptionMover(
            config,
            self.db_manager,
            logger=self.logger,
            movement_logger=self.movement_logger,
            monitor=self.resource_monitor,
            activity_tracker=self.activity_tracker,
        )
        self.corruption_validator = CorruptionValidator(
            config,
            self.db_manager,
            logger=self.logger,
            monitor=self.resource_monitor,
            activity_tracker=self.activity_tracker,
        )
        self.ai_engine = AiCategorizationEngine(
            config,
            self.db_manager,
            logger=self.logger,
            monitor=self.resource_monitor,
            activity_tracker=self.activity_tracker,
        )
        self.nsfw_mover = NsfwMover(
            config,
            self.db_manager,
            logger=self.logger,
            movement_logger=self.movement_logger,
            monitor=self.resource_monitor,
            activity_tracker=self.activity_tracker,
        )
        self.organization_engine = OrganizationPlanEngine(
            config,
            self.db_manager,
            logger=self.logger,
            movement_logger=self.movement_logger,
            monitor=self.resource_monitor,
            activity_tracker=self.activity_tracker,
        )
        self.drive_dedupe_engine = GoogleDriveDedupeEngine(
            config, logger=self.logger, activity_tracker=self.activity_tracker
        )
        self.drive_upload_engine = GoogleDriveUploadEngine(
            config, logger=self.logger, activity_tracker=self.activity_tracker
        )
        self.latest_organization_plan: Optional[Path] = None
        self.thumbnail_engine = ThumbnailCleanupEngine(
            config,
            self.db_manager,
            logger=self.logger,
            movement_logger=self.movement_logger,
            monitor=self.resource_monitor,
            activity_tracker=self.activity_tracker,
        )
        self.duplicate_engine = DuplicateEngine(
            config,
            self.db_manager,
            self.logger,
            monitor=self.resource_monitor,
            activity_tracker=self.activity_tracker,
        )
        self.duplicate_plan_engine = DuplicatePlanEngine(
            config,
            self.db_manager,
            logger=self.logger,
            movement_logger=self.movement_logger,
            monitor=self.resource_monitor,
            activity_tracker=self.activity_tracker,
        )
        self.rollback_manager = RollbackManager(
            self.db_manager, logger=self.logger, monitor=self.resource_monitor
        )
        self.task_queue = TaskQueue(
            self.db_manager,
            logger=self.logger,
            config=self.config,
            activity_tracker=self.activity_tracker,
        )
        self.checkpoint_interval = int(
            self.config.get("safety", "checkpoint_interval_seconds", default=300)
        )
        self.checkpoint_after_files = int(self.config.get("safety", "checkpoint_after_files", default=500))

    def run(self) -> None:
        """Run discovery and hashing workflows with checkpointing."""
        self.db_manager.initialize()
        self._ensure_paths()
        try:
            self._log_optional_dependency_warnings()
            self._enforce_resume_confirmation()
            self._maybe_run_rollback()
            self.activity_tracker.touch("startup")
            self.stall_monitor.start()
            self.progress_reporter.start()
            if self.web_dashboard_enabled:
                self.dashboard_server.start()
            context: dict = {}
            if bool(self.config.get("task_queue", "reset_on_start", default=True)):
                self.db_manager.reset_task_statuses()
            self.task_queue.register(self._build_tasks())
            self.task_queue.run(context)
        finally:
            if self.web_dashboard_enabled:
                self.dashboard_server.stop()
            self.progress_reporter.stop()
            self.stall_monitor.stop()
            self.db_manager.close()

    def _build_tasks(self) -> list[Task]:
        return [
            Task(task_id="folder_merge", name="Folder Merge", action=lambda ctx: self._run_folder_merges()),
            Task(
                task_id="scan",
                name="Scan Files",
                action=lambda ctx: self._run_scan(),
                depends_on=["folder_merge"],
            ),
            Task(
                task_id="thumbnails",
                name="Thumbnail Cleanup",
                action=lambda ctx: self._run_thumbnail_cleanup(),
                depends_on=["scan"],
            ),
            Task(
                task_id="hashing",
                name="Hash Files",
                action=lambda ctx: self._run_hashing(),
                depends_on=["scan"],
            ),
            Task(
                task_id="corruption_validation",
                name="Validate Corruptions",
                action=lambda ctx: self._run_corruption_validation(),
                depends_on=["hashing"],
            ),
            Task(
                task_id="corruption_quarantine",
                name="Quarantine Corruptions",
                action=lambda ctx: self._run_corruption_quarantine(),
                depends_on=["corruption_validation"],
            ),
            Task(
                task_id="duplicates",
                name="Detect Duplicates",
                action=lambda ctx: ctx.__setitem__("duplicate_report_path", self._run_duplicates().report_path),
                depends_on=["hashing"],
            ),
            Task(
                task_id="duplicate_plan",
                name="Plan Duplicate Moves",
                action=lambda ctx: self._run_duplicate_plan(ctx.get("duplicate_report_path")),
                depends_on=["duplicates"],
            ),
            Task(
                task_id="ai_categorization",
                name="AI Categorization",
                action=lambda ctx: self._run_ai_categorization(),
                depends_on=["duplicate_plan"],
            ),
            Task(
                task_id="nsfw_quarantine",
                name="NSFW Quarantine",
                action=lambda ctx: self._run_nsfw_quarantine(),
                depends_on=["ai_categorization"],
            ),
            Task(
                task_id="organization_plan",
                name="Organization Plan",
                action=lambda ctx: self._run_organization_plan(),
                depends_on=["nsfw_quarantine"],
            ),
            Task(
                task_id="drive_upload",
                name="Google Drive Upload",
                action=lambda ctx: self._run_drive_upload(),
                depends_on=["organization_plan"],
            ),
            Task(
                task_id="cloud_dedupe",
                name="Google Drive Dedupe",
                action=lambda ctx: self._run_cloud_dedupe(),
                depends_on=["drive_upload"],
            ),
            Task(
                task_id="permission_summary",
                name="Permission Summary",
                action=lambda ctx: self._log_permission_issue_summary(),
                depends_on=["scan"],
            ),
            Task(
                task_id="permission_retry",
                name="Permission Retry",
                action=lambda ctx: self._retry_permission_issues(),
                depends_on=["permission_summary"],
            ),
        ]

    def _run_folder_merges(self) -> None:
        merge_enabled = bool(self.config.get("merge_jobs", "enabled", default=False))
        jobs = self.config.get("merge_jobs", "jobs", default=[])
        if not merge_enabled or not jobs:
            self.logger.info("Folder merge disabled or no merge jobs configured.")
            return

        for job in jobs:
            if not isinstance(job, dict):
                self.logger.warning("Skipping merge job with invalid configuration: %s", job)
                continue
            if not job.get("enabled", True):
                continue
            name = str(job.get("name", "merge_job"))
            source = job.get("source")
            target = job.get("target")
            if not source or not target:
                self.logger.warning("Merge job missing source/target: %s", name)
                continue
            source_path = Path(source)
            target_path = Path(target)
            if not source_path.exists():
                self.logger.info(
                    "Merge source missing; skipping job (%s): %s", name, source_path
                )
                continue
            if not target_path.exists():
                self.logger.warning(
                    "Merge target missing; skipping job (%s): %s", name, target_path
                )
                continue
            inbox = job.get("inbox_root")
            report_path = job.get("report_path")
            apply_moves = bool(job.get("apply", False))
            delete_old = bool(job.get("delete_old", False))

            operation_id = self.db_manager.start_operation("folder_merge", details=name)
            try:
                result = run_merge_job(
                    self.config,
                    source_root=source_path,
                    target_root=target_path,
                    inbox_root=Path(inbox) if inbox else None,
                    apply=apply_moves,
                    delete_old=delete_old,
                    report_path=Path(report_path) if report_path else None,
                    logger=self.logger,
                    job_name=name,
                )
                self.db_manager.update_operation_details(operation_id, str(result.report_path))
                self.db_manager.complete_operation(operation_id, status="completed")
                self.logger.info(
                    "Folder merge complete (%s). Moved=%s Skipped=%s Errors=%s Report=%s",
                    name,
                    result.moved,
                    result.skipped,
                    result.errors,
                    result.report_path,
                )
            except Exception:
                self.db_manager.complete_operation(operation_id, status="failed")
                self.logger.exception("Folder merge failed (%s).", name)
                raise

    def _run_scan(self) -> None:
        resume_operation = self.db_manager.get_latest_incomplete_operation("scan")
        checkpoint = None
        if resume_operation:
            operation_id = resume_operation["operation_id"]
            checkpoint = self.db_manager.get_checkpoint(operation_id, "discovery")
            self.logger.warning(
                "Resuming scan operation %s started at %s",
                operation_id,
                resume_operation["started_at"],
            )
            if checkpoint and checkpoint.get("last_file_path"):
                self.logger.warning(
                    "Resuming from checkpoint updated at %s (last file: %s)",
                    checkpoint.get("updated_at"),
                    checkpoint.get("last_file_path"),
                )
        else:
            operation_id = self.db_manager.start_operation("scan")
            self.logger.info("Starting scan operation %s", operation_id)

        processed_files = int(checkpoint.get("processed_files", 0)) if checkpoint else 0
        last_checkpoint_time = time.monotonic()
        last_file_path = checkpoint.get("last_file_path") if checkpoint else None
        skip_completed = bool(self.config.get("scan", "skip_completed", default=False))
        incremental = bool(self.config.get("scan", "incremental", default=False))
        invalidate_on_change = bool(
            self.config.get("scan", "invalidate_hashes_on_change", default=True)
        )
        detect_removed = bool(self.config.get("scan", "detect_removed", default=False))
        detect_removed_full_only = bool(
            self.config.get("scan", "detect_removed_full_only", default=True)
        )
        scan_start = datetime.utcnow().isoformat()
        skipped_roots: list[Path] = []
        resume_root = None
        if checkpoint and checkpoint.get("extra"):
            resume_root = checkpoint["extra"].get("root")
        if not resume_root and last_file_path:
            try:
                anchor = Path(last_file_path).anchor
            except (OSError, RuntimeError):
                anchor = ""
            resume_root = anchor or None
        resume_root_value = None
        if resume_root:
            resume_root_value = os.path.normcase(os.path.normpath(str(resume_root)))
        resume_root_seen = resume_root_value is None
        resume_after = None
        last_root = None
        last_drive_key = None

        try:
            roots = list(self._scan_roots())
            if resume_root_value is not None:
                normalized_roots = [os.path.normcase(os.path.normpath(str(root))) for root in roots]
                if resume_root_value not in normalized_roots:
                    self.logger.warning(
                        "Resume root %s not in configured scan roots; starting from beginning.",
                        resume_root,
                    )
                    resume_root_value = None
                    resume_root_seen = True
            for root in roots:
                if not root.exists():
                    self.logger.warning("Scan root does not exist: %s", root)
                    continue
                if not resume_root_seen:
                    current_root_value = os.path.normcase(os.path.normpath(str(root)))
                    if current_root_value != resume_root_value:
                        self.logger.info("Skipping root before resume checkpoint: %s", root)
                        continue
                    resume_root_seen = True
                    resume_after = last_file_path
                drive_key = self.db_manager.normalize_drive_key(root)
                if skip_completed and self.db_manager.is_drive_completed(drive_key):
                    self.logger.info("Skipping completed drive %s (%s)", drive_key, root)
                    skipped_roots.append(root)
                    resume_after = None
                    continue
                self.logger.info("Scanning root: %s", root)
                existing_paths = None
                if not incremental:
                    existing_paths = self._prefetch_existing_paths(root)
                if resume_after:
                    self.logger.warning("Resuming scan within root %s after %s", root, resume_after)
                for record in self.scanner.scan(
                    root,
                    monitor=self.resource_monitor,
                    resume_after=resume_after,
                    existing_paths=existing_paths,
                ):
                    result = self.db_manager.upsert_file_with_status(record)
                    if invalidate_on_change and result.changed and record.accessible:
                        self.db_manager.invalidate_hashes(result.file_id)
                    if record.accessible:
                        self.db_manager.resolve_permission_issue(record.file_path)
                    processed_files += 1
                    last_file_path = record.file_path
                    self.activity_tracker.touch("scan")
                    if self._should_checkpoint(processed_files, last_checkpoint_time):
                        self.db_manager.save_checkpoint(
                            operation_id=operation_id,
                            phase="discovery",
                            processed_files=processed_files,
                            total_files=None,
                            last_file_path=last_file_path,
                            extra={"root": str(root), "drive_key": drive_key},
                        )
                        last_checkpoint_time = time.monotonic()
                resume_after = None
                last_root = str(root)
                last_drive_key = drive_key
                self.db_manager.mark_drive_completed(drive_key, notes="scan_completed")

            self.db_manager.save_checkpoint(
                operation_id=operation_id,
                phase="discovery",
                processed_files=processed_files,
                total_files=None,
                last_file_path=last_file_path,
                extra={"root": last_root, "drive_key": last_drive_key} if last_root else None,
            )
            if detect_removed:
                if detect_removed_full_only and skipped_roots:
                    self.logger.warning(
                        "Removed-file detection skipped because some roots were not scanned."
                    )
                else:
                    removed = self._mark_missing_files(scan_start)
                    if removed:
                        self.logger.info("Removed files detected and marked missing: %s", removed)
            self.db_manager.complete_operation(operation_id, status="completed")
            self.logger.info("Scan operation %s completed. Files processed: %s", operation_id, processed_files)
        except Exception:
            self.db_manager.complete_operation(operation_id, status="failed")
            self.logger.exception("Scan operation %s failed.", operation_id)
            raise

    def _run_hashing(self) -> None:
        operation_id = self.db_manager.start_operation("hashing")
        self.logger.info("Starting hashing operation %s", operation_id)
        try:
            stats = self.hashing_engine.run(operation_id)
            self.db_manager.complete_operation(operation_id, status="completed")
            self.logger.info(
                "Hashing operation %s completed. Hashed=%s Skipped=%s Corrupted=%s Errors=%s",
                operation_id,
                stats.hashed_files,
                stats.skipped_files,
                stats.corrupted_files,
                stats.error_files,
            )
        except Exception:
            self.db_manager.complete_operation(operation_id, status="failed")
            self.logger.exception("Hashing operation %s failed.", operation_id)
            raise

    def _run_corruption_quarantine(self) -> None:
        operation_id = self.db_manager.start_operation("corruption_quarantine")
        try:
            stats = self.corruption_mover.run(operation_id=operation_id)
            self.db_manager.complete_operation(operation_id, status="completed")
            if stats.moved or stats.errors:
                self.logger.info(
                    "Corruption quarantine complete. Moved=%s Errors=%s Report=%s",
                    stats.moved,
                    stats.errors,
                    stats.report_path,
                )
        except Exception:
            self.db_manager.complete_operation(operation_id, status="failed")
            self.logger.exception("Corruption quarantine failed (%s).", operation_id)
            raise

    def _run_corruption_validation(self) -> None:
        operation_id = self.db_manager.start_operation("corruption_validation")
        try:
            stats = self.corruption_validator.run()
            self.db_manager.complete_operation(operation_id, status="completed")
            if stats is not None:
                self.logger.info(
                    "Corruption validation complete. Scanned=%s Corrupted=%s Repaired=%s Report=%s",
                    stats.scanned,
                    stats.corrupted,
                    stats.repaired,
                    stats.report_path,
                )
        except Exception:
            self.db_manager.complete_operation(operation_id, status="failed")
            self.logger.exception("Corruption validation failed (%s).", operation_id)
            raise

    def _run_thumbnail_cleanup(self) -> None:
        stats = self.thumbnail_engine.run()
        if stats is None:
            return
        if stats.candidate_count or stats.skipped_missing:
            self.logger.info(
                "Thumbnail scan complete. Candidates=%s Missing=%s Report=%s",
                stats.candidate_count,
                stats.skipped_missing,
                stats.report_path,
            )

    def _maybe_run_rollback(self) -> None:
        allow_rollback = bool(self.config.get("safety", "allow_rollback", default=False))
        rollback_id = os.environ.get("FILE_MANAGER_ROLLBACK_OPERATION_ID")
        if not allow_rollback or not rollback_id:
            return
        self.logger.warning("Rollback requested for operation %s", rollback_id)
        self.rollback_manager.rollback_operation(rollback_id)
        rollback_only = os.environ.get("FILE_MANAGER_ROLLBACK_ONLY", "").lower() in {"1", "true", "yes"}
        if rollback_only:
            raise SystemExit("Rollback completed; exiting by request.")

    def _run_duplicates(self):
        operation_id = self.db_manager.start_operation("duplicates")
        self.logger.info("Starting duplicate detection operation %s", operation_id)
        try:
            stats = self.duplicate_engine.run(operation_id)
            self.db_manager.complete_operation(operation_id, status="completed")
            self.logger.info(
                "Duplicate detection %s completed. Groups=%s Duplicates=%s Report=%s",
                operation_id,
                stats.duplicate_groups,
                stats.duplicate_files,
                stats.report_path,
            )
            return stats
        except Exception:
            self.db_manager.complete_operation(operation_id, status="failed")
            self.logger.exception("Duplicate detection %s failed.", operation_id)
            raise

    def _run_duplicate_plan(self, report_path: Optional[Path]) -> None:
        if report_path is None:
            details = self.db_manager.get_latest_operation_details("duplicates")
            if not details:
                self.logger.warning("No duplicate report available; skipping duplicate plan.")
                return
            report_path = Path(details)
        stats = self.duplicate_plan_engine.build_plan(report_path)
        self.logger.info(
            "Duplicate move plan generated. Groups=%s Moves=%s Plan=%s Review=%s",
            stats.group_count,
            stats.move_count,
            stats.plan_path,
            stats.review_path,
        )
        self._maybe_apply_duplicate_plan(stats.plan_path)

    def _run_ai_categorization(self) -> None:
        operation_id = self.db_manager.start_operation("ai_categorization")
        try:
            stats = self.ai_engine.run()
            self.db_manager.complete_operation(operation_id, status="completed")
            if stats is not None:
                self.logger.info(
                    "AI categorization complete. Processed=%s Classified=%s NSFW=%s Errors=%s",
                    stats.processed,
                    stats.classified,
                    stats.nsfw_flagged,
                    stats.errors,
                )
        except Exception:
            self.db_manager.complete_operation(operation_id, status="failed")
            self.logger.exception("AI categorization failed (%s).", operation_id)
            raise

    def _run_nsfw_quarantine(self) -> None:
        operation_id = self.db_manager.start_operation("nsfw_quarantine")
        try:
            stats = self.nsfw_mover.run(operation_id=operation_id)
            self.db_manager.complete_operation(operation_id, status="completed")
            if stats is not None:
                self.logger.info(
                    "NSFW quarantine complete. Moved=%s Errors=%s Report=%s Review=%s",
                    stats.moved,
                    stats.errors,
                    stats.report_path,
                    stats.review_path,
                )
        except Exception:
            self.db_manager.complete_operation(operation_id, status="failed")
            self.logger.exception("NSFW quarantine failed (%s).", operation_id)
            raise

    def _run_organization_plan(self) -> None:
        operation_id = self.db_manager.start_operation("organization_plan")
        try:
            stats = self.organization_engine.build_plan()
            if stats is None:
                self.db_manager.complete_operation(operation_id, status="completed")
                return
            self.latest_organization_plan = stats.plan_path
            self.db_manager.update_operation_details(operation_id, str(stats.plan_path))
            self.db_manager.complete_operation(operation_id, status="completed")
            self.logger.info(
                "Organization plan generated. Moves=%s Plan=%s Review=%s",
                stats.move_count,
                stats.plan_path,
                stats.review_path,
            )
            self._maybe_apply_organization_plan(stats.plan_path)
        except Exception:
            self.db_manager.complete_operation(operation_id, status="failed")
            self.logger.exception("Organization plan failed (%s).", operation_id)
            raise

    def _maybe_apply_duplicate_plan(self, plan_path: Path) -> None:
        apply_plan = bool(self.config.get("duplicates", "apply_plan", default=False))
        confirm_required = bool(
            self.config.get("safety", "require_confirmation_for_duplicate_moves", default=True)
        )
        confirmed = os.environ.get("FILE_MANAGER_APPLY_DUPLICATE_PLAN", "").lower() in {"1", "true", "yes"}
        if not apply_plan and not confirmed:
            self.logger.info("Duplicate plan not applied. Set FILE_MANAGER_APPLY_DUPLICATE_PLAN=1 to apply.")
            return
        if confirm_required and not confirmed:
            self.logger.warning("Duplicate move confirmation required. Skipping plan apply.")
            return
        operation_id = self.db_manager.start_operation("duplicate_plan_apply")
        try:
            stats = self.duplicate_plan_engine.apply_plan(plan_path, operation_id=operation_id)
            self.db_manager.complete_operation(operation_id, status="completed")
            self.logger.info(
                "Duplicate plan applied. Moved=%s Copied=%s Deleted=%s Errors=%s Result=%s",
                stats.moved,
                stats.copied,
                stats.deleted,
                stats.errors,
                stats.result_path,
            )
        except Exception:
            self.db_manager.complete_operation(operation_id, status="failed")
            self.logger.exception("Duplicate plan apply failed (%s).", operation_id)
            raise

    def _maybe_apply_organization_plan(self, plan_path: Path) -> None:
        apply_plan = bool(self.config.get("organization", "apply_plan", default=False))
        confirm_required = bool(
            self.config.get("safety", "require_confirmation_for_organization_moves", default=True)
        )
        confirmed = os.environ.get("FILE_MANAGER_APPLY_ORGANIZATION_PLAN", "").lower() in {"1", "true", "yes"}
        if not apply_plan and not confirmed:
            self.logger.info(
                "Organization plan not applied. Set FILE_MANAGER_APPLY_ORGANIZATION_PLAN=1 to apply."
            )
            return
        if confirm_required and not confirmed:
            self.logger.warning("Organization move confirmation required. Skipping plan apply.")
            return
        operation_id = self.db_manager.start_operation("organization_plan_apply")
        try:
            stats = self.organization_engine.apply_plan(plan_path, operation_id=operation_id)
            self.db_manager.complete_operation(operation_id, status="completed")
            self.logger.info(
                "Organization plan applied. Moved=%s Copied=%s Errors=%s Result=%s",
                stats.moved,
                stats.copied,
                stats.errors,
                stats.result_path,
            )
        except Exception:
            self.db_manager.complete_operation(operation_id, status="failed")
            self.logger.exception("Organization plan apply failed (%s).", operation_id)
            raise

    def _run_cloud_dedupe(self) -> None:
        operation_id = self.db_manager.start_operation("cloud_dedupe")
        try:
            stats = self.drive_dedupe_engine.run()
            self.db_manager.complete_operation(operation_id, status="completed")
            if stats is not None:
                self.logger.info(
                    "Drive dedupe complete. Groups=%s Moved=%s Skipped=%s Report=%s",
                    stats.duplicate_groups,
                    stats.moved,
                    stats.skipped,
                    stats.report_path,
                )
        except Exception:
            self.db_manager.complete_operation(operation_id, status="failed")
            self.logger.exception("Drive dedupe failed (%s).", operation_id)
            raise

    def _run_drive_upload(self) -> None:
        operation_id = self.db_manager.start_operation("drive_upload")
        try:
            plan_path = self.latest_organization_plan
            if plan_path is None:
                details = self.db_manager.get_latest_operation_details("organization_plan")
                plan_path = Path(details) if details else None
            if plan_path is None:
                self.logger.info("No organization plan available for Drive upload.")
                self.db_manager.complete_operation(operation_id, status="completed")
                return
            stats = self.drive_upload_engine.run(plan_path)
            self.db_manager.complete_operation(operation_id, status="completed")
            if stats is not None:
                self.logger.info(
                    "Drive upload complete. Uploaded=%s Skipped=%s Errors=%s Report=%s",
                    stats.uploaded,
                    stats.skipped,
                    stats.errors,
                    stats.report_path,
                )
        except Exception:
            self.db_manager.complete_operation(operation_id, status="failed")
            self.logger.exception("Drive upload failed (%s).", operation_id)
            raise

    def _build_db_paths(self) -> dict[str, Path]:
        """Resolve database file paths from configuration."""
        return {
            "file_inventory": self.config.resolve_path(
                "databases", "file_inventory", default="data/file_inventory.sqlite"
            ),
            "hash_database": self.config.resolve_path(
                "databases", "hash_database", default="data/hash_database.sqlite"
            ),
            "ai_classifications": self.config.resolve_path(
                "databases", "ai_classifications", default="data/ai_classifications.sqlite"
            ),
            "state": self.config.resolve_path("databases", "state", default="data/state.sqlite"),
        }

    def _ensure_paths(self) -> None:
        """Create required directories for logs and staging paths."""
        ensure_directories(
            [
                self.config.resolve_path("paths", "staging", default="data/staging"),
                self.config.resolve_path("paths", "logs", default="logs"),
                self.config.resolve_path("paths", "nsfw_review", default="data/nsfw_review"),
                self.config.resolve_path("paths", "duplicates_backup", default="data/duplicates_backup"),
                self.config.resolve_path("paths", "corrupted", default="data/corrupted_files"),
            ]
        )

    def _log_optional_dependency_warnings(self) -> None:
        import importlib.util
        import shutil

        def missing(module: str) -> bool:
            return importlib.util.find_spec(module) is None

        warnings: list[str] = []
        ai_enabled = bool(self.config.get("ai", "enabled", default=False))
        nsfw_enabled = bool(self.config.get("nsfw", "enabled", default=False))
        corruption_enabled = bool(self.config.get("corruption", "enabled", default=False))
        repair_enabled = bool(self.config.get("corruption", "repair_enabled", default=False))
        use_embeddings = bool(self.config.get("ai", "use_embeddings", default=False))

        if ai_enabled:
            if missing("PIL"):
                warnings.append("Pillow missing: image analysis disabled")
            if missing("transformers"):
                warnings.append("transformers missing: CLIP image/text classification disabled")
            if missing("sentence_transformers") and use_embeddings:
                warnings.append("sentence-transformers missing: embedding-based doc classification disabled")
            if missing("nudenet"):
                warnings.append("nudenet missing: NSFW scoring disabled")
            if missing("fitz"):
                warnings.append("PyMuPDF missing: PDF text extraction disabled")
            if missing("docx"):
                warnings.append("python-docx missing: DOCX text extraction disabled")
            if missing("openpyxl"):
                warnings.append("openpyxl missing: spreadsheet text extraction disabled")

        if nsfw_enabled and missing("PIL"):
            warnings.append("Pillow missing: NSFW thumbnails disabled")

        if corruption_enabled and missing("PIL"):
            warnings.append("Pillow missing: image corruption checks limited")
        if repair_enabled:
            if missing("PIL"):
                warnings.append("Pillow missing: image repair disabled")
            if missing("fitz"):
                warnings.append("PyMuPDF missing: PDF repair disabled")
            if missing("docx"):
                warnings.append("python-docx missing: DOCX repair disabled")
            if missing("openpyxl"):
                warnings.append("openpyxl missing: XLSX repair disabled")
            if shutil.which("ffmpeg") is None:
                warnings.append("ffmpeg missing: video repair disabled")

        if warnings:
            self.logger.warning("Optional dependency warnings: %s", "; ".join(warnings))

    def _scan_roots(self) -> Iterable[Path]:
        """Return configured scan roots as Path objects."""
        roots = self.config.get("scan", "roots", default=["."])
        return [Path(root).expanduser() for root in roots]

    def _prefetch_existing_paths(self, root: Path) -> Optional[set[str]]:
        if not bool(self.config.get("scan", "prefetch_existing_paths", default=False)):
            return None
        max_entries = int(self.config.get("scan", "prefetch_max_entries", default=0))
        if max_entries <= 0:
            return None
        try:
            count = self.db_manager.count_files_for_root(root)
        except Exception as exc:
            self.logger.warning("Prefetch count failed for %s: %s", root, exc)
            return None
        if count > max_entries:
            self.logger.info(
                "Prefetch skipped for %s (count %s exceeds limit %s)", root, count, max_entries
            )
            return None
        self.logger.info("Prefetching %s existing paths for %s", count, root)
        try:
            return set(self.db_manager.iter_file_paths_for_root(root))
        except Exception as exc:
            self.logger.warning("Prefetch failed for %s: %s", root, exc)
            return None

    def _enforce_resume_confirmation(self) -> None:
        """Require explicit confirmation before continuing after incomplete operations."""
        incomplete = self.db_manager.list_incomplete_operations()
        if not incomplete:
            return
        require_confirmation = bool(
            self.config.get("safety", "require_confirmation_for_resume", default=False)
        )
        if not require_confirmation:
            self._log_incomplete_operations(incomplete)
            return

        env_confirm = os.environ.get("FILE_MANAGER_CONFIRM_RESUME", "").lower() in {"1", "true", "yes"}
        config_confirm = bool(self.config.get("safety", "resume_confirmed", default=False))
        if env_confirm or config_confirm:
            self.logger.warning("Resume confirmation provided; continuing with incomplete operations present.")
            self._log_incomplete_operations(incomplete)
            return

        self._log_incomplete_operations(incomplete)
        raise RuntimeError(
            "Incomplete operations detected. Set FILE_MANAGER_CONFIRM_RESUME=1 to continue."
        )

    def _log_incomplete_operations(self, incomplete: list[tuple[str, str, str]]) -> None:
        for operation_id, operation_type, started_at in incomplete:
            self.logger.warning(
                "Incomplete operation detected: %s (%s) started at %s",
                operation_id,
                operation_type,
                started_at,
            )

    def _log_permission_issue_summary(self) -> None:
        count = self.db_manager.count_permission_issues(resolved=False)
        if count:
            self.logger.warning("Permission issues pending: %s", count)

    def _retry_permission_issues(self) -> None:
        pending = self.db_manager.list_permission_issues(resolved=False, limit=1000)
        if not pending:
            return
        require_confirmation = bool(
            self.config.get("safety", "require_confirmation_for_permission_retry", default=True)
        )
        confirmed = os.environ.get("FILE_MANAGER_RETRY_PERMISSIONS", "").lower() in {"1", "true", "yes"}
        if require_confirmation and not confirmed:
            self.logger.warning(
                "Permission retry skipped. Set FILE_MANAGER_RETRY_PERMISSIONS=1 to retry %s items.",
                len(pending),
            )
            return

        self.logger.info("Retrying %s permission issues.", len(pending))
        resolved_paths: list[str] = []
        for issue in pending:
            file_path = Path(issue["file_path"])
            record = self.scanner.build_record(file_path)
            self.db_manager.upsert_file(record)
            if record.accessible:
                self.db_manager.resolve_permission_issue(record.file_path)
                resolved_paths.append(record.file_path)

        if resolved_paths:
            self._run_hashing_for_paths(resolved_paths)
            self._run_duplicates_for_paths(resolved_paths)

    def _run_hashing_for_paths(self, file_paths: list[str]) -> None:
        entries = self.db_manager.fetch_inventory_entries_by_paths(file_paths)
        if not entries:
            return
        operation_id = self.db_manager.start_operation("hashing_retry")
        self.logger.info("Starting hashing retry operation %s for %s files", operation_id, len(entries))
        try:
            stats = self.hashing_engine.run_for_entries(operation_id, entries)
            self.db_manager.complete_operation(operation_id, status="completed")
            self.logger.info(
                "Hashing retry %s completed. Hashed=%s Skipped=%s Errors=%s",
                operation_id,
                stats.hashed_files,
                stats.skipped_files,
                stats.error_files,
            )
        except Exception:
            self.db_manager.complete_operation(operation_id, status="failed")
            self.logger.exception("Hashing retry %s failed.", operation_id)
            raise

    def _run_duplicates_for_paths(self, file_paths: list[str]) -> None:
        candidate_keys = self.db_manager.fetch_name_size_by_paths(file_paths)
        if not candidate_keys:
            return
        operation_id = self.db_manager.start_operation("duplicates_retry")
        self.logger.info("Starting duplicate retry %s for %s candidates", operation_id, len(candidate_keys))
        try:
            stats = self.duplicate_engine.run(operation_id, candidates=candidate_keys)
            self.db_manager.complete_operation(operation_id, status="completed")
            self.logger.info(
                "Duplicate retry %s completed. Groups=%s Duplicates=%s Report=%s",
                operation_id,
                stats.duplicate_groups,
                stats.duplicate_files,
                stats.report_path,
            )
            self._run_duplicate_plan(stats.report_path)
        except Exception:
            self.db_manager.complete_operation(operation_id, status="failed")
            self.logger.exception("Duplicate retry %s failed.", operation_id)
            raise

    def _should_checkpoint(self, processed_files: int, last_checkpoint_time: float) -> bool:
        """Determine whether a checkpoint should be persisted."""
        if processed_files % self.checkpoint_after_files == 0:
            return True
        return (time.monotonic() - last_checkpoint_time) >= self.checkpoint_interval

    def _mark_missing_files(self, scan_start: str) -> int:
        """Mark inventory entries missing from the filesystem."""
        return self.db_manager.mark_missing_files(scan_start)


def main() -> None:
    """CLI entry point."""
    config = AppConfig.load()
    orchestrator = Orchestrator(config)
    orchestrator.run()


if __name__ == "__main__":
    main()
