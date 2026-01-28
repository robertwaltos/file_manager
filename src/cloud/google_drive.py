"""
Google Drive API integration for cloud deduplication.
"""

from __future__ import annotations

import json
import logging
import os
import random
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from config import AppConfig
from utils import ActivityTracker

try:
    from google.oauth2 import service_account
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:  # pragma: no cover
    service_account = None
    Credentials = None
    InstalledAppFlow = None
    Request = None
    build = None
    HttpError = None


@dataclass
class GoogleDriveDedupeStats:
    """Summary stats for Drive deduplication."""

    duplicate_groups: int
    moved: int
    skipped: int
    report_path: Path


class GoogleDriveDedupeEngine:
    """Detect and optionally move duplicate files in Google Drive."""

    def __init__(
        self,
        config: AppConfig,
        logger: Optional[logging.Logger] = None,
        activity_tracker: Optional[ActivityTracker] = None,
    ) -> None:
        self.config = config
        self.logger = logger or logging.getLogger("file_manager")
        self.activity_tracker = activity_tracker
        self.enabled = bool(self.config.get("cloud", "google_drive", "enabled", default=False))
        self.apply_moves = bool(self.config.get("cloud", "google_drive", "apply_moves", default=False))
        self.require_confirmation = bool(
            self.config.get("safety", "require_confirmation_for_cloud_moves", default=True)
        )
        self.scopes = self.config.get(
            "cloud",
            "google_drive",
            "scopes",
            default=["https://www.googleapis.com/auth/drive"],
        )
        self.credentials_path = self._resolve_path("credentials_path")
        self.token_path = self._resolve_path("token_path")
        self.service_account_path = self._resolve_path("service_account_path")
        self.duplicates_folder_name = str(
            self.config.get("cloud", "google_drive", "duplicates_folder_name", default="Duplicates")
        )
        self.duplicates_folder_id = self.config.get(
            "cloud", "google_drive", "duplicates_folder_id", default=None
        )
        self.logs_root = self.config.resolve_path("paths", "logs", default="logs")
        self.progress_log_interval = int(
            self.config.get("cloud", "google_drive", "progress_log_interval", default=50)
        )
        self.retry_max_attempts = int(
            self.config.get("cloud", "google_drive", "retry_max_attempts", default=5)
        )
        self.retry_base_delay = float(
            self.config.get("cloud", "google_drive", "retry_base_delay_seconds", default=1)
        )
        self.retry_max_delay = float(
            self.config.get("cloud", "google_drive", "retry_max_delay_seconds", default=30)
        )

    def run(self) -> Optional[GoogleDriveDedupeStats]:
        if not self.enabled:
            self.logger.info("Google Drive dedupe disabled.")
            return None
        if build is None:
            self.logger.warning("Google Drive dependencies missing; skipping cloud dedupe.")
            return None

        service = self._build_service()
        if service is None:
            return None

        files = self._list_files(service)
        groups = self._group_duplicates(files)
        moved = skipped = 0
        confirmed = os.environ.get("FILE_MANAGER_APPLY_DRIVE_DEDUPE", "").lower() in {"1", "true", "yes"}
        allow_moves = self.apply_moves or confirmed
        if self.require_confirmation and not confirmed:
            allow_moves = False
            self.logger.warning(
                "Drive dedupe moves require confirmation. Set FILE_MANAGER_APPLY_DRIVE_DEDUPE=1 to apply."
            )

        target_folder_id = self.duplicates_folder_id or self._ensure_duplicates_folder(service)
        for index, group in enumerate(groups, start=1):
            keep, *dupes = group
            self._touch("drive_dedupe", index, interval=25)
            if self.progress_log_interval > 0 and index % self.progress_log_interval == 0:
                self.logger.info(
                    "Drive dedupe progress: %s/%s moved=%s skipped=%s",
                    index,
                    len(groups),
                    moved,
                    skipped,
                )
            for item in dupes:
                if not allow_moves or not target_folder_id:
                    skipped += 1
                    continue
                if self._move_file(service, item["id"], target_folder_id, item.get("parents", [])):
                    moved += 1
                else:
                    skipped += 1

        report_path = self._write_report(groups, moved, skipped)
        return GoogleDriveDedupeStats(
            duplicate_groups=len(groups),
            moved=moved,
            skipped=skipped,
            report_path=report_path,
        )

    def _build_service(self):
        creds = None
        if self.service_account_path and service_account is not None:
            try:
                creds = service_account.Credentials.from_service_account_file(
                    str(self.service_account_path), scopes=self.scopes
                )
            except Exception as exc:
                self.logger.warning("Service account auth failed: %s", exc)
                return None
        elif self.token_path and Credentials is not None:
            try:
                creds = Credentials.from_authorized_user_file(str(self.token_path), self.scopes)
            except Exception:
                creds = None
            if creds and creds.expired and creds.refresh_token and Request is not None:
                try:
                    creds.refresh(Request())
                except Exception as exc:
                    self.logger.warning("Token refresh failed: %s", exc)
            if not creds and self.credentials_path and InstalledAppFlow is not None:
                self.logger.warning("OAuth token missing; create token at %s", self.token_path)
                return None
        else:
            self.logger.warning("No Drive credentials configured.")
            return None

        try:
            return build("drive", "v3", credentials=creds, cache_discovery=False)
        except Exception as exc:
            self.logger.warning("Failed to build Drive service: %s", exc)
            return None

    def _list_files(self, service) -> list[dict]:
        files = []
        page_token = None
        page_count = 0
        while True:
            response = self._execute_with_retry(
                lambda: service.files().list(
                    q="trashed = false",
                    fields="nextPageToken, files(id, name, size, md5Checksum, mimeType, parents)",
                    pageToken=page_token,
                ),
                context="list_files",
            )
            if response is None:
                break
            files.extend(response.get("files", []))
            page_count += 1
            self._touch("drive_list", page_count, interval=1)
            if self.progress_log_interval > 0 and page_count % self.progress_log_interval == 0:
                self.logger.info(
                    "Drive list progress: pages=%s files=%s",
                    page_count,
                    len(files),
                )
            page_token = response.get("nextPageToken")
            if not page_token:
                break
        return files

    def _group_duplicates(self, files: list[dict]) -> list[list[dict]]:
        buckets: dict[tuple[str, str], list[dict]] = {}
        for item in files:
            size = item.get("size")
            key = None
            if item.get("md5Checksum"):
                key = ("md5", item["md5Checksum"])
            elif item.get("name") and size:
                key = ("name_size", f"{item['name']}::{size}")
            if key is None:
                continue
            buckets.setdefault(key, []).append(item)
        return [group for group in buckets.values() if len(group) > 1]

    def _ensure_duplicates_folder(self, service) -> Optional[str]:
        if self.duplicates_folder_id:
            return self.duplicates_folder_id
        response = self._execute_with_retry(
            lambda: service.files().list(
                q=f"mimeType='application/vnd.google-apps.folder' and name='{self.duplicates_folder_name}' and trashed=false",
                fields="files(id, name)",
            ),
            context="find_duplicates_folder",
        )
        if response is None:
            return None
        files = response.get("files", [])
        if files:
            return files[0]["id"]
        folder = self._execute_with_retry(
            lambda: service.files().create(
                body={
                    "name": self.duplicates_folder_name,
                    "mimeType": "application/vnd.google-apps.folder",
                },
                fields="id",
            ),
            context="create_duplicates_folder",
        )
        if folder is None:
            return None
        return folder.get("id")

    def _move_file(self, service, file_id: str, target_folder_id: str, parents: list) -> bool:
        remove_parents = ",".join(parents) if parents else None
        response = self._execute_with_retry(
            lambda: service.files().update(
                fileId=file_id,
                addParents=target_folder_id,
                removeParents=remove_parents,
                fields="id, parents",
            ),
            context=f"move_file:{file_id}",
        )
        return response is not None

    def _execute_with_retry(self, build_request, context: str):
        attempts = max(self.retry_max_attempts, 1)
        delay = max(self.retry_base_delay, 0.1)
        for attempt in range(1, attempts + 1):
            try:
                return build_request().execute()
            except Exception as exc:
                retryable = self._is_retryable(exc)
                if not retryable or attempt >= attempts:
                    self.logger.warning("Drive %s failed: %s", context, exc)
                    return None
                sleep_for = min(self.retry_max_delay, delay * (2 ** (attempt - 1)))
                sleep_for += random.uniform(0, 0.25 * sleep_for)
                self.logger.warning(
                    "Drive %s failed (attempt %s/%s). Retrying in %.1fs: %s",
                    context,
                    attempt,
                    attempts,
                    sleep_for,
                    exc,
                )
                time.sleep(sleep_for)

    def _is_retryable(self, exc: Exception) -> bool:
        if HttpError is not None and isinstance(exc, HttpError):
            status = getattr(getattr(exc, "resp", None), "status", None)
            if status in {429, 500, 502, 503, 504}:
                return True
        return isinstance(exc, OSError)

    def _write_report(self, groups: list[list[dict]], moved: int, skipped: int) -> Path:
        self.logs_root.mkdir(parents=True, exist_ok=True)
        report_path = self.logs_root / f"drive_dedupe_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        report_path.write_text(
            json.dumps(
                {
                    "generated_at": datetime.utcnow().isoformat(),
                    "duplicate_groups": len(groups),
                    "moved": moved,
                    "skipped": skipped,
                    "groups": groups,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return report_path

    def _touch(self, note: str, count: int, interval: int = 10) -> None:
        if self.activity_tracker is None:
            return
        if count % interval == 0:
            self.activity_tracker.touch(note)

    def _resolve_path(self, key: str) -> Optional[Path]:
        value = self.config.get("cloud", "google_drive", key, default=None)
        if not value:
            return None
        path = Path(value)
        if not path.is_absolute():
            path = (self.config.root_dir / path).resolve()
        return path
