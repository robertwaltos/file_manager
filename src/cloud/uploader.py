"""
Google Drive upload and verification workflow.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
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
    from googleapiclient.http import MediaFileUpload
except ImportError:  # pragma: no cover
    service_account = None
    Credentials = None
    InstalledAppFlow = None
    Request = None
    build = None
    MediaFileUpload = None


@dataclass
class GoogleDriveUploadStats:
    """Summary stats for Drive uploads."""

    uploaded: int
    skipped: int
    errors: int
    report_path: Path


class GoogleDriveUploadEngine:
    """Upload local files to Google Drive and verify checksums."""

    def __init__(
        self,
        config: AppConfig,
        logger: Optional[logging.Logger] = None,
        activity_tracker: Optional[ActivityTracker] = None,
    ) -> None:
        self.config = config
        self.logger = logger or logging.getLogger("file_manager")
        self.activity_tracker = activity_tracker
        self.progress_log_interval = int(
            self.config.get("cloud", "google_drive", "upload_progress_log_interval", default=100)
        )
        self.enabled = bool(self.config.get("cloud", "google_drive", "upload_enabled", default=False))
        self.apply_uploads = bool(self.config.get("cloud", "google_drive", "upload_apply", default=False))
        self.require_confirmation = bool(
            self.config.get("safety", "require_confirmation_for_cloud_moves", default=True)
        )
        self.verify_after_upload = bool(
            self.config.get("cloud", "google_drive", "upload_verify", default=True)
        )
        self.delete_after_upload = bool(
            self.config.get("cloud", "google_drive", "upload_delete_after", default=False)
        )
        self.skip_existing = bool(
            self.config.get("cloud", "google_drive", "upload_skip_existing", default=True)
        )
        self.chunk_mb = int(self.config.get("cloud", "google_drive", "upload_chunk_mb", default=8))
        self.scopes = self.config.get(
            "cloud",
            "google_drive",
            "scopes",
            default=["https://www.googleapis.com/auth/drive"],
        )
        self.credentials_path = self._resolve_path("credentials_path")
        self.token_path = self._resolve_path("token_path")
        self.service_account_path = self._resolve_path("service_account_path")
        self.upload_root_id = str(
            self.config.get("cloud", "google_drive", "upload_root_id", default="root")
        )
        self.local_root = Path(
            self.config.get("cloud", "google_drive", "local_root", default="G:/My Drive")
        )
        self.logs_root = self.config.resolve_path("paths", "logs", default="logs")
        self._folder_cache: dict[str, str] = {}

    def run(self, plan_path: Path) -> Optional[GoogleDriveUploadStats]:
        if not self.enabled:
            self.logger.info("Google Drive upload disabled.")
            return None
        if build is None or MediaFileUpload is None:
            self.logger.warning("Google Drive dependencies missing; skipping uploads.")
            return None
        if not plan_path.exists():
            self.logger.warning("Organization plan missing: %s", plan_path)
            return None

        confirmed = os.environ.get("FILE_MANAGER_APPLY_DRIVE_UPLOAD", "").lower() in {"1", "true", "yes"}
        allow_uploads = self.apply_uploads or confirmed
        if self.require_confirmation and not confirmed:
            allow_uploads = False
            self.logger.warning(
                "Drive uploads require confirmation. Set FILE_MANAGER_APPLY_DRIVE_UPLOAD=1 to apply."
            )
        if not allow_uploads:
            return None

        service = self._build_service()
        if service is None:
            return None

        plan = _load_plan(plan_path)
        uploaded = skipped = errors = 0
        results: list[dict] = []

        for index, move in enumerate(plan, start=1):
            source = Path(move["source"])
            if not source.exists():
                skipped += 1
                results.append(_result(move, "skipped", "source_missing"))
                continue
            destination = Path(move["destination"])
            self._touch("drive_upload", index, interval=25)
            if self.progress_log_interval > 0 and index % self.progress_log_interval == 0:
                self.logger.info(
                    "Drive upload progress: %s/%s uploaded=%s skipped=%s errors=%s",
                    index,
                    len(plan),
                    uploaded,
                    skipped,
                    errors,
                )
            try:
                drive_path = destination.resolve().relative_to(self.local_root.resolve())
            except Exception:
                skipped += 1
                results.append(_result(move, "skipped", "destination_not_under_local_root"))
                continue

            folder_id = self._ensure_drive_folder(service, drive_path.parent)
            if not folder_id:
                errors += 1
                results.append(_result(move, "error", "folder_resolution_failed"))
                continue

            if self.skip_existing and self._drive_has_matching_file(service, folder_id, source):
                skipped += 1
                results.append(_result(move, "skipped", "already_uploaded"))
                continue

            try:
                file_id = self._upload_file(service, source, folder_id)
                if not file_id:
                    errors += 1
                    results.append(_result(move, "error", "upload_failed"))
                    continue
                if self.verify_after_upload:
                    if not self._verify_upload(service, file_id, source):
                        errors += 1
                        results.append(_result(move, "error", "checksum_mismatch"))
                        continue
                if self.delete_after_upload:
                    source.unlink()
                uploaded += 1
                results.append(_result(move, "uploaded", "ok"))
            except Exception as exc:
                errors += 1
                results.append(_result(move, "error", str(exc)))

        report_path = self.logs_root / f"drive_upload_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        report_path.write_text(
            json.dumps(
                {
                    "generated_at": datetime.utcnow().isoformat(),
                    "plan_path": str(plan_path),
                    "uploaded": uploaded,
                    "skipped": skipped,
                    "errors": errors,
                    "results": results,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return GoogleDriveUploadStats(
            uploaded=uploaded,
            skipped=skipped,
            errors=errors,
            report_path=report_path,
        )

    def _touch(self, note: str, count: int, interval: int = 25) -> None:
        if self.activity_tracker is None:
            return
        if count % interval == 0:
            self.activity_tracker.touch(note)

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

    def _ensure_drive_folder(self, service, drive_path: Path) -> Optional[str]:
        current_id = self.upload_root_id
        for part in drive_path.parts:
            key = f"{current_id}:{part}"
            if key in self._folder_cache:
                current_id = self._folder_cache[key]
                continue
            folder_id = self._find_folder(service, part, current_id)
            if not folder_id:
                folder_id = self._create_folder(service, part, current_id)
            if not folder_id:
                return None
            self._folder_cache[key] = folder_id
            current_id = folder_id
        return current_id

    def _find_folder(self, service, name: str, parent_id: str) -> Optional[str]:
        response = (
            service.files()
            .list(
                q=(
                    "mimeType='application/vnd.google-apps.folder' "
                    f"and name='{name}' and '{parent_id}' in parents and trashed=false"
                ),
                fields="files(id, name)",
            )
            .execute()
        )
        files = response.get("files", [])
        return files[0]["id"] if files else None

    def _create_folder(self, service, name: str, parent_id: str) -> Optional[str]:
        try:
            folder = (
                service.files()
                .create(
                    body={
                        "name": name,
                        "mimeType": "application/vnd.google-apps.folder",
                        "parents": [parent_id],
                    },
                    fields="id",
                )
                .execute()
            )
            return folder.get("id")
        except Exception as exc:
            self.logger.warning("Drive folder create failed for %s: %s", name, exc)
            return None

    def _upload_file(self, service, source: Path, folder_id: str) -> Optional[str]:
        media = MediaFileUpload(
            str(source),
            resumable=True,
            chunksize=self.chunk_mb * 1024 * 1024,
        )
        metadata = {"name": source.name, "parents": [folder_id]}
        request = service.files().create(body=metadata, media_body=media, fields="id, md5Checksum")
        response = None
        while response is None:
            status, response = request.next_chunk()
        return response.get("id") if response else None

    def _verify_upload(self, service, file_id: str, source: Path) -> bool:
        try:
            info = service.files().get(fileId=file_id, fields="md5Checksum").execute()
        except Exception:
            return False
        remote_md5 = info.get("md5Checksum")
        if not remote_md5:
            return True
        local_md5 = _compute_md5(source)
        return local_md5 == remote_md5

    def _drive_has_matching_file(self, service, folder_id: str, source: Path) -> bool:
        query = f"name='{source.name}' and '{folder_id}' in parents and trashed=false"
        response = (
            service.files()
            .list(q=query, fields="files(id, md5Checksum, name)")
            .execute()
        )
        files = response.get("files", [])
        if not files:
            return False
        local_md5 = _compute_md5(source)
        for file in files:
            if file.get("md5Checksum") == local_md5:
                return True
        return False

    def _resolve_path(self, key: str) -> Optional[Path]:
        value = self.config.get("cloud", "google_drive", key, default=None)
        if not value:
            return None
        path = Path(value)
        if not path.is_absolute():
            path = (self.config.root_dir / path).resolve()
        return path


def _compute_md5(path: Path) -> str:
    hash_md5 = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def _load_plan(plan_path: Path) -> list[dict]:
    data = json.loads(plan_path.read_text(encoding="utf-8"))
    return data.get("moves", [])


def _result(move: dict, status: str, message: str) -> dict:
    return {
        "source": move.get("source"),
        "destination": move.get("destination"),
        "status": status,
        "message": message,
    }
