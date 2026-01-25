"""
Merge unique files from a source folder into a target folder with reporting.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import time
import traceback
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Optional

from config import AppConfig
from hashing.hasher import Hasher
from utils import setup_logging


SIDE_CAR_EXTS = {
    ".cue",
    ".m3u",
    ".m3u8",
    ".lrc",
    ".nfo",
    ".sfv",
    ".ffp",
    ".log",
    ".txt",
}


@dataclass
class HashResult:
    size: int
    hash_type: str
    hash_value: str


@dataclass
class MergeResult:
    report_path: Path
    completion_path: Path
    progress_path: Path
    moved: int
    skipped: int
    errors: int
    crash_report_path: Optional[Path] = None


ProgressCallback = Callable[[str, int, Optional[Path]], None]


def write_progress(path: Path, payload: dict, logger: logging.Logger) -> None:
    try:
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError as exc:
        logger.warning("Progress write failed: %s", exc)


def notify_complete(logger: logging.Logger) -> None:
    try:
        import winsound

        winsound.MessageBeep()
    except Exception as exc:
        logger.debug("Completion alert failed: %s", exc)


def iter_files(root: Path) -> Iterable[Path]:
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            path = Path(dirpath) / name
            if path.is_symlink():
                continue
            yield path


def compute_folder_size(root: Path, logger: logging.Logger) -> int:
    total = 0
    for path in iter_files(root):
        try:
            total += path.stat().st_size
        except OSError as exc:
            logger.warning("Size check failed for %s: %s", path, exc)
    return total


def resolve_conflict(destination: Path) -> Path:
    if not destination.exists():
        return destination
    stem = destination.stem
    suffix = destination.suffix
    parent = destination.parent
    counter = 1
    while True:
        candidate = parent / f"{stem}__dup{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def build_allowed_sets(config: AppConfig) -> tuple[set[str], set[str], set[str], set[str]]:
    audio_exts = {
        ext.lower()
        for ext in config.get(
            "thumbnails",
            "cover_audio_extensions",
            default=[
                ".mp3",
                ".flac",
                ".wav",
                ".aac",
                ".m4a",
                ".ogg",
                ".wma",
                ".alac",
                ".aiff",
                ".ape",
            ],
        )
    }
    image_exts = {
        ext.lower()
        for ext in config.get(
            "thumbnails",
            "image_extensions",
            default=[
                ".jpg",
                ".jpeg",
                ".png",
                ".gif",
                ".bmp",
                ".webp",
                ".tif",
                ".tiff",
                ".heic",
                ".heif",
            ],
        )
    }
    cover_markers = {
        marker.lower()
        for marker in config.get(
            "thumbnails",
            "cover_name_markers",
            default=[
                "cover",
                "folder",
                "front",
                "album",
                "albumart",
                "artwork",
                "poster",
                "booklet",
            ],
        )
    }
    sidecars = {ext.lower() for ext in SIDE_CAR_EXTS}
    return audio_exts, sidecars, image_exts, cover_markers


def hash_file(path: Path, hasher: Hasher) -> Optional[HashResult]:
    size = path.stat().st_size
    hash_type = hasher.hash_type_for_size(size)
    hash_value = hasher.compute(path, size, hash_type)
    return HashResult(size=size, hash_type=hash_type, hash_value=hash_value)


def is_cover_image(
    path: Path,
    image_exts: set[str],
    cover_markers: set[str],
    audio_exts: set[str],
    dir_audio_cache: dict[Path, bool],
) -> bool:
    if path.suffix.lower() not in image_exts:
        return False
    stem = path.stem.lower()
    if any(marker in stem for marker in cover_markers):
        return True
    parent = path.parent
    if parent in dir_audio_cache:
        return dir_audio_cache[parent]
    has_audio = any(
        entry.is_file() and entry.suffix.lower() in audio_exts for entry in parent.iterdir()
    )
    dir_audio_cache[parent] = has_audio
    return has_audio


def is_audio_related(
    path: Path,
    audio_exts: set[str],
    sidecar_exts: set[str],
    image_exts: set[str],
    cover_markers: set[str],
    dir_audio_cache: dict[Path, bool],
) -> bool:
    ext = path.suffix.lower()
    if ext in audio_exts or ext in sidecar_exts:
        return True
    return is_cover_image(path, image_exts, cover_markers, audio_exts, dir_audio_cache)


def build_hash_index(
    root: Path,
    hasher: Hasher,
    logger: logging.Logger,
    progress_every: int = 500,
    progress_interval_seconds: float = 30.0,
    progress_cb: Optional[ProgressCallback] = None,
) -> tuple[dict[tuple[int, str, str], list[str]], list[dict], int]:
    index: dict[tuple[int, str, str], list[str]] = {}
    errors: list[dict] = []
    count = 0
    last_log = time.monotonic()
    last_path: Optional[Path] = None
    for path in iter_files(root):
        last_path = path
        count += 1
        try:
            result = hash_file(path, hasher)
        except OSError as exc:
            logger.warning("Hash failed for %s: %s", path, exc)
            errors.append({"path": str(path), "error": str(exc)})
            continue
        key = (result.size, result.hash_type, result.hash_value)
        index.setdefault(key, []).append(str(path))
        if count % progress_every == 0 or (time.monotonic() - last_log) >= progress_interval_seconds:
            logger.info("Target index progress: %s files hashed (%s)", count, root)
            if progress_cb is not None:
                progress_cb("target_index_progress", count, last_path)
            last_log = time.monotonic()
    logger.info("Target index complete: %s files hashed (%s)", count, root)
    if progress_cb is not None:
        progress_cb("target_index_complete", count, last_path)
    return index, errors, count


def load_inbox_root(config: AppConfig, override: Optional[str]) -> Optional[Path]:
    if override:
        return Path(override)
    root = config.get("organization", "root", default=None)
    inbox = config.get("organization", "inbox_root", default=None)
    if not root or not inbox:
        return None
    return Path(root) / inbox


def _safe_job_name(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value)
    safe = safe.strip("_")
    return safe or "merge"


def run_merge_job(
    config: AppConfig,
    source_root: Path,
    target_root: Path,
    inbox_root: Optional[Path] = None,
    apply: bool = False,
    delete_old: bool = False,
    report_path: Optional[Path] = None,
    logger: Optional[logging.Logger] = None,
    job_name: Optional[str] = None,
) -> MergeResult:
    logs_root = config.resolve_path("paths", "logs", default="logs")
    if logger is None:
        loggers = setup_logging(logs_root)
        logger = loggers["main"]

    if inbox_root is None:
        inbox_root = load_inbox_root(config, None)

    job_label = _safe_job_name(job_name or f"{source_root.name}_to_{target_root.name}")
    progress_path = logs_root / f"merge_progress_{job_label}.json"
    progress_state = {
        "started_at": datetime.utcnow().isoformat(),
        "last_update": datetime.utcnow().isoformat(),
        "stage": "starting",
        "job_name": job_label,
        "source_root": str(source_root),
        "target_root": str(target_root),
        "inbox_root": str(inbox_root) if inbox_root else None,
        "apply": bool(apply),
        "delete_old": bool(delete_old),
        "target_indexed_files": 0,
        "source_scanned_files": 0,
        "moved": 0,
        "skipped": 0,
        "errors": 0,
        "last_target_path": "",
        "last_source_path": "",
        "report_path": None,
        "completion_path": None,
        "crash_report_path": None,
        "source_delete": None,
        "error": None,
    }

    def progress_update(stage: str, **kwargs: object) -> None:
        progress_state["stage"] = stage
        progress_state["last_update"] = datetime.utcnow().isoformat()
        progress_state.update(kwargs)
        write_progress(progress_path, progress_state, logger)

    def handle_exception(exc: BaseException) -> Path:
        crash_path = logs_root / f"merge_crash_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        crash_payload = {
            "error": str(exc),
            "traceback": "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
            "progress": progress_state,
        }
        crash_path.write_text(json.dumps(crash_payload, indent=2), encoding="utf-8")
        progress_state["stage"] = "crashed"
        progress_state["last_update"] = datetime.utcnow().isoformat()
        progress_state["crash_report_path"] = str(crash_path)
        progress_state["error"] = str(exc)
        write_progress(progress_path, progress_state, logger)
        logger.error("Merge crashed. Crash report: %s", crash_path)
        return crash_path

    progress_update("starting")

    try:
        if not source_root.exists():
            logger.error("Source folder missing: %s", source_root)
            progress_update("failed", error="source_missing")
            raise FileNotFoundError(f"Source folder missing: {source_root}")
        if not target_root.exists():
            logger.error("Target folder missing: %s", target_root)
            progress_update("failed", error="target_missing")
            raise FileNotFoundError(f"Target folder missing: {target_root}")

        if delete_old and not apply:
            logger.warning("Delete requested without --apply; skipping deletion.")

        audio_exts, sidecar_exts, image_exts, cover_markers = build_allowed_sets(config)
        dir_audio_cache: dict[Path, bool] = {}

        hasher = Hasher(
            full_hash_max_bytes=int(
                config.get("hashing", "full_hash_max_bytes", default=100 * 1024 * 1024)
            ),
            hybrid_chunk_bytes=int(config.get("hashing", "hybrid_chunk_bytes", default=1024 * 1024)),
        )

        progress_every = int(config.get("merge", "progress_every", default=250))
        progress_interval = float(config.get("merge", "progress_interval_seconds", default=30))

        progress_update("target_index_start", target_indexed_files=0, last_target_path="")

        def target_progress(stage: str, count: int, last_path: Optional[Path]) -> None:
            progress_update(
                stage,
                target_indexed_files=count,
                last_target_path=str(last_path) if last_path else "",
            )

        logger.info("Building hash index for target: %s", target_root)
        target_index, target_errors, target_count = build_hash_index(
            target_root,
            hasher,
            logger,
            progress_every=progress_every,
            progress_interval_seconds=progress_interval,
            progress_cb=target_progress,
        )
        progress_update("target_index_done", target_indexed_files=target_count)

        folder_sizes: dict[Path, int] = {}

        def get_folder_size(path: Path) -> int:
            if path not in folder_sizes:
                folder_sizes[path] = compute_folder_size(path, logger)
            return folder_sizes[path]

        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "source_root": str(source_root),
            "target_root": str(target_root),
            "inbox_root": str(inbox_root) if inbox_root else None,
            "apply": bool(apply),
            "delete_old": bool(delete_old),
            "size_method": "running_total",
            "hash_settings": {
                "full_hash_max_bytes": hasher.full_hash_max_bytes,
                "hybrid_chunk_bytes": hasher.hybrid_chunk_bytes,
            },
            "target_hash_errors": target_errors,
            "target_indexed_files": target_count,
            "initial_sizes": {},
            "moves": [],
            "skipped": [],
            "errors": [],
            "source_delete": None,
        }

        report["initial_sizes"]["source"] = get_folder_size(source_root)
        report["initial_sizes"]["target"] = get_folder_size(target_root)
        if inbox_root:
            report["initial_sizes"]["inbox"] = get_folder_size(inbox_root)

        logger.info("Scanning source: %s", source_root)
        progress_update(
            "source_scan_start",
            source_scanned_files=0,
            moved=0,
            skipped=0,
            errors=0,
            last_source_path="",
        )
        seen_hashes: set[tuple[int, str, str]] = set()
        moved_count = 0
        source_count = 0
        last_progress = time.monotonic()
        last_source_path: Optional[Path] = None

        for path in iter_files(source_root):
            last_source_path = path
            source_count += 1
            try:
                result = hash_file(path, hasher)
            except OSError as exc:
                logger.warning("Hash failed for %s: %s", path, exc)
                report["errors"].append({"path": str(path), "error": str(exc), "stage": "hash_source"})
                continue

            key = (result.size, result.hash_type, result.hash_value)
            if key in target_index:
                report["skipped"].append(
                    {
                        "path": str(path),
                        "reason": "duplicate_in_target",
                        "matches": target_index.get(key, [])[:3],
                    }
                )
                continue
            if key in seen_hashes:
                report["skipped"].append({"path": str(path), "reason": "duplicate_in_source"})
                continue

            move_to_target = is_audio_related(
                path,
                audio_exts,
                sidecar_exts,
                image_exts,
                cover_markers,
                dir_audio_cache,
            )
            destination_root = target_root if move_to_target else inbox_root
            if destination_root is None:
                report["skipped"].append({"path": str(path), "reason": "non_audio_no_inbox"})
                continue

            relative = path.relative_to(source_root)
            destination = destination_root / relative
            if destination.exists():
                destination = resolve_conflict(destination)

            source_before = get_folder_size(source_root)
            dest_before = get_folder_size(destination_root)
            move_record = {
                "source": str(path),
                "destination": str(destination),
                "size": result.size,
                "hash_type": result.hash_type,
                "hash_value": result.hash_value,
                "source_size_before": source_before,
                "destination_size_before": dest_before,
                "source_size_after": source_before,
                "destination_size_after": dest_before,
                "status": "planned",
            }

            if apply:
                try:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(path), str(destination))
                except OSError as exc:
                    move_record["status"] = "error"
                    move_record["error"] = str(exc)
                    report["errors"].append(move_record)
                    logger.error("Move failed: %s -> %s (%s)", path, destination, exc)
                    continue

                if not destination.exists():
                    move_record["status"] = "error"
                    move_record["error"] = "destination_missing"
                    report["errors"].append(move_record)
                    logger.error("Destination missing after move: %s", destination)
                    continue

                if destination.stat().st_size != result.size:
                    move_record["status"] = "error"
                    move_record["error"] = "size_mismatch"
                    report["errors"].append(move_record)
                    logger.error("Size mismatch after move: %s", destination)
                    continue

                folder_sizes[source_root] = source_before - result.size
                folder_sizes[destination_root] = dest_before + result.size
                move_record["source_size_after"] = folder_sizes[source_root]
                move_record["destination_size_after"] = folder_sizes[destination_root]
                move_record["status"] = "moved"
                moved_count += 1
            else:
                folder_sizes[source_root] = source_before - result.size
                folder_sizes[destination_root] = dest_before + result.size
                move_record["source_size_after"] = folder_sizes[source_root]
                move_record["destination_size_after"] = folder_sizes[destination_root]
                move_record["status"] = "planned"

            report["moves"].append(move_record)
            seen_hashes.add(key)
            if destination_root == target_root:
                target_index.setdefault(key, []).append(str(destination))

            if source_count % progress_every == 0 or (time.monotonic() - last_progress) >= progress_interval:
                logger.info(
                    "Source scan progress: %s files | moved=%s | skipped=%s | errors=%s",
                    source_count,
                    moved_count,
                    len(report["skipped"]),
                    len(report["errors"]),
                )
                progress_update(
                    "source_scan_progress",
                    source_scanned_files=source_count,
                    moved=moved_count,
                    skipped=len(report["skipped"]),
                    errors=len(report["errors"]),
                    last_source_path=str(last_source_path) if last_source_path else "",
                )
                last_progress = time.monotonic()

        logger.info("Source scan complete: %s files", source_count)
        report["source_scanned_files"] = source_count
        progress_update(
            "source_scan_complete",
            source_scanned_files=source_count,
            moved=moved_count,
            skipped=len(report["skipped"]),
            errors=len(report["errors"]),
            last_source_path=str(last_source_path) if last_source_path else "",
        )

        report["final_sizes"] = {
            "source": folder_sizes.get(source_root, 0),
            "target": folder_sizes.get(target_root, 0),
            "inbox": folder_sizes.get(inbox_root, 0) if inbox_root else None,
        }
        report["summary"] = {
            "moved": moved_count,
            "skipped": len(report["skipped"]),
            "errors": len(report["errors"]),
        }

        if apply and delete_old:
            if report["errors"]:
                report["source_delete"] = {"status": "skipped", "reason": "errors_present"}
                logger.warning("Skipping source delete because errors were encountered.")
            else:
                size_before = folder_sizes.get(source_root, get_folder_size(source_root))
                try:
                    shutil.rmtree(source_root)
                    folder_sizes[source_root] = 0
                    report["source_delete"] = {
                        "status": "deleted",
                        "size_before": size_before,
                        "size_after": 0,
                    }
                    logger.info("Deleted source folder: %s", source_root)
                except OSError as exc:
                    report["source_delete"] = {"status": "error", "error": str(exc)}
                    logger.error("Delete failed for %s: %s", source_root, exc)
            progress_update("source_delete", source_delete=report["source_delete"])

        final_report_path = (
            report_path
            if report_path is not None
            else logs_root / f"merge_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        )
        final_report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        logger.info("Merge report written: %s", final_report_path)
        completion_stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        completion_path = logs_root / f"merge_complete_{completion_stamp}.txt"
        completion_path.write_text(
            "\n".join(
                [
                    f"completed_at={datetime.utcnow().isoformat()}",
                    f"report_path={final_report_path}",
                    f"moved={moved_count}",
                    f"skipped={len(report['skipped'])}",
                    f"errors={len(report['errors'])}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        progress_update(
            "completed",
            report_path=str(final_report_path),
            completion_path=str(completion_path),
            moved=moved_count,
            skipped=len(report["skipped"]),
            errors=len(report["errors"]),
        )
        logger.info(
            "Merge complete. Moved=%s Skipped=%s Errors=%s Completion=%s",
            moved_count,
            len(report["skipped"]),
            len(report["errors"]),
            completion_path,
        )
        notify_complete(logger)

        return MergeResult(
            report_path=final_report_path,
            completion_path=completion_path,
            progress_path=progress_path,
            moved=moved_count,
            skipped=len(report["skipped"]),
            errors=len(report["errors"]),
        )
    except Exception as exc:
        crash_path = handle_exception(exc)
        raise RuntimeError(f"Merge job failed. Crash report: {crash_path}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge unique files from a source into a target.")
    parser.add_argument("--source", required=True, help="Source folder (e.g., 13_AUDIO_OLD)")
    parser.add_argument("--target", required=True, help="Target folder (e.g., 13_AUDIO)")
    parser.add_argument("--inbox", default=None, help="Inbox folder for non-audio files")
    parser.add_argument("--config", default=None, help="Optional config path override")
    parser.add_argument("--apply", action="store_true", help="Apply moves (default: dry run)")
    parser.add_argument("--delete-old", action="store_true", help="Delete source after successful moves")
    parser.add_argument("--report", default=None, help="Report JSON output path")
    args = parser.parse_args()

    config_path = Path(args.config) if args.config else None
    config = AppConfig.load(config_path)
    logs_root = config.resolve_path("paths", "logs", default="logs")
    loggers = setup_logging(logs_root)
    logger = loggers["main"]

    try:
        run_merge_job(
            config,
            source_root=Path(args.source),
            target_root=Path(args.target),
            inbox_root=Path(args.inbox) if args.inbox else None,
            apply=args.apply,
            delete_old=args.delete_old,
            report_path=Path(args.report) if args.report else None,
            logger=logger,
            job_name="cli_merge",
        )
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
