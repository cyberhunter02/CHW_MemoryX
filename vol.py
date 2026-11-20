
#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
"""
CHW MemoryX
Advanced Memory Forensics Workstation - Volatility 3 Unified Launcher & AI-Powered Backend
"""

import csv
import datetime
import hashlib
import io
import json
import logging
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import volatility3.cli
import volatility3.framework
import volatility3.plugins

# Optional requests import (falls back to urllib.request if requests is not installed)
try:
    import requests as ext_requests
except ImportError:
    ext_requests = None

# ---------------------------------------------------------------------------
# BRANDING, AI CONFIGURATION & CORE PATHS
# ---------------------------------------------------------------------------
PRODUCT_NAME = "CHW MemoryX"
PRODUCT_SUBTITLE = "Memory Forensics Workstation • Volatility 3 Engine"
COMPANY_LOGO_URL = "https://iili.io/fU82tG2.png"

CHW_AI_URL = "https://chwchatgpt.vercel.app/v1/chat/completions"
CHW_AI_KEY = "chw_live_aac76cfd212c5287ec3e415519a5e691da2bd527"
CHW_AI_MODEL = "1"

# AI Conversation Memory Limits (last 5 user+assistant turns / messages, auto-trimmed by char budget)
AI_MAX_HISTORY_TURNS = 5       # Keeps up to last 5 exchanges (up to 10 messages: 5 user + 5 assistant)
AI_MAX_HISTORY_CHARS = 6500    # Auto-trims oldest messages if conversation history exceeds this budget
AI_MAX_CONTEXT_CHARS = 9000    # Max forensic command output characters sent alongside prompt

BASE_DIR = Path(__file__).resolve().parent
INDEX_HTML_PATH = BASE_DIR / "index.html"
RESULTS_ROOT = BASE_DIR / "CHW_Results"
GLOBAL_STATE_FILE = RESULTS_ROOT / "workstation_state.json"
SERVER_LOG_FILE = RESULTS_ROOT / "chw_server.log"

MAX_INTERNAL_WORKERS = 3

CASE_SUBDIRS = [
    "Evidence",
    "Command_Outputs",
    "Extracted_Files",
    "Reports",
    "Hashes",
    "Logs",
    "Uploads_Temp",
]

CASE_ID_REGEX = re.compile(r"^[A-Za-z0-9_-]{2,64}$")
PLUGIN_NAME_REGEX = re.compile(r"^[A-Za-z0-9_.]+$")
SAFE_FILENAME_REGEX = re.compile(r"[^A-Za-z0-9._-]")

# Runtime State & Thread Locks
STATE_LOCK = threading.RLock()
JOBS_LOCK = threading.RLock()
AI_CHAT_LOCK = threading.RLock()

WORKSTATION_STATE: Dict[str, Any] = {
    "active_case": None,
    "active_evidence": None,
    "max_concurrent_jobs": MAX_INTERNAL_WORKERS,
    "theme": "dark",
    "server_host": "127.0.0.1",
    "server_port": 5000,
    "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
}

JOBS: Dict[str, Dict[str, Any]] = {}
ACTIVE_PROCESSES: Dict[str, subprocess.Popen] = {}
INTERNAL_WORKER_SLOTS: Dict[int, Optional[str]] = {1: None, 2: None, 3: None}
CACHED_PLUGINS: List[Dict[str, Any]] = []
PLUGIN_HELP_CACHE: Dict[str, str] = {}
AI_CHAT_SESSIONS: Dict[str, List[Dict[str, str]]] = {}


# ---------------------------------------------------------------------------
# INITIALIZATION & LOGGING
# ---------------------------------------------------------------------------
def ensure_root_storage() -> None:
    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
    if GLOBAL_STATE_FILE.exists():
        try:
            saved = json.loads(GLOBAL_STATE_FILE.read_text(encoding="utf-8"))
            with STATE_LOCK:
                for k in ("active_case", "active_evidence", "theme"):
                    if k in saved:
                        WORKSTATION_STATE[k] = saved[k]
                WORKSTATION_STATE["max_concurrent_jobs"] = MAX_INTERNAL_WORKERS
        except Exception:
            pass


def save_global_state() -> None:
    with STATE_LOCK:
        payload = {
            "active_case": WORKSTATION_STATE.get("active_case"),
            "active_evidence": WORKSTATION_STATE.get("active_evidence"),
            "max_concurrent_jobs": MAX_INTERNAL_WORKERS,
            "theme": WORKSTATION_STATE.get("theme", "dark"),
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        GLOBAL_STATE_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def setup_logging() -> logging.Logger:
    ensure_root_storage()
    logger = logging.getLogger("CHW_MemoryX")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        fh = logging.FileHandler(SERVER_LOG_FILE, encoding="utf-8")
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


LOGGER = setup_logging()


# ---------------------------------------------------------------------------
# SECURITY, HASHING & PATH HELPERS
# ---------------------------------------------------------------------------
def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sanitize_filename(name: str) -> str:
    cleaned = SAFE_FILENAME_REGEX.sub("_", os.path.basename(name.strip()))
    return cleaned or f"artifact_{int(time.time())}"


def validate_case_id(case_id: str) -> bool:
    return bool(case_id and CASE_ID_REGEX.match(case_id))


def get_case_dir(case_id: str) -> Path:
    if not validate_case_id(case_id):
        raise ValueError(f"Invalid Case ID format: {case_id}")
    target = (RESULTS_ROOT / case_id).resolve()
    if RESULTS_ROOT.resolve() not in target.parents:
        raise ValueError("Path traversal detected in Case ID.")
    return target


def safe_case_subpath(case_id: str, *parts: str) -> Path:
    case_dir = get_case_dir(case_id)
    target = case_dir.joinpath(*parts).resolve()
    if case_dir not in target.parents and target != case_dir:
        raise ValueError("Path traversal blocked outside active case directory.")
    return target


def log_case_event(case_id: str, event_type: str, message: str, details: Optional[Dict] = None) -> None:
    try:
        case_dir = get_case_dir(case_id)
        if not case_dir.exists():
            return
        log_dir = case_dir / "Logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        activity_log = log_dir / "case_activity.log"
        entry = {
            "timestamp": utc_now(),
            "case_id": case_id,
            "type": event_type,
            "message": message,
            "details": details or {},
        }
        with open(activity_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as exc:
        LOGGER.error(f"Failed writing case event for {case_id}: {exc}")


def compute_sha256_incremental(file_path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0 or unit == "TB":
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{num_bytes} B"


def safe_int(value: Any, default: int = 0) -> int:
    try:
        s = str(value).strip().replace(",", "")
        if not s or s.lower() in ("n/a", "-", "none", "null"):
            return default
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(float(s))
    except Exception:
        return default


# ---------------------------------------------------------------------------
# TARGET MEMORY DUMP PHYSICAL PAGE OCCUPANCY & ACCURATE OS DETECTION
# ---------------------------------------------------------------------------
def sample_dump_physical_ram_occupancy(file_path: Path, sample_pages: int = 2048) -> Dict[str, Any]:
    """
    Samples evenly-spaced 4KB physical pages directly across the TARGET memory dump file
    to compute real physical memory page occupancy (active non-zero pages vs zeroed/free pages).
    """
    try:
        size_bytes = file_path.stat().st_size
        page_size = 4096
        if size_bytes < page_size:
            return {
                "sampled_pages": 0,
                "active_pages": 0,
                "occupancy_percent": 0.0,
                "estimated_used_gb": 0.0,
                "total_ram_gb": round(size_bytes / (1024 ** 3), 2),
            }

        total_pages = size_bytes // page_size
        actual_samples = min(sample_pages, total_pages)
        step = max(1, total_pages // actual_samples)
        zero_page = b"\x00" * page_size
        active_count = 0

        with open(file_path, "rb") as f:
            for i in range(actual_samples):
                f.seek(i * step * page_size)
                page = f.read(page_size)
                if len(page) == page_size and page != zero_page:
                    active_count += 1

        occ_pct = round((active_count / max(1, actual_samples)) * 100.0, 1)
        total_gb = round(size_bytes / (1024 ** 3), 2)
        used_gb = round(total_gb * (occ_pct / 100.0), 2)
        return {
            "sampled_pages": actual_samples,
            "active_pages": active_count,
            "occupancy_percent": occ_pct,
            "estimated_used_gb": used_gb,
            "total_ram_gb": total_gb,
        }
    except Exception as exc:
        LOGGER.warning(f"Dump page occupancy sampling failed for {file_path}: {exc}")
        return {
            "sampled_pages": 0,
            "active_pages": 0,
            "occupancy_percent": 0.0,
            "estimated_used_gb": 0.0,
            "total_ram_gb": 0.0,
        }


def detect_memory_image_os(file_path: Path) -> Dict[str, Any]:
    """
    Accurately inspects the TARGET memory dump (.mem, .dmp, .raw, .vmem, .lime, .elf)
    to detect Windows, Linux, or macOS directly from the dump image itself and extract
    real kernel/hardware specifications (OS version, architecture, CPU cores, capture time).
    """
    size_bytes = file_path.stat().st_size
    size_gb = round(size_bytes / (1024 ** 3), 2)
    ram_occ = sample_dump_physical_ram_occupancy(file_path)

    detected_os = "Unknown"
    confidence = "Low"
    detection_method = "Binary Signature Scan"
    banner_summary = ""
    target_arch = "Unknown"
    target_cpu_cores = 0
    capture_time = ""

    system_details: Dict[str, str] = {
        "Dump Image Size": f"{size_gb} GB ({human_size(size_bytes)})",
        "Image Format": file_path.suffix.lower() or ".raw",
        "Non-Zero Physical RAM": f"{ram_occ['estimated_used_gb']} GB / {size_gb} GB ({ram_occ['occupancy_percent']}%)",
    }

    win_score = 0
    lin_score = 0
    mac_score = 0

    # Step 1: Multi-offset binary header & kernel signature inspection across the dump
    try:
        fractions = [0.0, 0.05, 0.15, 0.30, 0.50, 0.70]
        seen_offsets = set()
        window_size = 8 * 1024 * 1024  # 8 MB per sample window

        with open(file_path, "rb") as f:
            for frac in fractions:
                off = int(size_bytes * frac)
                if off in seen_offsets or off >= size_bytes:
                    continue
                seen_offsets.add(off)
                f.seek(off)
                buf = f.read(window_size)
                if not buf:
                    continue

                if off == 0:
                    # Windows Crash Dump signatures
                    if buf.startswith((b"PAGEDUMP", b"PAGEDU64", b"PAGEIDLE", b"MDMP")):
                        win_score += 40
                        hdr = buf[:8].decode("ascii", errors="ignore").strip()
                        system_details["Dump Header"] = hdr
                        if b"64" in buf[:8]:
                            target_arch = "64-bit (x64)"
                    # LiME (Linux Memory Extractor) magic header: "EMiL" (0x4C694D45 little-endian)
                    elif buf.startswith(b"EMiL") or buf.startswith(b"LiME"):
                        lin_score += 40
                        system_details["Dump Header"] = "LiME Linux Memory Image"
                    # ELF core dump (common for Linux/KVM/VirtualBox dumps)
                    elif buf.startswith(b"\x7fELF"):
                        lin_score += 12
                        system_details["Dump Header"] = "ELF Core Memory Dump"

                # Strong Linux kernel signatures
                if b"Linux version " in buf:
                    lin_score += 35
                    m = re.search(rb"Linux version [0-9]+\.[0-9]+\.[0-9]+[^\x00\r\n]{0,120}", buf)
                    if m and not banner_summary:
                        banner_summary = m.group(0).decode("latin-1", errors="ignore").strip()
                        if "x86_64" in banner_summary or "amd64" in banner_summary:
                            target_arch = "64-bit (x86_64)"
                        elif "aarch64" in banner_summary or "arm64" in banner_summary:
                            target_arch = "64-bit (ARM64)"
                        elif "i386" in banner_summary or "i686" in banner_summary:
                            target_arch = "32-bit (x86)"
                if b"swapper/0" in buf or b"kthreadd" in buf or b"BOOT_IMAGE=" in buf:
                    lin_score += 10
                if b"/sbin/init" in buf or b"systemd-journald" in buf or b"vmlinux" in buf:
                    lin_score += 8

                # Strong macOS / Darwin signatures
                if b"Darwin Kernel Version " in buf:
                    mac_score += 35
                    m = re.search(rb"Darwin Kernel Version [0-9]+\.[0-9]+\.[0-9]+[^\x00\r\n]{0,120}", buf)
                    if m and not banner_summary:
                        banner_summary = m.group(0).decode("latin-1", errors="ignore").strip()
                        if "x86_64" in banner_summary:
                            target_arch = "64-bit (x86_64)"
                        elif "ARM64" in banner_summary:
                            target_arch = "64-bit (ARM64)"
                if b"mach_kernel" in buf or b"com.apple.kpi." in buf or b"/sbin/launchd" in buf:
                    mac_score += 10

                # Strong Windows NT kernel signatures
                if b"ntoskrnl.exe" in buf or b"\\SystemRoot\\System32\\ntoskrnl" in buf:
                    win_score += 20
                if b"\\SystemRoot\\System32\\" in buf or b"KDBG" in buf or b"hal.dll" in buf:
                    win_score += 12
                if b"lsass.exe" in buf or b"csrss.exe" in buf or b"svchost.exe" in buf or b"wininit.exe" in buf:
                    win_score += 10
                if b"Microsoft (R) Windows" in buf or b"Windows NT" in buf:
                    win_score += 8

        if win_score > lin_score and win_score > mac_score and win_score >= 12:
            detected_os = "Windows"
            confidence = "High" if win_score >= 25 else "Medium"
        elif lin_score > win_score and lin_score > mac_score and lin_score >= 12:
            detected_os = "Linux"
            confidence = "High" if lin_score >= 25 else "Medium"
        elif mac_score > win_score and mac_score > lin_score and mac_score >= 12:
            detected_os = "macOS"
            confidence = "High" if mac_score >= 25 else "Medium"
    except Exception as exc:
        LOGGER.warning(f"Binary signature scan warning on {file_path}: {exc}")

    # Step 2: Volatility 3 native probe (windows.info for Windows/Unknown; banners.Banners for Linux/macOS/Unknown)
    if detected_os in ("Windows", "Unknown"):
        try:
            p_win = resolve_plugin_name("windows.info") or "windows.info.Info"
            proc = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--cli", "-f", str(file_path), p_win],
                capture_output=True,
                text=True,
                timeout=35,
                check=False,
            )
            if proc.returncode == 0 and any(k in proc.stdout for k in ("Kernel Base", "NTBuildLab", "Major/Minor", "NtMajorVersion")):
                detected_os = "Windows"
                confidence = "Verified (Volatility Engine)"
                detection_method = "Volatility windows.info"
                parsed = parse_volatility_tabular_output(proc.stdout)
                for row in parsed.get("rows", []):
                    k = str(row.get("Variable", "")).strip()
                    v = str(row.get("Value", "")).strip()
                    if k and v:
                        system_details[k] = v
                if system_details.get("Is64Bit", "").lower() == "true":
                    target_arch = "64-bit (x64)"
                elif system_details.get("Is64Bit", "").lower() == "false":
                    target_arch = "32-bit (x86)"
                target_cpu_cores = safe_int(
                    system_details.get("NtNumberProcessors") or system_details.get("Processors"),
                    0,
                )
                capture_time = system_details.get("SystemTime", "")
                banner_summary = (
                    system_details.get("NTBuildLab")
                    or system_details.get("Major/Minor")
                    or "Windows NT Kernel Verified"
                )
        except Exception as exc:
            LOGGER.warning(f"windows.info probe skipped/timed out: {exc}")

    if detected_os in ("Linux", "macOS", "Unknown"):
        try:
            p_ban = resolve_plugin_name("banners.Banners") or "banners.Banners"
            proc = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--cli", "-f", str(file_path), p_ban],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            out = proc.stdout or ""
            for ln in out.splitlines():
                if "Linux version" in ln:
                    detected_os = "Linux"
                    confidence = "Verified (Volatility Banners)"
                    detection_method = "Volatility banners.Banners"
                    m = re.search(r"Linux version .+", ln)
                    banner_summary = m.group(0).strip() if m else ln.strip()
                    if "x86_64" in banner_summary or "amd64" in banner_summary:
                        target_arch = "64-bit (x86_64)"
                    elif "aarch64" in banner_summary or "arm64" in banner_summary:
                        target_arch = "64-bit (ARM64)"
                    break
                if "Darwin Kernel Version" in ln:
                    detected_os = "macOS"
                    confidence = "Verified (Volatility Banners)"
                    detection_method = "Volatility banners.Banners"
                    m = re.search(r"Darwin Kernel Version .+", ln)
                    banner_summary = m.group(0).strip() if m else ln.strip()
                    if "x86_64" in banner_summary:
                        target_arch = "64-bit (x86_64)"
                    elif "ARM64" in banner_summary:
                        target_arch = "64-bit (ARM64)"
                    break
        except Exception as exc:
            LOGGER.warning(f"banners.Banners probe skipped/timed out: {exc}")

    if banner_summary:
        system_details["Kernel Banner / Build"] = banner_summary
    if target_arch != "Unknown":
        system_details["Target Architecture"] = target_arch
    if target_cpu_cores > 0:
        system_details["Target CPU Cores"] = str(target_cpu_cores)
    if capture_time:
        system_details["Dump Capture Time (UTC)"] = capture_time

    return {
        "detected_os": detected_os,
        "confidence": confidence,
        "detection_method": detection_method,
        "banner_summary": banner_summary or f"{detected_os} Memory Image",
        "target_arch": target_arch,
        "target_cpu_cores": target_cpu_cores,
        "capture_time": capture_time,
        "ram_size_gb": size_gb,
        "ram_size_human": human_size(size_bytes),
        "ram_occupancy": ram_occ,
        "system_details": system_details,
    }


# ---------------------------------------------------------------------------
# TARGET MEMORY DUMP FORENSIC TELEMETRY (100% FROM DUMP — ZERO HOST STATS)
# ---------------------------------------------------------------------------
def _find_latest_completed_run_data(case_id: str, evidence_id: str, plugin_keywords: List[str]) -> Optional[Dict[str, Any]]:
    """
    Loads the latest completed structured output.json matching any plugin keyword for the active evidence.
    """
    try:
        case_dir = get_case_dir(case_id)
        hist_file = case_dir / "command_history.json"
        if not hist_file.exists():
            return None
        history = json.loads(hist_file.read_text(encoding="utf-8"))
        for entry in history:
            if entry.get("status") != "Completed":
                continue
            if evidence_id and entry.get("evidence_id") and entry.get("evidence_id") != evidence_id:
                continue
            p_lower = (entry.get("plugin") or "").lower()
            rp_lower = (entry.get("resolved_plugin") or "").lower()
            if any(k in p_lower or k in rp_lower for k in plugin_keywords):
                out_dir = entry.get("output_directory", "")
                json_path = case_dir / out_dir / "output.json"
                if json_path.exists():
                    return json.loads(json_path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None


def extract_dump_forensic_telemetry(case_id: Optional[str], ev_obj: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes 100% target-memory-dump telemetry (NOT investigator's host machine):
      - Target OS, Architecture, Kernel Build, Capture Time
      - Target CPU Cores & Estimated CPU/Thread Activity Load at dump capture time
      - Target Physical RAM Usage (GB & %) from Volatility statistics + dump page occupancy
      - Active Processes, Exited Processes, Total Threads, Open Handles, Top Processes, Network & Malfind hits
    """
    if not case_id or not ev_obj:
        return {
            "has_evidence": False,
            "target_os": "No Dump Loaded",
            "os_confidence": "None",
            "target_arch": "Unknown",
            "kernel_version": "Upload or select a memory dump",
            "capture_time": "N/A",
            "target_cpu_cores": 0,
            "dump_cpu_load_percent": 0.0,
            "dump_cpu_note": "No active memory image",
            "dump_ram_total_gb": 0.0,
            "dump_ram_used_gb": 0.0,
            "dump_ram_percent": 0.0,
            "dump_ram_swapped_percent": 0.0,
            "dump_ram_source": "None",
            "active_processes": 0,
            "terminated_processes": 0,
            "total_threads": 0,
            "total_handles": 0,
            "network_connections": 0,
            "malfind_hits": 0,
            "top_processes": [],
            "system_details": {},
        }

    ev_id = ev_obj.get("evidence_id", "")
    sys_details = dict(ev_obj.get("system_details") or {})
    detected_os = ev_obj.get("detected_os", "Unknown")
    ram_total_gb = float(ev_obj.get("ram_size_gb") or 0.0)
    if ram_total_gb == 0.0 and ev_obj.get("size_bytes"):
        ram_total_gb = round(int(ev_obj["size_bytes"]) / (1024 ** 3), 2)

    # 1. Enrich kernel & CPU cores from windows.info or banners if completed
    info_data = _find_latest_completed_run_data(case_id, ev_id, ["windows.info", "banners.banners", "linux.banners", "mac.banners"])
    if info_data and info_data.get("rows"):
        for r in info_data["rows"]:
            var_k = str(r.get("Variable") or "").strip()
            var_v = str(r.get("Value") or "").strip()
            if var_k and var_v:
                sys_details[var_k] = var_v
            elif r.get("Banner"):
                sys_details["Kernel Banner / Build"] = str(r["Banner"]).strip()

    target_cpu_cores = safe_int(
        sys_details.get("NtNumberProcessors")
        or sys_details.get("Processors")
        or sys_details.get("Target CPU Cores")
        or ev_obj.get("target_cpu_cores"),
        0,
    )

    target_arch = ev_obj.get("target_arch") or sys_details.get("Target Architecture") or "Unknown"
    if target_arch == "Unknown":
        if sys_details.get("Is64Bit", "").lower() == "true":
            target_arch = "64-bit (x64)"
        elif sys_details.get("Is64Bit", "").lower() == "false":
            target_arch = "32-bit (x86)"

    capture_time = sys_details.get("SystemTime") or ev_obj.get("capture_time") or "Not in header"
    kernel_version = (
        sys_details.get("NTBuildLab")
        or sys_details.get("Kernel Banner / Build")
        or sys_details.get("Major/Minor")
        or ev_obj.get("banner_summary")
        or detected_os
    )

    # 2. Target Physical RAM Utilization (from windows.statistics first, fallback to direct dump 4KB page occupancy)
    ram_occ = ev_obj.get("ram_occupancy")
    if not ram_occ and ev_obj.get("path") and Path(ev_obj["path"]).exists():
        ram_occ = sample_dump_physical_ram_occupancy(Path(ev_obj["path"]))

    dump_ram_pct = float((ram_occ or {}).get("occupancy_percent") or 0.0)
    dump_ram_used_gb = round(ram_total_gb * (dump_ram_pct / 100.0), 2)
    dump_ram_swapped_pct = 0.0
    dump_ram_source = "Dump Physical 4KB Page Occupancy"

    stats_data = _find_latest_completed_run_data(case_id, ev_id, ["windows.statistics"])
    if stats_data and stats_data.get("rows"):
        valid_pages = 0
        swapped_pages = 0
        invalid_pages = 0
        for row in stats_data["rows"]:
            for k, v in row.items():
                kl = k.lower()
                val_int = safe_int(v, 0)
                if "valid" in kl and "invalid" not in kl and "all" in kl:
                    valid_pages = max(valid_pages, val_int)
                elif "swapped" in kl and "all" in kl:
                    swapped_pages = max(swapped_pages, val_int)
                elif "invalid" in kl and "other" not in kl and "all" in kl:
                    invalid_pages = max(invalid_pages, val_int)
        total_tracked = valid_pages + swapped_pages + invalid_pages
        if total_tracked > 0 and valid_pages > 0:
            dump_ram_pct = round((valid_pages / total_tracked) * 100.0, 1)
            dump_ram_swapped_pct = round((swapped_pages / total_tracked) * 100.0, 1)
            dump_ram_used_gb = round(ram_total_gb * (dump_ram_pct / 100.0), 2)
            dump_ram_source = "Volatility windows.statistics (Valid Pages)"

    # 3. Target Processes, Threads, Handles & Snapshot CPU Activity Load (from pslist)
    active_processes = 0
    terminated_processes = 0
    total_threads = 0
    total_handles = 0
    top_processes: List[Dict[str, Any]] = []

    ps_data = _find_latest_completed_run_data(case_id, ev_id, ["windows.pslist", "linux.pslist", "mac.pslist"])
    if ps_data and ps_data.get("rows"):
        proc_entries = []
        for row in ps_data["rows"]:
            pid = str(row.get("PID") or row.get("Pid") or "").strip()
            name = str(
                row.get("ImageFileName")
                or row.get("COMM")
                or row.get("NAME")
                or row.get("Process")
                or ""
            ).strip()
            exit_time = str(row.get("ExitTime") or "").strip()
            threads = safe_int(row.get("Threads"), 0)
            handles = safe_int(row.get("Handles"), 0)

            is_terminated = bool(exit_time and exit_time.lower() not in ("n/a", "-", "none", "null"))
            if is_terminated:
                terminated_processes += 1
            else:
                active_processes += 1
                total_threads += threads
                total_handles += handles
                if name:
                    proc_entries.append({
                        "pid": pid,
                        "name": name,
                        "threads": threads,
                        "handles": handles,
                    })

        proc_entries.sort(key=lambda x: (x["threads"], x["handles"]), reverse=True)
        top_processes = proc_entries[:6]

    # Estimate Target CPU Load Index at capture time from dump's active processes/threads & CPU cores
    # (Static RAM images freeze state; thread density per core + active process pressure represents workload at capture)
    if active_processes > 0:
        effective_cores = target_cpu_cores if target_cpu_cores > 0 else 4
        if total_threads > 0:
            # Typical idle OS has ~250-350 threads per 4 cores; heavy load approaches 600+ threads/core
            threads_per_core = total_threads / float(effective_cores)
            dump_cpu_load_pct = round(min(98.5, max(4.0, (threads_per_core / 350.0) * 100.0)), 1)
            dump_cpu_note = (
                f"{target_cpu_cores or 'Est. 4'} Cores • {active_processes} Active Procs • "
                f"{total_threads:,} Active Threads ({round(threads_per_core, 1)}/core)"
            )
        else:
            # Linux/macOS pslist doesn't always expose thread count column -> estimate from active tasks/core
            tasks_per_core = active_processes / float(effective_cores)
            dump_cpu_load_pct = round(min(95.0, max(5.0, (tasks_per_core / 60.0) * 100.0)), 1)
            dump_cpu_note = f"{active_processes} Active Tasks in Dump ({effective_cores} Cores)"
    else:
        dump_cpu_load_pct = 0.0
        dump_cpu_note = "Run pslist (or wait for auto-triage) to compute target CPU/thread workload"

    # 4. Network & Malware counts if those plugins have been run
    net_data = _find_latest_completed_run_data(case_id, ev_id, ["netscan", "netstat", "sockstat"])
    network_connections = int(net_data.get("row_count", 0)) if net_data else 0

    mal_data = _find_latest_completed_run_data(case_id, ev_id, ["malfind"])
    malfind_hits = int(mal_data.get("row_count", 0)) if mal_data else 0

    return {
        "has_evidence": True,
        "evidence_filename": ev_obj.get("filename", ""),
        "target_os": detected_os,
        "os_confidence": ev_obj.get("os_confidence", "Detected"),
        "target_arch": target_arch,
        "kernel_version": kernel_version,
        "capture_time": capture_time,
        "target_cpu_cores": target_cpu_cores,
        "dump_cpu_load_percent": dump_cpu_load_pct,
        "dump_cpu_note": dump_cpu_note,
        "dump_ram_total_gb": ram_total_gb,
        "dump_ram_used_gb": dump_ram_used_gb,
        "dump_ram_percent": dump_ram_pct,
        "dump_ram_swapped_percent": dump_ram_swapped_pct,
        "dump_ram_source": dump_ram_source,
        "active_processes": active_processes,
        "terminated_processes": terminated_processes,
        "total_threads": total_threads,
        "total_handles": total_handles,
        "network_connections": network_connections,
        "malfind_hits": malfind_hits,
        "top_processes": top_processes,
        "system_details": sys_details,
    }


# ---------------------------------------------------------------------------
# CASE & EVIDENCE STORAGE HELPERS
# ---------------------------------------------------------------------------
def load_case_metadata(case_id: str) -> Dict[str, Any]:
    case_dir = get_case_dir(case_id)
    case_file = case_dir / "case.json"
    if not case_file.exists():
        raise FileNotFoundError(f"Case '{case_id}' does not exist.")
    return json.loads(case_file.read_text(encoding="utf-8"))


def save_case_metadata(case_id: str, data: Dict[str, Any]) -> None:
    case_dir = get_case_dir(case_id)
    case_file = case_dir / "case.json"
    data["updated_at"] = utc_now()
    case_file.write_text(json.dumps(data, indent=2), encoding="utf-8")


def list_all_cases() -> List[Dict[str, Any]]:
    ensure_root_storage()
    cases = []
    for item in sorted(RESULTS_ROOT.iterdir()):
        if item.is_dir() and (item / "case.json").exists():
            try:
                meta = json.loads((item / "case.json").read_text(encoding="utf-8"))
                cmd_root = item / "Command_Outputs"
                run_count = 0
                if cmd_root.exists():
                    for p_dir in cmd_root.iterdir():
                        if p_dir.is_dir():
                            run_count += sum(1 for r in p_dir.iterdir() if r.is_dir() and r.name.startswith("run_"))
                ext_dir = item / "Extracted_Files"
                ext_count = sum(1 for f in ext_dir.rglob("*") if f.is_file()) if ext_dir.exists() else 0
                rep_dir = item / "Reports"
                rep_count = sum(1 for f in rep_dir.iterdir() if f.is_file()) if rep_dir.exists() else 0

                meta["stats"] = {
                    "evidence_count": len(meta.get("evidence", [])),
                    "command_runs": run_count,
                    "extracted_files": ext_count,
                    "reports_count": rep_count,
                }
                cases.append(meta)
            except Exception as exc:
                LOGGER.warning(f"Skipping malformed case folder {item}: {exc}")
    return cases


def get_evidence_record(case_id: str, evidence_id: str) -> Optional[Dict[str, Any]]:
    meta = load_case_metadata(case_id)
    for ev in meta.get("evidence", []):
        if ev.get("evidence_id") == evidence_id:
            return ev
    return None


def record_hash_entry(case_id: str, category: str, filename: str, rel_path: str, size_bytes: int, sha256_hex: str) -> Dict[str, Any]:
    hashes_dir = safe_case_subpath(case_id, "Hashes")
    hashes_dir.mkdir(parents=True, exist_ok=True)
    manifest_file = hashes_dir / "hash_registry.json"
    records = []
    if manifest_file.exists():
        try:
            records = json.loads(manifest_file.read_text(encoding="utf-8"))
        except Exception:
            records = []

    record = {
        "record_id": f"HASH-{uuid.uuid4().hex[:10].upper()}",
        "timestamp": utc_now(),
        "case_id": case_id,
        "category": category,
        "filename": filename,
        "relative_path": rel_path,
        "size_bytes": size_bytes,
        "size_human": human_size(size_bytes),
        "algorithm": "SHA-256",
        "sha256": sha256_hex,
    }
    records.append(record)
    manifest_file.write_text(json.dumps(records, indent=2), encoding="utf-8")
    return record


# ---------------------------------------------------------------------------
# VOLATILITY 3 DYNAMIC PLUGIN DISCOVERY, OS FILTERING & CSV/TABLE PARSING
# ---------------------------------------------------------------------------
def categorize_plugin(plugin_name: str) -> Tuple[str, str]:
    lower = plugin_name.lower()
    if lower.startswith("windows."):
        os_type = "Windows"
    elif lower.startswith("linux."):
        os_type = "Linux"
    elif lower.startswith("mac."):
        os_type = "macOS"
    else:
        os_type = "Cross-Platform"

    if any(k in lower for k in ["pslist", "pstree", "psscan", "cmdline", "envars", "getsids", "handles", "pid", "psaux"]):
        cat = "Process Analysis"
    elif any(k in lower for k in ["netscan", "netstat", "sock", "ifconfig"]):
        cat = "Network Analysis"
    elif any(k in lower for k in ["malfind", "ldrmodules", "callbacks", "ssdt", "hollow", "check_", "tty_check", "kmsg"]):
        cat = "Malware Analysis"
    elif any(k in lower for k in ["memmap", "vad", "virtmap", "maps", "proc", "statistics"]):
        cat = "Memory Analysis"
    elif any(k in lower for k in ["dlllist", "modules", "lsmod", "modscan"]):
        cat = "DLL & Modules"
    elif any(k in lower for k in ["filescan", "dumpfiles", "lsof", "elist"]):
        cat = "File Analysis"
    elif "registry" in lower:
        cat = "Registry Analysis"
    elif any(k in lower for k in ["svcscan", "driver", "service"]):
        cat = "Services & Drivers"
    elif any(k in lower for k in ["info", "banner", "timeliner", "layerwriter", "isfinfo"]):
        cat = "System Information"
    else:
        cat = "General / Other"

    return os_type, cat


def discover_installed_plugins(force_refresh: bool = False) -> List[Dict[str, Any]]:
    global CACHED_PLUGINS
    if CACHED_PLUGINS and not force_refresh:
        return CACHED_PLUGINS

    discovered: List[Dict[str, Any]] = []
    try:
        volatility3.framework.import_files(volatility3.plugins, True)
        plugin_list = volatility3.framework.list_plugins()
        for name in sorted(plugin_list.keys()):
            cls = plugin_list[name]
            doc = (cls.__doc__ or "Official Volatility 3 forensic plugin.").strip().splitlines()[0]
            os_type, category = categorize_plugin(name)

            reqs = []
            try:
                for req in cls.get_requirements():
                    reqs.append({
                        "name": getattr(req, "name", ""),
                        "description": getattr(req, "description", ""),
                        "optional": bool(getattr(req, "optional", True)),
                        "default": getattr(req, "default", None),
                    })
            except Exception:
                pass

            discovered.append({
                "name": name,
                "os": os_type,
                "category": category,
                "description": doc,
                "requirements": reqs,
                "supports_extraction": any(k in name.lower() for k in ["dumpfiles", "memmap", "pslist", "malfind", "layerwriter"]),
            })
    except Exception as exc:
        LOGGER.error(f"Framework plugin discovery fallback triggered: {exc}")

    CACHED_PLUGINS = discovered
    return discovered


def filter_plugins_for_os(plugins: List[Dict[str, Any]], target_os: Optional[str]) -> List[Dict[str, Any]]:
    if not target_os or target_os in ("All", "ALL", "Unknown"):
        return plugins
    norm = target_os.strip().lower()
    return [p for p in plugins if p.get("os", "").lower() in (norm, "cross-platform")]


def resolve_plugin_name(requested_name: str) -> Optional[str]:
    plugins = discover_installed_plugins()
    names = {p["name"]: p["name"] for p in plugins}
    if requested_name in names:
        return requested_name
    lower_map = {p["name"].lower(): p["name"] for p in plugins}
    if requested_name.lower() in lower_map:
        return lower_map[requested_name.lower()]
    prefix = requested_name.lower() + "."
    for lower_full, exact in lower_map.items():
        if lower_full.startswith(prefix):
            return exact
    return None


def parse_volatility_tabular_output(raw_text: str) -> Dict[str, Any]:
    lines = [ln.rstrip("\r\n") for ln in raw_text.splitlines()]
    non_empty = [ln for ln in lines if ln.strip() and not ln.startswith("Volatility 3 Framework")]
    if not non_empty:
        return {"parsed": False, "columns": [], "rows": [], "row_count": 0, "format": "raw"}

    header_idx = -1
    columns: List[str] = []
    for idx, line in enumerate(non_empty):
        if "\t" in line:
            candidate_cols = [c.strip() for c in line.split("\t") if c.strip()]
            if len(candidate_cols) >= 2:
                header_idx = idx
                columns = [c.strip() for c in line.split("\t")]
                break

    if header_idx != -1 and len(columns) >= 2:
        rows = []
        for line in non_empty[header_idx + 1:]:
            if not line.strip() or set(line.strip()) <= {"-", "=", " ", "\t"}:
                continue
            parts = [p.strip() for p in line.split("\t")]
            if len(parts) < len(columns):
                parts.extend([""] * (len(columns) - len(parts)))
            elif len(parts) > len(columns):
                parts = parts[: len(columns) - 1] + [" ".join(parts[len(columns) - 1:])]
            rows.append({columns[i]: parts[i] for i in range(len(columns))})
        if rows:
            return {
                "parsed": True,
                "format": "tsv_table",
                "columns": columns,
                "rows": rows,
                "row_count": len(rows),
            }

    for idx, line in enumerate(non_empty[:15]):
        parts = [p.strip() for p in re.split(r"\s{2,}", line.strip()) if p.strip()]
        if len(parts) >= 3:
            columns = parts
            rows = []
            for dline in non_empty[idx + 1:]:
                if not dline.strip() or set(dline.strip()) <= {"-", "=", " "}:
                    continue
                dparts = [p.strip() for p in re.split(r"\s{2,}", dline.strip())]
                if len(dparts) >= 2:
                    if len(dparts) < len(columns):
                        dparts.extend([""] * (len(columns) - len(dparts)))
                    elif len(dparts) > len(columns):
                        dparts = dparts[: len(columns) - 1] + [" ".join(dparts[len(columns) - 1:])]
                    rows.append({columns[i]: dparts[i] for i in range(len(columns))})
            if rows:
                return {
                    "parsed": True,
                    "format": "aligned_table",
                    "columns": columns,
                    "rows": rows,
                    "row_count": len(rows),
                }

    fallback_rows = [{"Line_Number": i + 1, "Forensic_Output": ln} for i, ln in enumerate(non_empty)]
    return {
        "parsed": True,
        "format": "line_records",
        "columns": ["Line_Number", "Forensic_Output"],
        "rows": fallback_rows,
        "row_count": len(fallback_rows),
    }


def write_structured_output_to_csv(csv_path: Path, structured: Dict[str, Any]) -> None:
    cols = structured.get("columns") or []
    rows = structured.get("rows") or []
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if cols:
            writer.writerow(cols)
            for r in rows:
                writer.writerow([r.get(c, "") for c in cols])
        else:
            writer.writerow(["Output"])


# ---------------------------------------------------------------------------
# INTERNAL CONCURRENT WORKER POOL (SILENT BACKGROUND EXECUTION)
# ---------------------------------------------------------------------------
def allocate_worker_slot(job_id: str) -> Optional[int]:
    with JOBS_LOCK:
        for slot_num in range(1, MAX_INTERNAL_WORKERS + 1):
            curr_jid = INTERNAL_WORKER_SLOTS.get(slot_num)
            if curr_jid is None:
                INTERNAL_WORKER_SLOTS[slot_num] = job_id
                return slot_num
            curr_job = JOBS.get(curr_jid)
            if not curr_job or curr_job.get("status") not in ("Pending", "Running"):
                INTERNAL_WORKER_SLOTS[slot_num] = job_id
                return slot_num
    return None


def release_worker_slot(job_id: str) -> None:
    with JOBS_LOCK:
        for slot_num in range(1, MAX_INTERNAL_WORKERS + 1):
            if INTERNAL_WORKER_SLOTS.get(slot_num) == job_id:
                INTERNAL_WORKER_SLOTS[slot_num] = None


def allocate_run_directory(case_id: str, plugin_display_name: str) -> Tuple[str, Path]:
    safe_plugin_folder = SAFE_FILENAME_REGEX.sub("_", plugin_display_name.strip())
    plugin_root = safe_case_subpath(case_id, "Command_Outputs", safe_plugin_folder)
    plugin_root.mkdir(parents=True, exist_ok=True)
    existing_runs = []
    for item in plugin_root.iterdir():
        if item.is_dir() and item.name.startswith("run_"):
            try:
                existing_runs.append(int(item.name.split("_")[1]))
            except Exception:
                pass
    next_num = (max(existing_runs) + 1) if existing_runs else 1
    run_id = f"run_{next_num:03d}"
    run_dir = plugin_root / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_id, run_dir


def validate_plugin_arguments(args_list: List[str]) -> List[str]:
    cleaned: List[str] = []
    forbidden_tokens = [";", "&&", "||", "`", "$(", "|", ">", "<", "\n", "\r"]
    for arg in args_list:
        arg_str = str(arg).strip()
        if not arg_str:
            continue
        for bad in forbidden_tokens:
            if bad in arg_str:
                raise ValueError(f"Disallowed shell token '{bad}' in plugin argument '{arg_str}'.")
        cleaned.append(arg_str)
    return cleaned


def append_command_history(case_id: str, history_entry: Dict[str, Any]) -> None:
    case_dir = get_case_dir(case_id)
    history_file = case_dir / "command_history.json"
    history = []
    if history_file.exists():
        try:
            history = json.loads(history_file.read_text(encoding="utf-8"))
        except Exception:
            history = []
    updated = False
    for idx, item in enumerate(history):
        if item.get("job_id") == history_entry.get("job_id"):
            history[idx] = history_entry
            updated = True
            break
    if not updated:
        history.insert(0, history_entry)
    history_file.write_text(json.dumps(history, indent=2), encoding="utf-8")


def _update_evidence_metadata_from_completed_run(
    case_id: str,
    evidence_id: str,
    plugin_name: str,
    structured: Dict[str, Any],
) -> None:
    """
    When info/banner plugins complete on a memory dump, automatically enrich
    evidence system_details, detected_os, architecture, and CPU core count in case.json.
    """
    p_low = plugin_name.lower()
    if not any(k in p_low for k in ("info", "banner")):
        return
    try:
        c_meta = load_case_metadata(case_id)
        changed = False
        for ev in c_meta.get("evidence", []):
            if ev.get("evidence_id") != evidence_id:
                continue
            sys_det = ev.setdefault("system_details", {})
            for r in structured.get("rows", []):
                var_k = str(r.get("Variable") or "").strip()
                var_v = str(r.get("Value") or "").strip()
                if var_k and var_v:
                    sys_det[var_k] = var_v
                    changed = True
                elif r.get("Banner"):
                    b_val = str(r["Banner"]).strip()
                    sys_det["Kernel Banner / Build"] = b_val
                    if "linux version" in b_val.lower():
                        ev["detected_os"] = "Linux"
                        ev["os_confidence"] = "Verified (Volatility Banners)"
                    elif "darwin kernel" in b_val.lower():
                        ev["detected_os"] = "macOS"
                        ev["os_confidence"] = "Verified (Volatility Banners)"
                    changed = True

            if "windows.info" in p_low and (sys_det.get("NTBuildLab") or sys_det.get("Kernel Base")):
                ev["detected_os"] = "Windows"
                ev["os_confidence"] = "Verified (Volatility Engine)"
                if sys_det.get("Is64Bit", "").lower() == "true":
                    ev["target_arch"] = "64-bit (x64)"
                elif sys_det.get("Is64Bit", "").lower() == "false":
                    ev["target_arch"] = "32-bit (x86)"
                cores = safe_int(sys_det.get("NtNumberProcessors") or sys_det.get("Processors"), 0)
                if cores > 0:
                    ev["target_cpu_cores"] = cores
                if sys_det.get("SystemTime"):
                    ev["capture_time"] = sys_det["SystemTime"]
                changed = True

        if changed:
            save_case_metadata(case_id, c_meta)
    except Exception as exc:
        LOGGER.warning(f"Metadata enrichment warning: {exc}")


def execute_volatility_job_worker(job_id: str) -> None:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        job["status"] = "Running"
        job["started_at"] = utc_now()

    start_ts = time.time()
    case_id = job["case_id"]
    run_dir = Path(job["run_dir"])
    cmd_array = job["command_array"]
    extraction_dir = Path(job["extraction_dir"]) if job.get("extraction_dir") else None

    stdout_lines: List[str] = []
    stderr_lines: List[str] = []

    try:
        proc = subprocess.Popen(
            cmd_array,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(BASE_DIR),
            bufsize=1,
        )
        with JOBS_LOCK:
            ACTIVE_PROCESSES[job_id] = proc

        def reader_thread(pipe, target_list, stream_key):
            try:
                for line in iter(pipe.readline, ""):
                    target_list.append(line)
                    with JOBS_LOCK:
                        if job_id in JOBS:
                            JOBS[job_id][stream_key] = "".join(target_list)
                            JOBS[job_id]["line_count"] = len(target_list)
                            JOBS[job_id]["last_line"] = line.strip()[:160]
            except Exception:
                pass
            finally:
                try:
                    pipe.close()
                except Exception:
                    pass

        t_out = threading.Thread(target=reader_thread, args=(proc.stdout, stdout_lines, "stdout"), daemon=True)
        t_err = threading.Thread(target=reader_thread, args=(proc.stderr, stderr_lines, "stderr"), daemon=True)
        t_out.start()
        t_err.start()

        return_code = proc.wait()
        t_out.join(timeout=5)
        t_err.join(timeout=5)

        duration = round(time.time() - start_ts, 2)
        raw_stdout = "".join(stdout_lines)
        raw_stderr = "".join(stderr_lines)

        with JOBS_LOCK:
            was_cancelled = JOBS[job_id].get("status") == "Cancelled"

        final_status = "Cancelled" if was_cancelled else ("Completed" if return_code == 0 else "Failed")
        structured = parse_volatility_tabular_output(raw_stdout)

        output_txt = run_dir / "output.txt"
        stderr_txt = run_dir / "stderr.txt"
        output_json = run_dir / "output.json"
        output_csv = run_dir / "output.csv"
        command_json = run_dir / "command.json"

        output_txt.write_text(raw_stdout, encoding="utf-8")
        stderr_txt.write_text(raw_stderr, encoding="utf-8")
        write_structured_output_to_csv(output_csv, structured)

        extracted_artifacts: List[Dict[str, Any]] = []
        if extraction_dir and extraction_dir.exists():
            for fpath in sorted(extraction_dir.rglob("*")):
                if fpath.is_file():
                    fsize = fpath.stat().st_size
                    fhash = compute_sha256_incremental(fpath)
                    rel_p = str(fpath.relative_to(get_case_dir(case_id)))
                    rec = record_hash_entry(
                        case_id=case_id,
                        category="EXTRACTED_ARTIFACT",
                        filename=fpath.name,
                        rel_path=rel_p,
                        size_bytes=fsize,
                        sha256_hex=fhash,
                    )
                    extracted_artifacts.append(rec)

        structured_payload = {
            "job_id": job_id,
            "case_id": case_id,
            "plugin": job["plugin"],
            "resolved_plugin": job["resolved_plugin"],
            "run_id": job["run_id"],
            "status": final_status,
            "return_code": return_code,
            "parsed": structured["parsed"],
            "format": structured["format"],
            "columns": structured["columns"],
            "row_count": structured["row_count"],
            "rows": structured["rows"],
            "extracted_files": extracted_artifacts,
        }
        output_json.write_text(json.dumps(structured_payload, indent=2), encoding="utf-8")

        if final_status == "Completed":
            _update_evidence_metadata_from_completed_run(
                case_id=case_id,
                evidence_id=job["evidence_id"],
                plugin_name=job["plugin"],
                structured=structured,
            )

        cmd_meta = {
            "job_id": job_id,
            "case_id": case_id,
            "run_id": job["run_id"],
            "plugin": job["plugin"],
            "resolved_plugin": job["resolved_plugin"],
            "arguments": job["plugin_args"],
            "command_preview": job["command_preview"],
            "command_array": [str(x) for x in cmd_array],
            "evidence_id": job["evidence_id"],
            "evidence_filename": job["evidence_filename"],
            "evidence_path": job["evidence_path"],
            "evidence_sha256": job["evidence_sha256"],
            "started_at": job["started_at"],
            "ended_at": utc_now(),
            "duration_seconds": duration,
            "status": final_status,
            "return_code": return_code,
            "row_count": structured["row_count"],
            "output_directory": str(run_dir.relative_to(get_case_dir(case_id))),
            "files": {
                "output_txt": str(output_txt.relative_to(get_case_dir(case_id))),
                "output_json": str(output_json.relative_to(get_case_dir(case_id))),
                "output_csv": str(output_csv.relative_to(get_case_dir(case_id))),
                "stderr_txt": str(stderr_txt.relative_to(get_case_dir(case_id))),
                "command_json": str(command_json.relative_to(get_case_dir(case_id))),
            },
            "extracted_artifacts": extracted_artifacts,
        }
        command_json.write_text(json.dumps(cmd_meta, indent=2), encoding="utf-8")

        with JOBS_LOCK:
            JOBS[job_id].update({
                "status": final_status,
                "ended_at": cmd_meta["ended_at"],
                "duration_seconds": duration,
                "return_code": return_code,
                "stdout": raw_stdout,
                "stderr": raw_stderr,
                "structured": structured_payload,
                "command_meta": cmd_meta,
                "extracted_artifacts": extracted_artifacts,
            })
            ACTIVE_PROCESSES.pop(job_id, None)

        release_worker_slot(job_id)
        append_command_history(case_id, cmd_meta)
        log_case_event(
            case_id,
            "COMMAND_FINISHED",
            f"{job['plugin']} ({job['run_id']}) finished with status {final_status}",
            {"job_id": job_id, "return_code": return_code, "duration_seconds": duration},
        )

    except Exception as exc:
        duration = round(time.time() - start_ts, 2)
        err_msg = f"Internal Execution Error: {exc}"
        LOGGER.exception(err_msg)
        release_worker_slot(job_id)
        with JOBS_LOCK:
            if job_id in JOBS:
                JOBS[job_id].update({
                    "status": "Failed",
                    "ended_at": utc_now(),
                    "duration_seconds": duration,
                    "return_code": -1,
                    "stderr": "".join(stderr_lines) + "\n" + err_msg,
                })
            ACTIVE_PROCESSES.pop(job_id, None)


def launch_plugin_job_internal(
    case_id: str,
    evidence_id: str,
    plugin_req: str,
    validated_args: List[str],
    extraction_mode: bool = False,
    extraction_subdir: str = "",
) -> Tuple[Optional[Dict[str, Any]], Optional[str], int]:
    resolved_plugin = resolve_plugin_name(plugin_req)
    if not resolved_plugin:
        return None, f"Plugin '{plugin_req}' is not available in this Volatility 3 installation.", 404

    ev = get_evidence_record(case_id, evidence_id)
    if not ev:
        return None, "Selected evidence image could not be found in the active case.", 404

    ev_path = Path(ev["path"])
    if not ev_path.exists():
        return None, f"Evidence file missing on disk: {ev_path}", 404

    job_id = f"JOB-{uuid.uuid4().hex[:10].upper()}"
    worker_slot = allocate_worker_slot(job_id)
    if worker_slot is None:
        return (
            None,
            f"Background engine is currently processing {MAX_INTERNAL_WORKERS} commands concurrently. Please wait a moment for one to finish.",
            429,
        )

    run_id, run_dir = allocate_run_directory(case_id, plugin_req)
    extraction_target_dir: Optional[Path] = None
    global_vol_args = ["-f", str(ev_path)]

    if extraction_mode or "--dump" in validated_args or "dumpfiles" in resolved_plugin.lower():
        folder_label = sanitize_filename(extraction_subdir) if extraction_subdir else f"{sanitize_filename(plugin_req)}_{run_id}"
        extraction_target_dir = safe_case_subpath(case_id, "Extracted_Files", folder_label)
        extraction_target_dir.mkdir(parents=True, exist_ok=True)
        global_vol_args.extend(["-o", str(extraction_target_dir)])

    cmd_array = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--cli",
        *global_vol_args,
        resolved_plugin,
        *validated_args,
    ]
    preview_parts = ["python3", Path(__file__).name, *global_vol_args, plugin_req, *validated_args]
    cmd_preview = " ".join(shlex.quote(p) for p in preview_parts)

    job_record = {
        "job_id": job_id,
        "worker_slot": worker_slot,
        "case_id": case_id,
        "run_id": run_id,
        "run_dir": str(run_dir),
        "plugin": plugin_req,
        "resolved_plugin": resolved_plugin,
        "plugin_args": validated_args,
        "command_array": cmd_array,
        "command_preview": cmd_preview,
        "evidence_id": evidence_id,
        "evidence_filename": ev["filename"],
        "evidence_path": str(ev_path),
        "evidence_sha256": ev["sha256"],
        "extraction_dir": str(extraction_target_dir) if extraction_target_dir else None,
        "status": "Pending",
        "created_at": utc_now(),
        "started_at": None,
        "ended_at": None,
        "duration_seconds": 0.0,
        "return_code": None,
        "line_count": 0,
        "last_line": "Initializing Volatility 3 engine...",
        "stdout": "",
        "stderr": "",
        "structured": None,
    }

    with JOBS_LOCK:
        JOBS[job_id] = job_record

    worker = threading.Thread(target=execute_volatility_job_worker, args=(job_id,), daemon=True)
    worker.start()
    return job_record, None, 200


def start_auto_triage_for_evidence(case_id: str, evidence_record: Dict[str, Any]) -> List[str]:
    """
    Runs OS-specific baseline triage silently in the background when a RAM dump is imported,
    so target OS details, process/thread workload, and memory statistics populate automatically.
    """
    ev_id = evidence_record["evidence_id"]
    detected_os = evidence_record.get("detected_os", "Unknown")

    if detected_os == "Windows":
        auto_plugins = ["windows.info", "windows.pslist", "windows.statistics"]
    elif detected_os == "Linux":
        auto_plugins = ["banners.Banners", "linux.pslist"]
    elif detected_os == "macOS":
        auto_plugins = ["banners.Banners", "mac.pslist"]
    else:
        auto_plugins = ["banners.Banners", "windows.info"]

    started_jobs = []
    for p_name in auto_plugins:
        if resolve_plugin_name(p_name):
            job_rec, _, _ = launch_plugin_job_internal(case_id, ev_id, p_name, [])
            if job_rec:
                started_jobs.append(job_rec["job_id"])
    return started_jobs


# ---------------------------------------------------------------------------
# CHW MEMORYX AI ASSISTANT (5-MESSAGE CONTEXT BACKUP + AUTO-TRIM + MULTI-LANGUAGE)
# ---------------------------------------------------------------------------
def _get_ai_history_file(case_id: Optional[str]) -> Optional[Path]:
    if not case_id or not validate_case_id(case_id):
        return None
    try:
        log_dir = safe_case_subpath(case_id, "Logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        return log_dir / "ai_chat_history.json"
    except Exception:
        return None


def load_ai_chat_history(case_id: Optional[str]) -> List[Dict[str, str]]:
    session_key = case_id or "__global__"
    with AI_CHAT_LOCK:
        if session_key in AI_CHAT_SESSIONS:
            return list(AI_CHAT_SESSIONS[session_key])
        hfile = _get_ai_history_file(case_id)
        if hfile and hfile.exists():
            try:
                loaded = json.loads(hfile.read_text(encoding="utf-8"))
                if isinstance(loaded, list):
                    AI_CHAT_SESSIONS[session_key] = loaded
                    return list(loaded)
            except Exception:
                pass
        AI_CHAT_SESSIONS[session_key] = []
        return []


def save_ai_chat_history(case_id: Optional[str], messages: List[Dict[str, str]]) -> None:
    session_key = case_id or "__global__"
    # Keep at most the last 5 exchanges (10 messages: 5 user + 5 assistant)
    max_msgs = AI_MAX_HISTORY_TURNS * 2
    capped = messages[-max_msgs:]
    with AI_CHAT_LOCK:
        AI_CHAT_SESSIONS[session_key] = capped
        hfile = _get_ai_history_file(case_id)
        if hfile:
            try:
                hfile.write_text(json.dumps(capped, indent=2, ensure_ascii=False), encoding="utf-8")
            except Exception:
                pass


def clear_ai_chat_history(case_id: Optional[str]) -> None:
    session_key = case_id or "__global__"
    with AI_CHAT_LOCK:
        AI_CHAT_SESSIONS[session_key] = []
        hfile = _get_ai_history_file(case_id)
        if hfile and hfile.exists():
            try:
                hfile.unlink()
            except Exception:
                pass


def trim_history_to_budget(history: List[Dict[str, str]], max_chars: int = AI_MAX_HISTORY_CHARS) -> List[Dict[str, str]]:
    """
    Takes up to the last 5 turns (10 messages) and automatically drops oldest messages
    if total character count exceeds the context window budget.
    """
    max_msgs = AI_MAX_HISTORY_TURNS * 2
    recent = [
        {"role": m.get("role", "user"), "content": str(m.get("content", ""))}
        for m in history[-max_msgs:]
        if m.get("role") in ("user", "assistant") and str(m.get("content", "")).strip()
    ]

    while len(recent) > 1 and sum(len(m["content"]) for m in recent) > max_chars:
        recent.pop(0)

    # If even a single remaining historical message is huge, truncate it safely
    if recent and len(recent[0]["content"]) > max_chars:
        recent[0]["content"] = recent[0]["content"][:max_chars] + "... [trimmed]"

    return recent


def _call_chw_ai_endpoint(messages: List[Dict[str, str]]) -> Dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {CHW_AI_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": CHW_AI_MODEL,
        "messages": messages,
    }
    if ext_requests is not None:
        resp = ext_requests.post(CHW_AI_URL, headers=headers, json=payload, timeout=50)
        resp.raise_for_status()
        return resp.json()
    else:
        req = urllib.request.Request(
            CHW_AI_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=50) as resp:
            return json.loads(resp.read().decode("utf-8"))


def query_chw_ai_assistant(
    user_prompt: str,
    context_title: str = "",
    context_output: str = "",
    active_case: Optional[Dict[str, Any]] = None,
    active_evidence: Optional[Dict[str, Any]] = None,
    client_history: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """
    Calls CHW AI with:
      1. Automatic Language Mirroring (Hindi -> Hindi, Hinglish -> Hinglish, English -> English)
      2. Clean Markdown Formatting (bold, italics, bullet lists, code blocks, Markdown tables)
      3. Rolling 5-Turn Conversation Context Backup with automatic context-budget trimming
      4. Active Target Memory Dump & Volatility 3 Output Context
    """
    case_id = active_case.get("case_id") if active_case else None
    dump_telemetry = extract_dump_forensic_telemetry(case_id, active_evidence)

    ev_summary = "No memory image currently loaded."
    if active_evidence:
        ev_summary = (
            f"Target Evidence Image: {active_evidence.get('filename')} | "
            f"Target OS: {dump_telemetry.get('target_os')} ({dump_telemetry.get('os_confidence')}) | "
            f"Architecture: {dump_telemetry.get('target_arch')} | "
            f"Kernel: {dump_telemetry.get('kernel_version')} | "
            f"Capture Time: {dump_telemetry.get('capture_time')} | "
            f"Target RAM: {dump_telemetry.get('dump_ram_used_gb')} GB / {dump_telemetry.get('dump_ram_total_gb')} GB ({dump_telemetry.get('dump_ram_percent')}%) | "
            f"Target CPU Cores: {dump_telemetry.get('target_cpu_cores') or 'Unknown'} | "
            f"Active Procs: {dump_telemetry.get('active_processes')} | "
            f"Active Threads: {dump_telemetry.get('total_threads')} | "
            f"SHA-256: {active_evidence.get('sha256')}"
        )

    trimmed_context = (context_output or "").strip()
    if len(trimmed_context) > AI_MAX_CONTEXT_CHARS:
        trimmed_context = trimmed_context[:AI_MAX_CONTEXT_CHARS] + "\n...[Output trimmed to fit AI context limit]..."

    system_instruction = (
        f"You are the official {PRODUCT_NAME} AI Memory Forensics Assistant.\n"
        "RULES:\n"
        "1. LANGUAGE MATCHING: Always respond in the exact language and script the investigator uses. "
        "If the user writes in Hindi (Devanagari), answer in clear Hindi. If the user writes in Hinglish (Hindi in English letters), answer in natural Hinglish. "
        "If the user writes in English, answer in professional English.\n"
        "2. FORMATTING: Use proper Markdown formatting for readability: **bold** for key threats/PIDs/verdicts, "
        "*italics* for notes, `inline code` for plugin names/paths/hashes, bullet lists, and Markdown tables "
        "(`| Column | Column |`) whenever summarizing processes, network connections, or comparisons.\n"
        "3. FORENSIC ACCURACY: Refer strictly to the Target Memory Dump context provided below (never confuse it with the investigator's host PC). "
        "Use the previous conversation turns for continuity when the user asks follow-up questions.\n\n"
        f"--- ACTIVE CASE & TARGET MEMORY DUMP CONTEXT ---\n"
        f"Case: {case_id or 'N/A'} ({active_case.get('case_name') if active_case else ''})\n"
        f"{ev_summary}\n"
        f"--- CURRENT FORENSIC VIEW ({context_title or 'General Workstation'}) ---\n"
        f"{trimmed_context or 'No specific command output attached.'}"
    )

    # Load rolling history (prefer server-persisted history; seed from client_history if provided and server is empty)
    stored_history = load_ai_chat_history(case_id)
    if not stored_history and isinstance(client_history, list) and client_history:
        stored_history = client_history

    trimmed_history = trim_history_to_budget(stored_history, max_chars=AI_MAX_HISTORY_CHARS)

    question = (user_prompt or "").strip() or (
        "Analyze this forensic output, highlight anomalies or malware risks, and suggest next steps."
    )

    messages: List[Dict[str, str]] = [
        {"role": "system", "content": system_instruction},
        *trimmed_history,
        {"role": "user", "content": question},
    ]

    try:
        try:
            data = _call_chw_ai_endpoint(messages)
        except Exception:
            # Fallback if upstream endpoint rejects 'system' role: merge context + history into user prompt
            hist_text = "\n".join(
                f"{'Investigator' if m['role'] == 'user' else 'Assistant'}: {m['content']}"
                for m in trimmed_history
            )
            fallback_msg = (
                f"{system_instruction}\n\n"
                + (f"--- RECENT CONVERSATION CONTEXT ---\n{hist_text}\n\n" if hist_text else "")
                + f"--- LATEST QUESTION ---\n{question}"
            )
            data = _call_chw_ai_endpoint([{"role": "user", "content": fallback_msg}])

        reply_text = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
        if not reply_text:
            reply_text = json.dumps(data)

        # Persist updated rolling 5-turn history
        updated_history = stored_history + [
            {"role": "user", "content": question},
            {"role": "assistant", "content": reply_text},
        ]
        save_ai_chat_history(case_id, updated_history)

        return {
            "ok": True,
            "reply": reply_text,
            "context_messages_used": len(trimmed_history),
            "history_count": len(load_ai_chat_history(case_id)),
        }
    except Exception as exc:
        LOGGER.error(f"CHW AI Assistant request failed: {exc}")
        return {"ok": False, "error": f"CHW AI Service unreachable or returned an error: {exc}"}


# ---------------------------------------------------------------------------
# BROWSER ARTIFACT CORRELATION WORKFLOW
# ---------------------------------------------------------------------------
BROWSER_PROCESS_SIGNATURES = [
    "chrome.exe",
    "msedge.exe",
    "msedgewebview2.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "iexplore.exe",
    "safari",
    "vivaldi.exe",
]

URL_EXTRACT_REGEX = re.compile(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,250}")


def analyze_case_browser_artifacts(case_id: str, scan_evidence_strings: bool = False) -> Dict[str, Any]:
    case_dir = get_case_dir(case_id)
    cmd_root = case_dir / "Command_Outputs"

    process_observations: List[Dict[str, Any]] = []
    cmdline_observations: List[Dict[str, Any]] = []
    network_observations: List[Dict[str, Any]] = []
    file_artifacts: List[Dict[str, Any]] = []
    recovered_urls: List[Dict[str, Any]] = []

    if cmd_root.exists():
        for plugin_dir in sorted(cmd_root.iterdir()):
            if not plugin_dir.is_dir():
                continue
            p_lower = plugin_dir.name.lower()
            runs = sorted([r for r in plugin_dir.iterdir() if r.is_dir() and r.name.startswith("run_")])
            if not runs:
                continue
            latest_run = runs[-1]
            out_txt = latest_run / "output.txt"
            if not out_txt.exists():
                continue
            content = out_txt.read_text(encoding="utf-8", errors="replace")
            source_ref = f"{plugin_dir.name}/{latest_run.name}/output.txt"

            for line in content.splitlines():
                l_lower = line.lower()
                matched_proc = next((b for b in BROWSER_PROCESS_SIGNATURES if b in l_lower), None)

                if matched_proc:
                    is_webview = "msedgewebview2.exe" in l_lower
                    note = (
                        "WebView2 runtime host process (spawned by system widgets or apps; not standalone proof of Edge browsing)."
                        if is_webview
                        else "Browser executable process entry observed in RAM."
                    )
                    if any(k in p_lower for k in ["pslist", "pstree", "psscan"]):
                        process_observations.append({
                            "browser_binary": matched_proc,
                            "classification": "Process Observation",
                            "is_webview_component": is_webview,
                            "source": source_ref,
                            "raw_line": line.strip(),
                            "forensic_note": note,
                        })
                    elif "cmdline" in p_lower or "envars" in p_lower:
                        cmdline_observations.append({
                            "browser_binary": matched_proc,
                            "classification": "Command-Line Observation",
                            "source": source_ref,
                            "raw_line": line.strip(),
                        })
                    elif "net" in p_lower:
                        network_observations.append({
                            "browser_binary": matched_proc,
                            "classification": "Correlated Network Socket",
                            "source": source_ref,
                            "raw_line": line.strip(),
                        })

                if any(k in l_lower for k in ["\\history", "\\cookies", "\\cache", "\\web data", "\\login data", "places.sqlite", "cookies.sqlite"]):
                    file_artifacts.append({
                        "classification": "Directly Recovered File Handle",
                        "source": source_ref,
                        "raw_line": line.strip(),
                    })

                for url_match in URL_EXTRACT_REGEX.findall(line):
                    recovered_urls.append({
                        "url": url_match,
                        "classification": "Memory String URL Fragment",
                        "source": source_ref,
                    })

    if scan_evidence_strings:
        ext_root = case_dir / "Extracted_Files"
        if ext_root.exists():
            for fpath in sorted(ext_root.rglob("*"))[:25]:
                if fpath.is_file() and fpath.stat().st_size <= 32 * 1024 * 1024:
                    try:
                        raw_bytes = fpath.read_bytes()
                        text_ascii = raw_bytes.decode("latin-1", errors="ignore")
                        for u in URL_EXTRACT_REGEX.findall(text_ascii)[:100]:
                            recovered_urls.append({
                                "url": u,
                                "classification": "Extracted Artifact String",
                                "source": str(fpath.relative_to(case_dir)),
                            })
                    except Exception:
                        pass

    seen_urls = set()
    unique_urls = []
    for item in recovered_urls:
        if item["url"] not in seen_urls:
            seen_urls.add(item["url"])
            unique_urls.append(item)

    return {
        "case_id": case_id,
        "generated_at": utc_now(),
        "methodology_disclaimer": (
            "Volatility 3 inspects volatile RAM structures. Background WebView processes (e.g., msedgewebview2.exe) "
            "do not by themselves prove interactive user web browsing."
        ),
        "process_observations": process_observations[:250],
        "cmdline_observations": cmdline_observations[:250],
        "network_observations": network_observations[:250],
        "file_artifacts": file_artifacts[:250],
        "url_fragments": unique_urls[:300],
    }


# ---------------------------------------------------------------------------
# FLASK APPLICATION FACTORY & REST API ENDPOINTS
# ---------------------------------------------------------------------------
def create_chw_flask_app():
    try:
        from flask import Flask, jsonify, request, send_file
    except ImportError:
        print(
            "\n[!] CRITICAL DEPENDENCY MISSING: Flask is required to run CHW MemoryX.\n"
            f"    Install it with: {sys.executable} -m pip install flask\n",
            file=sys.stderr,
        )
        sys.exit(1)

    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    @app.after_request
    def apply_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Cache-Control"] = "no-store"
        return response

    # 1. FRONTEND ENTRYPOINT
    @app.route("/", methods=["GET"])
    def serve_dashboard():
        if not INDEX_HTML_PATH.exists():
            return "<h3>CHW MemoryX Error: index.html not found beside script.</h3>", 404
        return send_file(INDEX_HTML_PATH, mimetype="text/html")

    # 2. WORKSTATION STATUS & ACTIVE TARGET DUMP TELEMETRY
    @app.route("/api/status", methods=["GET"])
    def api_status():
        ensure_root_storage()
        with STATE_LOCK:
            active_case_id = WORKSTATION_STATE.get("active_case")
            active_ev_id = WORKSTATION_STATE.get("active_evidence")
            theme = WORKSTATION_STATE.get("theme", "dark")
            host = WORKSTATION_STATE.get("server_host", "127.0.0.1")
            port = WORKSTATION_STATE.get("server_port", 5000)

        active_case_obj = None
        active_evidence_obj = None
        detected_os = None

        if active_case_id:
            try:
                active_case_obj = load_case_metadata(active_case_id)
                if active_ev_id:
                    active_evidence_obj = get_evidence_record(active_case_id, active_ev_id)
                elif active_case_obj.get("evidence"):
                    active_evidence_obj = active_case_obj["evidence"][0]
                    WORKSTATION_STATE["active_evidence"] = active_evidence_obj["evidence_id"]
                    save_global_state()
                if active_evidence_obj:
                    detected_os = active_evidence_obj.get("detected_os", "Unknown")
            except Exception:
                WORKSTATION_STATE["active_case"] = None
                WORKSTATION_STATE["active_evidence"] = None
                save_global_state()

        all_plugins = discover_installed_plugins()
        os_plugins = filter_plugins_for_os(all_plugins, detected_os)
        dump_telemetry = extract_dump_forensic_telemetry(active_case_id, active_evidence_obj)

        with JOBS_LOCK:
            running_jobs = [
                {
                    "job_id": j["job_id"],
                    "plugin": j["plugin"],
                    "run_id": j["run_id"],
                    "status": j["status"],
                }
                for j in JOBS.values()
                if j["status"] in ("Pending", "Running")
            ]

        return jsonify({
            "ok": True,
            "product": PRODUCT_NAME,
            "subtitle": PRODUCT_SUBTITLE,
            "logo_url": COMPANY_LOGO_URL,
            "engine": f"Volatility 3 v{volatility3.framework.constants.PACKAGE_VERSION}",
            "server_address": f"http://{host}:{port}",
            "active_case": active_case_obj,
            "active_evidence": active_evidence_obj,
            "detected_os": detected_os or "Unknown",
            "running_jobs": len(running_jobs),
            "active_jobs_list": running_jobs,
            "theme": theme,
            "plugin_count": len(os_plugins),
            "total_installed_plugins": len(all_plugins),
            "dump_telemetry": dump_telemetry,
        })

    # 3. DASHBOARD METRICS (100% TARGET MEMORY DUMP TELEMETRY)
    @app.route("/api/dashboard_metrics", methods=["GET"])
    def api_dashboard_metrics():
        case_id = request.args.get("case_id") or WORKSTATION_STATE.get("active_case")
        ev_id = request.args.get("evidence_id") or WORKSTATION_STATE.get("active_evidence")

        case_obj = None
        ev_obj = None
        history = []
        category_counts: Dict[str, int] = {}
        status_counts = {"Completed": 0, "Running": 0, "Failed": 0}

        if case_id:
            try:
                case_obj = load_case_metadata(case_id)
                if ev_id:
                    ev_obj = get_evidence_record(case_id, ev_id)
                elif case_obj.get("evidence"):
                    ev_obj = case_obj["evidence"][0]

                hist_file = get_case_dir(case_id) / "command_history.json"
                if hist_file.exists():
                    history = json.loads(hist_file.read_text(encoding="utf-8"))
                for h in history:
                    st = h.get("status", "Completed")
                    if st in status_counts:
                        status_counts[st] += 1
                    _, cat = categorize_plugin(h.get("plugin", ""))
                    category_counts[cat] = category_counts.get(cat, 0) + 1
            except Exception:
                pass

        dump_telemetry = extract_dump_forensic_telemetry(case_id, ev_obj)

        return jsonify({
            "ok": True,
            "product": PRODUCT_NAME,
            "logo_url": COMPANY_LOGO_URL,
            "dump_telemetry": dump_telemetry,
            "active_case": case_obj,
            "active_evidence": ev_obj,
            "charts": {
                "category_distribution": category_counts,
                "status_distribution": status_counts,
                "dump_ram_total_gb": dump_telemetry["dump_ram_total_gb"],
                "dump_ram_used_gb": dump_telemetry["dump_ram_used_gb"],
                "dump_ram_percent": dump_telemetry["dump_ram_percent"],
                "dump_cpu_load_percent": dump_telemetry["dump_cpu_load_percent"],
                "top_processes": dump_telemetry["top_processes"],
            },
            "recent_runs": history[:15],
        })

    # 4. CASE MANAGEMENT API
    @app.route("/api/cases", methods=["GET"])
    def api_list_cases():
        return jsonify({
            "ok": True,
            "cases": list_all_cases(),
            "active_case_id": WORKSTATION_STATE.get("active_case"),
            "active_evidence_id": WORKSTATION_STATE.get("active_evidence"),
        })

    @app.route("/api/cases", methods=["POST"])
    def api_create_case():
        payload = request.get_json(force=True, silent=True) or {}
        case_id = str(payload.get("case_id", "")).strip()
        case_name = str(payload.get("case_name", "")).strip()
        investigator = str(payload.get("investigator", "")).strip()
        description = str(payload.get("description", "")).strip()
        evidence_desc = str(payload.get("evidence_description", "")).strip()
        ref_num = str(payload.get("reference_number", "")).strip()
        case_dt = str(payload.get("datetime", "")).strip() or utc_now()

        if not validate_case_id(case_id):
            return jsonify({"ok": False, "error": "Case ID must be 2-64 characters (letters, numbers, hyphen, underscore only)."}), 400
        if not case_name or not investigator:
            return jsonify({"ok": False, "error": "Case Name and Investigator Name are required."}), 400

        case_dir = get_case_dir(case_id)
        if case_dir.exists():
            return jsonify({"ok": False, "error": f"Case '{case_id}' already exists."}), 409

        case_dir.mkdir(parents=True, exist_ok=False)
        for sub in CASE_SUBDIRS:
            (case_dir / sub).mkdir(parents=True, exist_ok=True)

        metadata = {
            "case_id": case_id,
            "case_name": case_name,
            "investigator": investigator,
            "description": description,
            "evidence_description": evidence_desc,
            "reference_number": ref_num,
            "created_at": case_dt,
            "updated_at": utc_now(),
            "case_directory": str(case_dir),
            "status": "OPEN",
            "evidence": [],
            "analyst_notes": "",
        }
        save_case_metadata(case_id, metadata)
        (case_dir / "command_history.json").write_text("[]", encoding="utf-8")
        (case_dir / "Hashes" / "hash_registry.json").write_text("[]", encoding="utf-8")

        with STATE_LOCK:
            WORKSTATION_STATE["active_case"] = case_id
            WORKSTATION_STATE["active_evidence"] = None
            save_global_state()

        log_case_event(case_id, "CASE_CREATED", f"Case '{case_name}' initialized by {investigator}.")
        return jsonify({"ok": True, "case": metadata})

    @app.route("/api/cases/activate", methods=["POST"])
    def api_activate_case():
        payload = request.get_json(force=True, silent=True) or {}
        case_id = str(payload.get("case_id", "")).strip()
        try:
            meta = load_case_metadata(case_id)
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 404

        ev_list = meta.get("evidence", [])
        default_ev = ev_list[0]["evidence_id"] if ev_list else None

        with STATE_LOCK:
            WORKSTATION_STATE["active_case"] = case_id
            WORKSTATION_STATE["active_evidence"] = default_ev
            save_global_state()

        log_case_event(case_id, "CASE_ACTIVATED", f"Switched active session to {case_id}.")
        return jsonify({"ok": True, "case": meta, "active_evidence_id": default_ev})

    @app.route("/api/cases/close", methods=["POST"])
    def api_close_case():
        with STATE_LOCK:
            WORKSTATION_STATE["active_case"] = None
            WORKSTATION_STATE["active_evidence"] = None
            save_global_state()
        return jsonify({"ok": True})

    @app.route("/api/cases/<case_id>/summary", methods=["GET"])
    def api_case_summary(case_id: str):
        try:
            meta = load_case_metadata(case_id)
            case_dir = get_case_dir(case_id)
            hist_file = case_dir / "command_history.json"
            history = json.loads(hist_file.read_text(encoding="utf-8")) if hist_file.exists() else []
            hashes_file = case_dir / "Hashes" / "hash_registry.json"
            hashes = json.loads(hashes_file.read_text(encoding="utf-8")) if hashes_file.exists() else []
            rep_dir = case_dir / "Reports"
            reports = [f.name for f in sorted(rep_dir.iterdir()) if f.is_file()] if rep_dir.exists() else []
            return jsonify({
                "ok": True,
                "case": meta,
                "command_history": history,
                "hashes": hashes,
                "reports": reports,
            })
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    # 5. EVIDENCE MANAGER API (WITH ACCURATE TARGET OS DETECTION & AUTO TRIAGE)
    @app.route("/api/evidence/upload_init", methods=["POST"])
    def api_upload_init():
        payload = request.get_json(force=True, silent=True) or {}
        case_id = payload.get("case_id") or WORKSTATION_STATE.get("active_case")
        if not case_id:
            return jsonify({"ok": False, "error": "Select or create an active case first."}), 400

        raw_filename = str(payload.get("filename", "")).strip()
        total_size = int(payload.get("total_size", 0))
        notes = str(payload.get("notes", "")).strip()
        if not raw_filename:
            return jsonify({"ok": False, "error": "Evidence filename is required."}), 400

        safe_name = sanitize_filename(raw_filename)
        ev_dir = safe_case_subpath(case_id, "Evidence")
        ev_dir.mkdir(parents=True, exist_ok=True)
        final_path = ev_dir / safe_name
        if final_path.exists():
            final_path = ev_dir / f"{final_path.stem}_{int(time.time())}{final_path.suffix}"
            safe_name = final_path.name

        upload_id = f"UPL-{uuid.uuid4().hex[:12].upper()}"
        temp_dir = safe_case_subpath(case_id, "Uploads_Temp")
        temp_dir.mkdir(parents=True, exist_ok=True)
        temp_file = temp_dir / f"{upload_id}.part"
        temp_meta = temp_dir / f"{upload_id}.json"

        meta_info = {
            "upload_id": upload_id,
            "case_id": case_id,
            "original_filename": raw_filename,
            "safe_filename": safe_name,
            "final_path": str(final_path),
            "temp_file": str(temp_file),
            "total_size": total_size,
            "received_bytes": 0,
            "notes": notes,
            "started_at": utc_now(),
        }
        temp_file.write_bytes(b"")
        temp_meta.write_text(json.dumps(meta_info, indent=2), encoding="utf-8")
        return jsonify({"ok": True, "upload_id": upload_id, "safe_filename": safe_name})

    @app.route("/api/evidence/upload_chunk", methods=["POST"])
    def api_upload_chunk():
        upload_id = request.form.get("upload_id", "").strip()
        case_id = request.form.get("case_id") or WORKSTATION_STATE.get("active_case")
        if not case_id or not upload_id:
            return jsonify({"ok": False, "error": "Missing case_id or upload_id."}), 400

        temp_dir = safe_case_subpath(case_id, "Uploads_Temp")
        temp_meta_path = temp_dir / f"{sanitize_filename(upload_id)}.json"
        if not temp_meta_path.exists():
            return jsonify({"ok": False, "error": "Upload session not found."}), 404

        meta_info = json.loads(temp_meta_path.read_text(encoding="utf-8"))
        temp_file = Path(meta_info["temp_file"])
        chunk_file = request.files.get("chunk")
        if chunk_file is None:
            return jsonify({"ok": False, "error": "No binary chunk supplied."}), 400

        with open(temp_file, "ab") as f:
            f.write(chunk_file.read())

        meta_info["received_bytes"] = temp_file.stat().st_size
        temp_meta_path.write_text(json.dumps(meta_info, indent=2), encoding="utf-8")
        return jsonify({
            "ok": True,
            "received_bytes": meta_info["received_bytes"],
            "total_size": meta_info["total_size"],
        })

    @app.route("/api/evidence/upload_complete", methods=["POST"])
    def api_upload_complete():
        payload = request.get_json(force=True, silent=True) or {}
        upload_id = str(payload.get("upload_id", "")).strip()
        case_id = payload.get("case_id") or WORKSTATION_STATE.get("active_case")
        if not case_id or not upload_id:
            return jsonify({"ok": False, "error": "Missing case_id or upload_id."}), 400

        temp_dir = safe_case_subpath(case_id, "Uploads_Temp")
        temp_meta_path = temp_dir / f"{sanitize_filename(upload_id)}.json"
        if not temp_meta_path.exists():
            return jsonify({"ok": False, "error": "Upload session not found."}), 404

        meta_info = json.loads(temp_meta_path.read_text(encoding="utf-8"))
        temp_file = Path(meta_info["temp_file"])
        final_path = Path(meta_info["final_path"])

        if not temp_file.exists():
            return jsonify({"ok": False, "error": "Temporary evidence file missing."}), 400

        shutil.move(str(temp_file), str(final_path))
        temp_meta_path.unlink(missing_ok=True)

        size_bytes = final_path.stat().st_size
        sha256_hex = compute_sha256_incremental(final_path)
        os_profile = detect_memory_image_os(final_path)

        evidence_id = f"EV-{uuid.uuid4().hex[:8].upper()}"
        rel_path = str(final_path.relative_to(get_case_dir(case_id)))

        ev_record = {
            "evidence_id": evidence_id,
            "filename": final_path.name,
            "original_filename": meta_info["original_filename"],
            "acquisition_mode": "UPLOADED_TO_CASE",
            "path": str(final_path),
            "relative_path": rel_path,
            "size_bytes": size_bytes,
            "size_human": human_size(size_bytes),
            "ram_size_gb": os_profile["ram_size_gb"],
            "ram_occupancy": os_profile["ram_occupancy"],
            "sha256": sha256_hex,
            "detected_os": os_profile["detected_os"],
            "os_confidence": os_profile["confidence"],
            "os_detection_method": os_profile["detection_method"],
            "banner_summary": os_profile["banner_summary"],
            "target_arch": os_profile["target_arch"],
            "target_cpu_cores": os_profile["target_cpu_cores"],
            "capture_time": os_profile["capture_time"],
            "system_details": os_profile["system_details"],
            "imported_at": utc_now(),
            "status": "VERIFIED_READY",
            "notes": meta_info.get("notes", ""),
        }

        case_meta = load_case_metadata(case_id)
        case_meta.setdefault("evidence", []).append(ev_record)
        save_case_metadata(case_id, case_meta)

        record_hash_entry(case_id, "SOURCE_EVIDENCE", final_path.name, rel_path, size_bytes, sha256_hex)

        with STATE_LOCK:
            WORKSTATION_STATE["active_case"] = case_id
            WORKSTATION_STATE["active_evidence"] = evidence_id
            save_global_state()

        auto_jobs = start_auto_triage_for_evidence(case_id, ev_record)
        log_case_event(
            case_id,
            "EVIDENCE_UPLOADED",
            f"Memory image '{final_path.name}' ({os_profile['detected_os']}) uploaded, hashed, and auto-triage started.",
            {"evidence_id": evidence_id, "detected_os": os_profile["detected_os"], "auto_jobs": auto_jobs},
        )
        return jsonify({"ok": True, "evidence": ev_record, "auto_triage_jobs": auto_jobs})

    @app.route("/api/evidence/register_local", methods=["POST"])
    def api_register_local_evidence():
        payload = request.get_json(force=True, silent=True) or {}
        case_id = payload.get("case_id") or WORKSTATION_STATE.get("active_case")
        if not case_id:
            return jsonify({"ok": False, "error": "An active case is required to register evidence."}), 400

        local_path_str = str(payload.get("local_path", "")).strip()
        copy_to_case = bool(payload.get("copy_to_case", False))
        notes = str(payload.get("notes", "")).strip()

        if not local_path_str:
            return jsonify({"ok": False, "error": "Provide a valid filesystem path to the memory image."}), 400

        src_path = Path(os.path.expanduser(local_path_str)).resolve()
        if not src_path.exists() or not src_path.is_file():
            return jsonify({"ok": False, "error": f"Memory image not found at path: {src_path}"}), 404

        if copy_to_case:
            ev_dir = safe_case_subpath(case_id, "Evidence")
            ev_dir.mkdir(parents=True, exist_ok=True)
            safe_name = sanitize_filename(src_path.name)
            dest_path = ev_dir / safe_name
            if dest_path.exists():
                dest_path = ev_dir / f"{dest_path.stem}_{int(time.time())}{dest_path.suffix}"
            shutil.copy2(str(src_path), str(dest_path))
            final_path = dest_path
            mode = "COPIED_TO_CASE"
            rel_path = str(final_path.relative_to(get_case_dir(case_id)))
        else:
            final_path = src_path
            mode = "REGISTERED_READONLY_LOCAL"
            rel_path = str(final_path)

        size_bytes = final_path.stat().st_size
        sha256_hex = compute_sha256_incremental(final_path)
        os_profile = detect_memory_image_os(final_path)
        evidence_id = f"EV-{uuid.uuid4().hex[:8].upper()}"

        ev_record = {
            "evidence_id": evidence_id,
            "filename": final_path.name,
            "original_filename": src_path.name,
            "acquisition_mode": mode,
            "path": str(final_path),
            "relative_path": rel_path,
            "size_bytes": size_bytes,
            "size_human": human_size(size_bytes),
            "ram_size_gb": os_profile["ram_size_gb"],
            "ram_occupancy": os_profile["ram_occupancy"],
            "sha256": sha256_hex,
            "detected_os": os_profile["detected_os"],
            "os_confidence": os_profile["confidence"],
            "os_detection_method": os_profile["detection_method"],
            "banner_summary": os_profile["banner_summary"],
            "target_arch": os_profile["target_arch"],
            "target_cpu_cores": os_profile["target_cpu_cores"],
            "capture_time": os_profile["capture_time"],
            "system_details": os_profile["system_details"],
            "imported_at": utc_now(),
            "status": "VERIFIED_READY",
            "notes": notes,
        }

        case_meta = load_case_metadata(case_id)
        case_meta.setdefault("evidence", []).append(ev_record)
        save_case_metadata(case_id, case_meta)

        record_hash_entry(case_id, "SOURCE_EVIDENCE", final_path.name, rel_path, size_bytes, sha256_hex)

        with STATE_LOCK:
            WORKSTATION_STATE["active_case"] = case_id
            WORKSTATION_STATE["active_evidence"] = evidence_id
            save_global_state()

        auto_jobs = start_auto_triage_for_evidence(case_id, ev_record)
        log_case_event(
            case_id,
            "EVIDENCE_REGISTERED",
            f"Memory image '{final_path.name}' ({os_profile['detected_os']}) registered & auto-triage started.",
            {"evidence_id": evidence_id, "detected_os": os_profile["detected_os"], "auto_jobs": auto_jobs},
        )
        return jsonify({"ok": True, "evidence": ev_record, "auto_triage_jobs": auto_jobs})

    @app.route("/api/evidence/select", methods=["POST"])
    def api_select_evidence():
        payload = request.get_json(force=True, silent=True) or {}
        case_id = payload.get("case_id") or WORKSTATION_STATE.get("active_case")
        evidence_id = str(payload.get("evidence_id", "")).strip()
        if not case_id or not evidence_id:
            return jsonify({"ok": False, "error": "Case ID and Evidence ID are required."}), 400

        ev = get_evidence_record(case_id, evidence_id)
        if not ev:
            return jsonify({"ok": False, "error": "Evidence record not found in active case."}), 404

        if (not ev.get("detected_os") or ev.get("detected_os") == "Unknown" or not ev.get("ram_occupancy")) and Path(ev["path"]).exists():
            os_prof = detect_memory_image_os(Path(ev["path"]))
            ev["detected_os"] = os_prof["detected_os"]
            ev["os_confidence"] = os_prof["confidence"]
            ev["os_detection_method"] = os_prof["detection_method"]
            ev["banner_summary"] = os_prof["banner_summary"]
            ev["target_arch"] = os_prof["target_arch"]
            ev["target_cpu_cores"] = os_prof["target_cpu_cores"]
            ev["capture_time"] = os_prof["capture_time"]
            ev["ram_size_gb"] = os_prof["ram_size_gb"]
            ev["ram_occupancy"] = os_prof["ram_occupancy"]
            ev["system_details"] = os_prof["system_details"]
            c_meta = load_case_metadata(case_id)
            for item in c_meta.get("evidence", []):
                if item["evidence_id"] == evidence_id:
                    item.update(ev)
            save_case_metadata(case_id, c_meta)

        with STATE_LOCK:
            WORKSTATION_STATE["active_case"] = case_id
            WORKSTATION_STATE["active_evidence"] = evidence_id
            save_global_state()

        return jsonify({"ok": True, "evidence": ev})

    @app.route("/api/evidence/reprobe_os", methods=["POST"])
    def api_reprobe_evidence_os():
        """
        Re-runs target OS & kernel detection directly on the active memory dump image.
        """
        payload = request.get_json(force=True, silent=True) or {}
        case_id = payload.get("case_id") or WORKSTATION_STATE.get("active_case")
        evidence_id = payload.get("evidence_id") or WORKSTATION_STATE.get("active_evidence")
        if not case_id or not evidence_id:
            return jsonify({"ok": False, "error": "Active case and evidence required."}), 400

        ev = get_evidence_record(case_id, evidence_id)
        if not ev or not Path(ev["path"]).exists():
            return jsonify({"ok": False, "error": "Evidence file not found on disk."}), 404

        os_prof = detect_memory_image_os(Path(ev["path"]))
        c_meta = load_case_metadata(case_id)
        updated_ev = None
        for item in c_meta.get("evidence", []):
            if item["evidence_id"] == evidence_id:
                item.update({
                    "detected_os": os_prof["detected_os"],
                    "os_confidence": os_prof["confidence"],
                    "os_detection_method": os_prof["detection_method"],
                    "banner_summary": os_prof["banner_summary"],
                    "target_arch": os_prof["target_arch"],
                    "target_cpu_cores": os_prof["target_cpu_cores"],
                    "capture_time": os_prof["capture_time"],
                    "ram_size_gb": os_prof["ram_size_gb"],
                    "ram_occupancy": os_prof["ram_occupancy"],
                    "system_details": os_prof["system_details"],
                })
                updated_ev = item
                break
        save_case_metadata(case_id, c_meta)
        return jsonify({"ok": True, "evidence": updated_ev})

    # 6. OS-AWARE DYNAMIC PLUGIN EXPLORER & HELP API
    @app.route("/api/plugins", methods=["GET"])
    def api_list_plugins():
        refresh = request.args.get("refresh") == "1"
        include_all = request.args.get("all") == "1"
        explicit_os = request.args.get("os", "").strip()

        all_plugins = discover_installed_plugins(force_refresh=refresh)

        detected_os = explicit_os
        if not detected_os and not include_all:
            case_id = WORKSTATION_STATE.get("active_case")
            ev_id = WORKSTATION_STATE.get("active_evidence")
            if case_id and ev_id:
                try:
                    ev = get_evidence_record(case_id, ev_id)
                    if ev:
                        detected_os = ev.get("detected_os", "")
                except Exception:
                    pass

        filtered = all_plugins if include_all else filter_plugins_for_os(all_plugins, detected_os)
        return jsonify({
            "ok": True,
            "detected_os": detected_os or "All",
            "count": len(filtered),
            "total_installed": len(all_plugins),
            "plugins": filtered,
        })

    @app.route("/api/plugins/help", methods=["GET"])
    def api_plugin_help():
        plugin_req = request.args.get("plugin", "").strip()
        if not plugin_req or not PLUGIN_NAME_REGEX.match(plugin_req):
            return jsonify({"ok": False, "error": "Invalid plugin name."}), 400

        resolved = resolve_plugin_name(plugin_req)
        if not resolved:
            return jsonify({"ok": False, "error": f"Plugin '{plugin_req}' is not installed."}), 404

        if resolved in PLUGIN_HELP_CACHE:
            return jsonify({"ok": True, "plugin": resolved, "help": PLUGIN_HELP_CACHE[resolved]})

        try:
            proc = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--cli", resolved, "--help"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            help_text = proc.stdout or proc.stderr or "No help text returned."
            PLUGIN_HELP_CACHE[resolved] = help_text
            return jsonify({"ok": True, "plugin": resolved, "help": help_text})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

    # 7. COMMAND EXECUTION & INTERNAL BACKGROUND JOB API
    @app.route("/api/execute", methods=["POST"])
    def api_execute_plugin():
        payload = request.get_json(force=True, silent=True) or {}
        case_id = payload.get("case_id") or WORKSTATION_STATE.get("active_case")
        evidence_id = payload.get("evidence_id") or WORKSTATION_STATE.get("active_evidence")
        plugin_req = str(payload.get("plugin", "")).strip()
        raw_args = payload.get("args", [])
        extraction_mode = bool(payload.get("extraction_mode", False))
        extraction_subdir = str(payload.get("extraction_subdir", "")).strip()

        if not case_id:
            return jsonify({"ok": False, "error": "Active Case Required: Please create or open a case first."}), 400
        if not evidence_id:
            return jsonify({"ok": False, "error": "Selected Evidence Required: Please upload or select a RAM image first."}), 400
        if not plugin_req or not PLUGIN_NAME_REGEX.match(plugin_req):
            return jsonify({"ok": False, "error": "Valid Volatility 3 plugin name is required."}), 400

        try:
            if isinstance(raw_args, str):
                parsed_args = shlex.split(raw_args) if raw_args.strip() else []
            elif isinstance(raw_args, list):
                parsed_args = [str(a) for a in raw_args]
            else:
                parsed_args = []
            validated_args = validate_plugin_arguments(parsed_args)
        except Exception as exc:
            return jsonify({"ok": False, "error": f"Argument validation error: {exc}"}), 400

        job_record, err_msg, code = launch_plugin_job_internal(
            case_id=case_id,
            evidence_id=evidence_id,
            plugin_req=plugin_req,
            validated_args=validated_args,
            extraction_mode=extraction_mode,
            extraction_subdir=extraction_subdir,
        )
        if err_msg:
            return jsonify({"ok": False, "error": err_msg}), code

        return jsonify({"ok": True, "job": job_record})

    @app.route("/api/jobs", methods=["GET"])
    def api_list_jobs():
        case_id = request.args.get("case_id") or WORKSTATION_STATE.get("active_case")
        with JOBS_LOCK:
            items = [
                {
                    "job_id": j["job_id"],
                    "case_id": j["case_id"],
                    "run_id": j["run_id"],
                    "plugin": j["plugin"],
                    "resolved_plugin": j["resolved_plugin"],
                    "evidence_filename": j["evidence_filename"],
                    "status": j["status"],
                    "line_count": j.get("line_count", 0),
                    "started_at": j["started_at"],
                    "ended_at": j["ended_at"],
                    "duration_seconds": j["duration_seconds"],
                    "return_code": j["return_code"],
                }
                for j in JOBS.values()
                if (not case_id or j["case_id"] == case_id)
            ]
        items.sort(key=lambda x: x.get("started_at") or "", reverse=True)
        return jsonify({"ok": True, "jobs": items})

    @app.route("/api/jobs/<job_id>", methods=["GET"])
    def api_job_detail(job_id: str):
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job:
                return jsonify({"ok": False, "error": "Job ID not found."}), 404
            return jsonify({"ok": True, "job": dict(job)})

    @app.route("/api/jobs/<job_id>/cancel", methods=["POST"])
    def api_cancel_job(job_id: str):
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job:
                return jsonify({"ok": False, "error": "Job not found."}), 404
            proc = ACTIVE_PROCESSES.get(job_id)
            job["status"] = "Cancelled"

        if proc and proc.poll() is None:
            try:
                proc.terminate()
                time.sleep(0.3)
                if proc.poll() is None:
                    proc.kill()
            except Exception:
                pass

        release_worker_slot(job_id)
        return jsonify({"ok": True, "job_id": job_id, "status": "Cancelled"})

    # 8. SAVED RESULTS, INDIVIDUAL CSV & MASTER ALL-IN-ONE CSV EXPORT
    @app.route("/api/history", methods=["GET"])
    def api_get_history():
        case_id = request.args.get("case_id") or WORKSTATION_STATE.get("active_case")
        if not case_id:
            return jsonify({"ok": True, "history": []})
        try:
            hist_file = get_case_dir(case_id) / "command_history.json"
            history = json.loads(hist_file.read_text(encoding="utf-8")) if hist_file.exists() else []
            return jsonify({"ok": True, "case_id": case_id, "history": history})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.route("/api/results/view", methods=["GET"])
    def api_view_saved_result():
        case_id = request.args.get("case_id") or WORKSTATION_STATE.get("active_case")
        plugin_folder = request.args.get("plugin", "").strip()
        run_id = request.args.get("run_id", "").strip()
        if not case_id or not plugin_folder or not run_id:
            return jsonify({"ok": False, "error": "case_id, plugin, and run_id are required."}), 400

        try:
            safe_plugin = SAFE_FILENAME_REGEX.sub("_", plugin_folder)
            safe_run = SAFE_FILENAME_REGEX.sub("_", run_id)
            run_dir = safe_case_subpath(case_id, "Command_Outputs", safe_plugin, safe_run)
            if not run_dir.exists():
                return jsonify({"ok": False, "error": f"Saved folder not found: {safe_plugin}/{safe_run}"}), 404

            stdout = (run_dir / "output.txt").read_text(encoding="utf-8", errors="replace") if (run_dir / "output.txt").exists() else ""
            stderr = (run_dir / "stderr.txt").read_text(encoding="utf-8", errors="replace") if (run_dir / "stderr.txt").exists() else ""
            structured = json.loads((run_dir / "output.json").read_text(encoding="utf-8")) if (run_dir / "output.json").exists() else None
            cmd_meta = json.loads((run_dir / "command.json").read_text(encoding="utf-8")) if (run_dir / "command.json").exists() else {}

            return jsonify({
                "ok": True,
                "case_id": case_id,
                "plugin": plugin_folder,
                "run_id": run_id,
                "stdout": stdout,
                "stderr": stderr,
                "structured": structured,
                "command_meta": cmd_meta,
            })
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.route("/api/results/csv", methods=["GET"])
    def api_download_single_run_csv():
        case_id = request.args.get("case_id") or WORKSTATION_STATE.get("active_case")
        plugin_folder = request.args.get("plugin", "").strip()
        run_id = request.args.get("run_id", "").strip()
        if not case_id or not plugin_folder or not run_id:
            return jsonify({"ok": False, "error": "Missing parameters."}), 400

        safe_plugin = SAFE_FILENAME_REGEX.sub("_", plugin_folder)
        safe_run = SAFE_FILENAME_REGEX.sub("_", run_id)
        run_dir = safe_case_subpath(case_id, "Command_Outputs", safe_plugin, safe_run)
        csv_file = run_dir / "output.csv"

        if not csv_file.exists() and (run_dir / "output.txt").exists():
            raw_text = (run_dir / "output.txt").read_text(encoding="utf-8", errors="replace")
            st = parse_volatility_tabular_output(raw_text)
            write_structured_output_to_csv(csv_file, st)

        if not csv_file.exists():
            return jsonify({"ok": False, "error": "CSV file not found for this run."}), 404

        return send_file(
            csv_file,
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"{case_id}_{safe_plugin}_{safe_run}.csv",
        )

    @app.route("/api/export_all_csv", methods=["GET"])
    def api_export_all_case_data_csv():
        case_id = request.args.get("case_id") or WORKSTATION_STATE.get("active_case")
        if not case_id:
            return jsonify({"ok": False, "error": "Open an active case first."}), 400

        try:
            case_meta = load_case_metadata(case_id)
            case_dir = get_case_dir(case_id)
            hist_file = case_dir / "command_history.json"
            history = json.loads(hist_file.read_text(encoding="utf-8")) if hist_file.exists() else []

            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow([
                "Case_ID",
                "Case_Name",
                "Investigator",
                "Evidence_Filename",
                "Detected_Target_OS",
                "Plugin_Name",
                "Run_ID",
                "Executed_At_UTC",
                "Row_Index",
                "Column_Summary_Or_Key",
                "Primary_Value",
                "Full_Structured_Row_JSON",
            ])

            ev_os_map = {e["evidence_id"]: e.get("detected_os", "Unknown") for e in case_meta.get("evidence", [])}

            for run in history:
                p_name = run.get("plugin", "")
                r_id = run.get("run_id", "")
                ev_name = run.get("evidence_filename", "")
                ev_os = ev_os_map.get(run.get("evidence_id", ""), "Unknown")
                started = run.get("started_at", "")
                out_dir_rel = run.get("output_directory", "")
                out_json_path = case_dir / out_dir_rel / "output.json"

                if out_json_path.exists():
                    st_data = json.loads(out_json_path.read_text(encoding="utf-8"))
                    cols = st_data.get("columns") or []
                    rows = st_data.get("rows") or []
                    for idx, row_obj in enumerate(rows, start=1):
                        col_1 = f"{cols[0]}={row_obj.get(cols[0], '')}" if cols else "Record"
                        col_2 = f"{cols[1]}={row_obj.get(cols[1], '')}" if len(cols) > 1 else ""
                        writer.writerow([
                            case_id,
                            case_meta.get("case_name", ""),
                            case_meta.get("investigator", ""),
                            ev_name,
                            ev_os,
                            p_name,
                            r_id,
                            started,
                            idx,
                            col_1,
                            col_2,
                            json.dumps(row_obj, ensure_ascii=False),
                        ])

            rep_dir = safe_case_subpath(case_id, "Reports")
            rep_dir.mkdir(parents=True, exist_ok=True)
            master_csv_name = f"CHW_MemoryX_{case_id}_MASTER_ALL_ANALYSIS.csv"
            master_csv_path = rep_dir / master_csv_name
            master_csv_path.write_text(buf.getvalue(), encoding="utf-8")

            return send_file(
                master_csv_path,
                mimetype="text/csv",
                as_attachment=True,
                download_name=master_csv_name,
            )
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

    # 9. CHW AI ASSISTANT ENDPOINTS (MULTI-TURN 5-MESSAGE CONTEXT + CLEAR/HISTORY)
    @app.route("/api/ai/history", methods=["GET"])
    def api_ai_history():
        case_id = request.args.get("case_id") or WORKSTATION_STATE.get("active_case")
        return jsonify({
            "ok": True,
            "case_id": case_id,
            "max_turns": AI_MAX_HISTORY_TURNS,
            "messages": load_ai_chat_history(case_id),
        })

    @app.route("/api/ai/clear", methods=["POST"])
    def api_ai_clear():
        payload = request.get_json(force=True, silent=True) or {}
        case_id = payload.get("case_id") or WORKSTATION_STATE.get("active_case")
        clear_ai_chat_history(case_id)
        return jsonify({"ok": True, "cleared": True})

    @app.route("/api/ai/analyze", methods=["POST"])
    def api_ai_analyze():
        payload = request.get_json(force=True, silent=True) or {}
        user_prompt = str(payload.get("prompt", "")).strip()
        context_title = str(payload.get("context_title", "")).strip()
        context_output = str(payload.get("context_output", "")).strip()
        plugin_folder = str(payload.get("plugin", "")).strip()
        run_id = str(payload.get("run_id", "")).strip()
        client_history = payload.get("history") if isinstance(payload.get("history"), list) else None

        case_id = payload.get("case_id") or WORKSTATION_STATE.get("active_case")
        ev_id = payload.get("evidence_id") or WORKSTATION_STATE.get("active_evidence")

        active_case = None
        active_ev = None
        if case_id:
            try:
                active_case = load_case_metadata(case_id)
                if ev_id:
                    active_ev = get_evidence_record(case_id, ev_id)
                elif active_case.get("evidence"):
                    active_ev = active_case["evidence"][0]
            except Exception:
                pass

        if not context_output and case_id:
            try:
                if plugin_folder and run_id:
                    safe_p = SAFE_FILENAME_REGEX.sub("_", plugin_folder)
                    safe_r = SAFE_FILENAME_REGEX.sub("_", run_id)
                    out_f = safe_case_subpath(case_id, "Command_Outputs", safe_p, safe_r, "output.txt")
                    if out_f.exists():
                        context_output = out_f.read_text(encoding="utf-8", errors="replace")
                        context_title = f"{plugin_folder} ({run_id})"
                else:
                    hist_file = get_case_dir(case_id) / "command_history.json"
                    if hist_file.exists():
                        hist = json.loads(hist_file.read_text(encoding="utf-8"))
                        snippets = []
                        for h in hist[:4]:
                            out_f = get_case_dir(case_id) / h.get("output_directory", "") / "output.txt"
                            if out_f.exists():
                                head = "\n".join(out_f.read_text(encoding="utf-8", errors="replace").splitlines()[:35])
                                snippets.append(f"=== {h.get('plugin')} ({h.get('run_id')}) ===\n{head}")
                        context_output = "\n\n".join(snippets)
                        context_title = "Active Case Automatic Forensic Context"
            except Exception:
                pass

        result = query_chw_ai_assistant(
            user_prompt=user_prompt,
            context_title=context_title,
            context_output=context_output,
            active_case=active_case,
            active_evidence=active_ev,
            client_history=client_history,
        )
        return jsonify(result), (200 if result.get("ok") else 502)

    # 10. EXTRACTION CENTER API
    @app.route("/api/extractions", methods=["GET"])
    def api_list_extractions():
        case_id = request.args.get("case_id") or WORKSTATION_STATE.get("active_case")
        if not case_id:
            return jsonify({"ok": True, "files": []})
        try:
            case_dir = get_case_dir(case_id)
            ext_root = case_dir / "Extracted_Files"
            hashes_file = case_dir / "Hashes" / "hash_registry.json"
            hash_map = {}
            if hashes_file.exists():
                for h in json.loads(hashes_file.read_text(encoding="utf-8")):
                    hash_map[h.get("relative_path", "")] = h.get("sha256", "")

            files = []
            if ext_root.exists():
                for fpath in sorted(ext_root.rglob("*")):
                    if fpath.is_file():
                        rel = str(fpath.relative_to(case_dir))
                        fsize = fpath.stat().st_size
                        sha = hash_map.get(rel) or compute_sha256_incremental(fpath)
                        files.append({
                            "filename": fpath.name,
                            "subfolder": str(fpath.parent.relative_to(ext_root)),
                            "relative_path": rel,
                            "size_bytes": fsize,
                            "size_human": human_size(fsize),
                            "sha256": sha,
                            "modified_at": datetime.datetime.fromtimestamp(
                                fpath.stat().st_mtime, tz=datetime.timezone.utc
                            ).isoformat(),
                        })
            return jsonify({"ok": True, "case_id": case_id, "files": files})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.route("/api/extractions/download", methods=["GET"])
    def api_download_extracted_file():
        case_id = request.args.get("case_id") or WORKSTATION_STATE.get("active_case")
        rel_path = request.args.get("path", "").strip()
        if not case_id or not rel_path:
            return jsonify({"ok": False, "error": "Missing case_id or path."}), 400
        try:
            target = safe_case_subpath(case_id, rel_path)
            ext_root = safe_case_subpath(case_id, "Extracted_Files")
            rep_root = safe_case_subpath(case_id, "Reports")
            cmd_root = safe_case_subpath(case_id, "Command_Outputs")

            if not any(root in target.parents for root in (ext_root, rep_root, cmd_root)):
                return jsonify({"ok": False, "error": "Access restricted."}), 403
            if not target.exists() or not target.is_file():
                return jsonify({"ok": False, "error": "File not found."}), 404

            return send_file(target, as_attachment=True, download_name=target.name)
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    # 11. HASHES, BROWSER ARTIFACTS & REPORT GENERATION API
    @app.route("/api/hashes", methods=["GET"])
    def api_get_hashes():
        case_id = request.args.get("case_id") or WORKSTATION_STATE.get("active_case")
        if not case_id:
            return jsonify({"ok": True, "hashes": []})
        try:
            hashes_file = safe_case_subpath(case_id, "Hashes", "hash_registry.json")
            records = json.loads(hashes_file.read_text(encoding="utf-8")) if hashes_file.exists() else []
            return jsonify({"ok": True, "case_id": case_id, "hashes": records})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.route("/api/hashes/verify", methods=["POST"])
    def api_verify_hash():
        payload = request.get_json(force=True, silent=True) or {}
        case_id = payload.get("case_id") or WORKSTATION_STATE.get("active_case")
        rel_path = str(payload.get("relative_path", "")).strip()
        expected_hash = str(payload.get("expected_sha256", "")).strip().lower()

        if not case_id or not rel_path:
            return jsonify({"ok": False, "error": "case_id and relative_path are required."}), 400

        try:
            case_meta = load_case_metadata(case_id)
            registered_ev = next((e for e in case_meta.get("evidence", []) if e["relative_path"] == rel_path or e["path"] == rel_path), None)
            if registered_ev:
                target_file = Path(registered_ev["path"]).resolve()
            else:
                target_file = safe_case_subpath(case_id, rel_path)

            if not target_file.exists() or not target_file.is_file():
                return jsonify({"ok": False, "error": f"File not found on disk: {rel_path}"}), 404

            actual_hash = compute_sha256_incremental(target_file).lower()
            matched = (actual_hash == expected_hash) if expected_hash else True
            return jsonify({
                "ok": True,
                "filename": target_file.name,
                "actual_sha256": actual_hash,
                "expected_sha256": expected_hash,
                "matched": matched,
                "verified_at": utc_now(),
            })
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.route("/api/browser_artifacts", methods=["GET"])
    def api_browser_artifacts():
        case_id = request.args.get("case_id") or WORKSTATION_STATE.get("active_case")
        scan_strings = request.args.get("scan_strings") == "1"
        if not case_id:
            return jsonify({"ok": False, "error": "Active case required."}), 400
        try:
            report = analyze_case_browser_artifacts(case_id, scan_evidence_strings=scan_strings)
            return jsonify({"ok": True, "analysis": report})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.route("/api/reports", methods=["GET"])
    def api_list_reports():
        case_id = request.args.get("case_id") or WORKSTATION_STATE.get("active_case")
        if not case_id:
            return jsonify({"ok": True, "reports": []})
        try:
            rep_dir = safe_case_subpath(case_id, "Reports")
            reports = []
            if rep_dir.exists():
                for f in sorted(rep_dir.iterdir(), reverse=True):
                    if f.is_file():
                        reports.append({
                            "filename": f.name,
                            "relative_path": str(f.relative_to(get_case_dir(case_id))),
                            "size_bytes": f.stat().st_size,
                            "size_human": human_size(f.stat().st_size),
                            "format": f.suffix.lstrip(".").upper(),
                            "created_at": datetime.datetime.fromtimestamp(
                                f.stat().st_mtime, tz=datetime.timezone.utc
                            ).isoformat(),
                        })
            return jsonify({"ok": True, "case_id": case_id, "reports": reports})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.route("/api/reports/generate", methods=["POST"])
    def api_generate_report():
        payload = request.get_json(force=True, silent=True) or {}
        case_id = payload.get("case_id") or WORKSTATION_STATE.get("active_case")
        report_type = str(payload.get("report_type", "CONSOLIDATED_CASE")).strip().upper()
        export_format = str(payload.get("format", "CSV")).strip().upper()
        analyst_notes = str(payload.get("analyst_notes", "")).strip()

        if not case_id:
            return jsonify({"ok": False, "error": "Select an active case first."}), 400
        if export_format not in ("TXT", "JSON", "CSV"):
            return jsonify({"ok": False, "error": "Format must be TXT, JSON, or CSV."}), 400

        try:
            case_meta = load_case_metadata(case_id)
            case_dir = get_case_dir(case_id)
            rep_dir = safe_case_subpath(case_id, "Reports")
            rep_dir.mkdir(parents=True, exist_ok=True)

            hist_file = case_dir / "command_history.json"
            history = json.loads(hist_file.read_text(encoding="utf-8")) if hist_file.exists() else []
            hashes_file = case_dir / "Hashes" / "hash_registry.json"
            hashes = json.loads(hashes_file.read_text(encoding="utf-8")) if hashes_file.exists() else []

            timestamp_slug = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
            report_filename = f"CHW_MemoryX_{case_id}_{report_type}_{timestamp_slug}.{export_format.lower()}"
            report_path = rep_dir / report_filename

            report_obj = {
                "product": PRODUCT_NAME,
                "logo_url": COMPANY_LOGO_URL,
                "report_type": report_type,
                "generated_at": utc_now(),
                "case_metadata": case_meta,
                "observed_command_executions": history,
                "observed_hash_records": hashes,
                "analyst_interpretations": analyst_notes,
            }

            if export_format == "JSON":
                report_path.write_text(json.dumps(report_obj, indent=2), encoding="utf-8")
            elif export_format == "CSV":
                buf = io.StringIO()
                writer = csv.writer(buf)
                writer.writerow([
                    "Case_ID", "Case_Name", "Investigator", "Evidence_Name",
                    "Plugin", "Run_ID", "Arguments", "Started_At",
                    "Duration_Sec", "Status", "Row_Count", "Output_CSV_Path", "Analyst_Notes"
                ])
                for run in history:
                    writer.writerow([
                        case_meta["case_id"],
                        case_meta["case_name"],
                        case_meta["investigator"],
                        run.get("evidence_filename", ""),
                        run.get("plugin", ""),
                        run.get("run_id", ""),
                        " ".join(run.get("arguments", [])),
                        run.get("started_at", ""),
                        run.get("duration_seconds", 0),
                        run.get("status", ""),
                        run.get("row_count", 0),
                        run.get("files", {}).get("output_csv", ""),
                        analyst_notes,
                    ])
                report_path.write_text(buf.getvalue(), encoding="utf-8")
            else:
                lines = [
                    "=" * 88,
                    f"{PRODUCT_NAME} - OFFICIAL MEMORY FORENSICS REPORT",
                    "=" * 88,
                    f"Case ID      : {case_meta['case_id']} ({case_meta['case_name']})",
                    f"Investigator : {case_meta['investigator']}",
                    f"Generated    : {utc_now()}",
                    "-" * 88,
                ]
                for ev in case_meta.get("evidence", []):
                    lines.append(
                        f"Evidence     : {ev['filename']} | Target OS: {ev.get('detected_os', 'Unknown')} | "
                        f"Size: {ev['size_human']} | SHA256: {ev['sha256']}"
                    )
                lines.append("-" * 88)
                for run in history:
                    lines.append(f"Run [{run.get('run_id')}] {run.get('plugin')} -> {run.get('status')} ({run.get('duration_seconds')}s)")
                lines.extend(["-" * 88, "Analyst Notes:", analyst_notes or "None", "=" * 88])
                report_path.write_text("\n".join(lines), encoding="utf-8")

            return jsonify({
                "ok": True,
                "filename": report_filename,
                "relative_path": str(report_path.relative_to(case_dir)),
                "format": export_format,
            })
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

    # 12. SETTINGS API
    @app.route("/api/settings", methods=["GET", "POST"])
    def api_settings():
        if request.method == "POST":
            payload = request.get_json(force=True, silent=True) or {}
            with STATE_LOCK:
                if "theme" in payload and payload["theme"] in ("dark", "light"):
                    WORKSTATION_STATE["theme"] = payload["theme"]
                save_global_state()

        return jsonify({
            "ok": True,
            "settings": {
                "product": PRODUCT_NAME,
                "logo_url": COMPANY_LOGO_URL,
                "theme": WORKSTATION_STATE.get("theme", "dark"),
            },
        })

    return app


# ---------------------------------------------------------------------------
# PORT DISCOVERY & AUTOMATIC GUI LAUNCHER
# ---------------------------------------------------------------------------
def find_available_localhost_port(preferred_port: int = 5000, max_tries: int = 50) -> int:
    for port in range(preferred_port, preferred_port + max_tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_and_open_browser(host: str, port: int) -> None:
    url = f"http://{host}:{port}"
    for _ in range(50):
        try:
            with socket.create_connection((host, port), timeout=0.3):
                print(f"[+] {PRODUCT_NAME} Ready -> Opening browser at {url}")
                try:
                    webbrowser.open(url, new=1)
                except Exception:
                    pass
                return
        except OSError:
            time.sleep(0.15)


def launch_chw_workstation() -> None:
    ensure_root_storage()
    host = "127.0.0.1"
    port = find_available_localhost_port(5000)

    with STATE_LOCK:
        WORKSTATION_STATE["server_host"] = host
        WORKSTATION_STATE["server_port"] = port
        save_global_state()

    app = create_chw_flask_app()

    banner = f"""
================================================================================
   {PRODUCT_NAME}
   AI-Integrated Memory Forensics Workstation (Volatility 3 Engine)
================================================================================
   [*] Workstation URL   : http://{host}:{port}
   [*] Case Storage Root : {RESULTS_ROOT}
   [*] CHW AI Assistant  : Enabled ({CHW_AI_URL})
================================================================================
"""
    print(banner)
    threading.Thread(target=wait_and_open_browser, args=(host, port), daemon=True).start()

    cli_log = logging.getLogger("werkzeug")
    cli_log.setLevel(logging.WARNING)
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)


def main() -> None:
    sys.stderr.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")

    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        del sys.argv[1]
        volatility3.cli.main()
        return

    if len(sys.argv) > 1:
        volatility3.cli.main()
        return

    launch_chw_workstation()


if __name__ == "__main__":
    main()
