import os
import json
import time
import threading
import sys
import base64
import re

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

# Global callbacks for broadcasting alerts
_alert_callbacks = []

def register_alert_callback(callback):
    """Registers a callback function to be called when a security alert is triggered."""
    _alert_callbacks.append(callback)

def trigger_alert(alert_type, severity, message, details=None):
    """Triggers an alert by calling all registered callbacks with event details."""
    alert_event = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "type": alert_type,       # "usb_device" or "file_restriction"
        "severity": severity,   # "critical", "warning", "info"
        "message": message,
        "details": details or {}
    }
    for cb in _alert_callbacks:
        try:
            cb(alert_event)
        except Exception as e:
            print(f"Error in alert callback: {e}")

# Base workspace directory configuration
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESTRICTIONS_PATH = os.path.join(BASE_DIR, "data", "restricted_files.json")

# Thread-safe storage for active restricted paths
_restricted_paths = set()
_restrictions_lock = threading.Lock()

# Thread-safe tracker for active alerts to avoid duplicate spamming
# Keys: (pid, create_time, normalized_path) for processes — create_time ensures
# a re-opened file (new process after kill) always fires a fresh alert.
# (hwnd, normalized_path) for window-title hits.
_active_alerts = set()
_active_alerts_lock = threading.Lock()

# Event to wake the scanner thread immediately on restriction changes
_wake_scanner = threading.Event()

# Watchdog write events cooldown tracker to prevent spam from write bursts
_last_watchdog_alerts = {}
_watchdog_alerts_lock = threading.Lock()
WATCHDOG_COOLDOWN_SECONDS = 2.0

def _normalize_user_path(path_str):
    if not path_str:
        return ""
    p = path_str.strip().strip('"').strip("'")
    p = os.path.normpath(p)
    if sys.platform == "win32":
        p = os.path.abspath(p)
        # Windows is case-insensitive, let's lower-case everything except the drive letter for standard set matching
        p = p.lower()
        if len(p) >= 2 and p[1] == ':':
            p = p[0].upper() + p[1:]
    return p

def _is_subpath_or_equal(child, parent):
    if not child or not parent:
        return False
    # Standardize both paths using our normalization
    c = _normalize_user_path(child)
    p = _normalize_user_path(parent)
    # Check if equal or child is subpath of parent
    return c == p or c.startswith(p + os.sep)

def load_restricted_paths():
    """Loads restricted paths from JSON config file."""
    global _restricted_paths
    with _restrictions_lock:
        if os.path.exists(RESTRICTIONS_PATH):
            try:
                with open(RESTRICTIONS_PATH, "r") as f:
                    paths = json.load(f)
                    # Standardize paths to absolute, normalized forms
                    _restricted_paths = {_normalize_user_path(p) for p in paths if p}
            except Exception as e:
                print(f"Error loading restricted paths: {e}")
                _restricted_paths = set()
        else:
            _restricted_paths = set()
    print(f"Loaded restricted paths: {_restricted_paths}")

def get_restricted_paths():
    """Returns a list of current restricted paths."""
    with _restrictions_lock:
        return list(_restricted_paths)

def show_user_notification(title, message):
    """Shows a native, always-on-top message box alert on the user's desktop.
    
    Flags used:
      0x10     = MB_ICONERROR  (red X icon)
      0x1000   = MB_SYSTEMMODAL  (system-level modal — appears above all apps)
      0x40000  = MB_TOPMOST  (forces window to top of Z-order)
    Combined = 0x41010
    """
    if sys.platform == "win32":
        import ctypes
        MB_FLAGS = 0x10 | 0x1000 | 0x40000  # MB_ICONERROR | MB_SYSTEMMODAL | MB_TOPMOST
        def run_popup():
            try:
                # SetForegroundWindow focus trick to raise the dialog above everything
                ctypes.windll.user32.MessageBoxW(0, message, title, MB_FLAGS)
            except Exception as e:
                print(f"Error displaying desktop message box: {e}")
        threading.Thread(target=run_popup, daemon=True).start()

def force_close_file_access(file_path):
    """Forcibly closes any process or window that has the restricted file open.
    
    Strategy:
    1. Use psutil to scan ALL processes for open file handles matching the restricted path.
    2. Also check if the process is inside a restricted directory (folder-level restriction).
    3. Fallback: Use win32gui to send WM_CLOSE to any visible window whose title contains the filename.
    4. Retry once after 800ms to catch apps that spawn a child viewer on open.
    """
    
    def _do_close(file_path):
        normalized_path = os.path.normpath(file_path).lower()
        file_name = os.path.basename(file_path).lower()
        file_dir = os.path.dirname(normalized_path)
        
        # Determine if we're watching a directory restriction or a specific file
        is_dir_restriction = os.path.isdir(file_path)
        
        # Build the set of restricted parent dirs for this event
        restricted_parents = set()
        with _restrictions_lock:
            for r_path in _restricted_paths:
                abs_r = os.path.abspath(r_path) if not os.path.isabs(r_path) else os.path.normpath(r_path)
                restricted_parents.add(abs_r.lower())
        
        terminated_count = 0
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_name = proc.name().lower()
                    # Skip critical system processes to avoid OS instability
                    SYSTEM_PROCS = {
                        "system", "svchost.exe", "explorer.exe", "lsass.exe",
                        "wininit.exe", "csrss.exe", "services.exe", "smss.exe",
                        "winlogon.exe", "taskhostw.exe", "dwm.exe", "sihost.exe"
                    }
                    if proc_name in SYSTEM_PROCS:
                        continue
                    
                    match = False
                    
                    # Check open file handles — most reliable method
                    try:
                        for f in proc.open_files():
                            f_norm = os.path.normpath(f.path).lower()
                            # Exact file match
                            if f_norm == normalized_path:
                                match = True
                                break
                            # File is inside a restricted directory
                            for rp in restricted_parents:
                                if f_norm.startswith(rp + os.sep) or f_norm == rp:
                                    match = True
                                    break
                            if match:
                                break
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    except Exception:
                        pass
                    
                    # Check command-line arguments (catches apps opened via file association)
                    if not match:
                        try:
                            cmd = proc.cmdline()
                            for arg in cmd:
                                arg_norm = os.path.normpath(arg).lower()
                                if normalized_path in arg_norm:
                                    match = True
                                    break
                                if file_name and file_name in os.path.basename(arg).lower():
                                    match = True
                                    break
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass
                        except Exception:
                            pass
                    
                    if match:
                        try:
                            proc.kill()  # SIGKILL — immediate, no graceful close
                            print(f"[SECURITY] Killed process '{proc.name()}' (PID {proc.pid}) — accessed restricted path: {file_path}", flush=True)
                            terminated_count += 1
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                    
        except Exception as e:
            print(f"[ERROR] force_close psutil scan failed: {e}", flush=True)
            
        # Fallback: win32gui window title matching
        if sys.platform == "win32":
            try:
                import win32gui
                import win32con
                
                def win_close_enum(hwnd, ctx):
                    if win32gui.IsWindowVisible(hwnd):
                        win_title = win32gui.GetWindowText(hwnd).lower()
                        if file_name and file_name in win_title:
                            win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
                            print(f"[SECURITY] Sent WM_CLOSE to window: '{win32gui.GetWindowText(hwnd)}'", flush=True)
                try:
                    win32gui.EnumWindows(win_close_enum, None)
                except Exception:
                    pass
            except ImportError:
                pass
            except Exception as e:
                print(f"[ERROR] win32gui close failed: {e}", flush=True)
        
        return terminated_count
    
    # First close attempt — immediate
    count = _do_close(file_path)
    
    # Second pass after 300ms — catches apps that open a child process or viewer window on access
    def _retry_close():
        time.sleep(0.3)
        _do_close(file_path)
    threading.Thread(target=_retry_close, daemon=True).start()


def add_restricted_path(path):
    """Adds a path to restricted list, persists config, and dynamically schedules watch."""
    global _restricted_paths
    normalized = _normalize_user_path(path)
    if not normalized:
        return
    
    should_schedule = False
    with _restrictions_lock:
        if normalized not in _restricted_paths:
            _restricted_paths.add(normalized)
            try:
                with open(RESTRICTIONS_PATH, "w") as f:
                    json.dump(list(_restricted_paths), f, indent=2)
            except Exception as e:
                print(f"Error saving restricted paths: {e}")
            should_schedule = True
            
    if should_schedule and _file_observer and _file_observer.is_alive():
        abs_p = os.path.abspath(normalized) if not os.path.isabs(normalized) else os.path.normpath(normalized)
        watch_path = abs_p if os.path.isdir(abs_p) or not os.path.exists(abs_p) else os.path.dirname(abs_p)
        if os.path.exists(watch_path) and watch_path not in _file_observer_watches:
            try:
                w = _file_observer.schedule(_file_observer_event_handler, path=watch_path, recursive=True)
                _file_observer_watches[watch_path] = w
                print(f"Dynamically scheduled watchdog watch on: {watch_path}")
            except Exception as e:
                print(f"Error dynamically scheduling watch for {watch_path}: {e}")
    
    # Wake up the scanner immediately to check the new restricted path
    _wake_scanner.set()
    print(f"Added restricted path: {normalized}")

def remove_restricted_path(path):
    """Removes a path from restricted list, persists config, and unschedules watch if unneeded."""
    global _restricted_paths
    normalized = _normalize_user_path(path)
    if not normalized:
        return
    
    should_unschedule = False
    with _restrictions_lock:
        if normalized in _restricted_paths:
            _restricted_paths.remove(normalized)
            try:
                with open(RESTRICTIONS_PATH, "w") as f:
                    json.dump(list(_restricted_paths), f, indent=2)
            except Exception as e:
                print(f"Error saving restricted paths: {e}")
            should_unschedule = True
            
    if should_unschedule:
        abs_p = os.path.abspath(normalized) if not os.path.isabs(normalized) else os.path.normpath(normalized)
        watch_path = abs_p if os.path.isdir(abs_p) or not os.path.exists(abs_p) else os.path.dirname(abs_p)
        
        if _file_observer and watch_path in _file_observer_watches:
            still_needed = False
            with _restrictions_lock:
                for rp in _restricted_paths:
                    rp_abs = os.path.abspath(rp) if not os.path.isabs(rp) else os.path.normpath(rp)
                    rp_watch = rp_abs if os.path.isdir(rp_abs) or not os.path.exists(rp_abs) else os.path.dirname(rp_abs)
                    if rp_watch == watch_path:
                        still_needed = True
                        break
            if not still_needed and watch_path != BASE_DIR:
                try:
                    _file_observer.unschedule(_file_observer_watches[watch_path])
                    del _file_observer_watches[watch_path]
                    print(f"Unscheduled watchdog watch on: {watch_path}")
                except Exception as e:
                    print(f"Error unscheduling watch for {watch_path}: {e}")
    
    # Wake up the scanner immediately to reflect removed restriction
    _wake_scanner.set()
    print(f"Removed restricted path: {normalized}")

# =============================================================================
# 1. FILE RESTRICTION WATCHER — PRIMARY: psutil process scanner
#    Secondary: watchdog for write/create events (belt + suspenders)
# =============================================================================
# KEY INSIGHT: Windows ReadDirectoryChangesW (used by watchdog) does NOT fire
# for plain file opens/reads — only for writes/creates/deletes/renames.
# The psutil scanner below catches ALL access types every 1.5 seconds.
# =============================================================================

_file_observer = None
_file_observer_watches = {}
_file_observer_event_handler = None

# Process scanner state
_scanner_thread = None
_stop_scanner = threading.Event()

# Cache of verified clean processes mapping pid -> creation_time
_clean_processes = {}

# Persistent callback reference for WNDENUMPROC to prevent garbage collection
_enum_windows_callback_ref = None

def _decode_base64_cmdline(arg):
    """Tries to find and decode base64 strings in the cmdline argument (like UWP session args)."""
    decoded_strings = []
    # Match potential base64 substrings (characters: letters, numbers, +, /, =; length >= 8)
    for m in re.finditer(r'[A-Za-z0-9+/]{8,}={0,2}', arg):
        try:
            b64_str = m.group(0)
            # Add missing base64 padding if needed
            missing_padding = len(b64_str) % 4
            if missing_padding:
                b64_str += '=' * (4 - missing_padding)
                
            b = base64.b64decode(b64_str)
            for enc in ('utf-16-le', 'utf-8', 'ascii'):
                try:
                    # Ignore decode errors to handle odd byte lengths or garbage data gracefully
                    s = b.decode(enc, errors='ignore')
                    cleaned = "".join(c for c in s if c.isprintable())
                    if cleaned:
                        decoded_strings.append(cleaned)
                except Exception:
                    pass
        except Exception:
            pass
    return decoded_strings


def _fire_restriction_alert(proc_name, pid, file_path, action="Open"):
    """Kill the process first for fastest response, then send notifications."""

    # 1. Kill immediately — fastest possible response
    force_close_file_access(file_path)

    print(f"[ALERT] Restricted access blocked: '{file_path}' by '{proc_name}' (PID {pid})", flush=True)

    # 2. Admin portal WebSocket alert
    trigger_alert(
        alert_type="file_restriction",
        severity="critical",
        message=f"RESTRICTED ACCESS: '{proc_name}' opened restricted file '{os.path.basename(file_path)}'. Access blocked.",
        details={
            "path": file_path,
            "process": proc_name,
            "pid": pid,
            "action": action
        }
    )

    # 3. Topmost system popup — non-blocking (own thread)
    show_user_notification(
        "\u26a0 Insider Detection System \u2014 Restricted File Access",
        f"WARNING: Restricted File Accessed!\n\n"
        f"Process : {proc_name} (PID {pid})\n"
        f"File    : {file_path}\n\n"
        f"This file is RESTRICTED.\n"
        f"Access has been blocked and the application closed."
    )


def start_access_scanner():
    """
    PRIMARY detection engine — three independent detection layers:

    Layer 1 — open_files():
        Catches apps (VS Code, Word, etc.) that keep file handles open.

    Layer 2 — cmdline args:
        Catches apps like Notepad that read the file into memory and close the
        handle immediately. Decoding base64 session arguments is supported.

    Layer 3 — window title (ctypes EnumWindows):
        Catches any visible window whose title contains the restricted filename.
        Runs every 0.3 seconds in a background thread.
    """
    global _scanner_thread
    _stop_scanner.clear()
    _wake_scanner.clear()

    # System processes we must never kill/alert
    SAFE_PROCS = {
        "system", "svchost.exe", "explorer.exe", "lsass.exe", "wininit.exe",
        "csrss.exe", "services.exe", "smss.exe", "winlogon.exe", "taskhostw.exe",
        "dwm.exe", "sihost.exe", "runtimebroker.exe", "searchhost.exe",
        "applicationframehost.exe",  # UWP host — don't kill
        # Never kill our own Python process
        "python.exe", "python3.exe", "python3.11.exe", "pythonw.exe", "pythonw3.11.exe"
    }

    # Ensure windows types are defined for ctypes callbacks
    if sys.platform == "win32":
        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)

    def scan_loop():
        import psutil
        global _clean_processes, _enum_windows_callback_ref
        cycle_count = 0
        heavy_scan_cycle = 0

        while not _stop_scanner.is_set():
            try:
                cycle_count += 1
                if cycle_count >= 20:  # Clear clean process cache every ~4s (20 * 0.2s)
                    _clean_processes.clear()
                    cycle_count = 0

                heavy_scan_cycle += 1
                run_heavy_scan = False
                if heavy_scan_cycle >= 2:  # Heavy psutil scan every 2 cycles = 0.4s (was 1.5s)
                    run_heavy_scan = True
                    heavy_scan_cycle = 0

                # Clean up process cache for exited processes to prevent memory leak
                if run_heavy_scan:
                    try:
                        active_pids = set(psutil.pids())
                        for k in list(_clean_processes.keys()):
                            if k[0] not in active_pids:
                                del _clean_processes[k]
                    except Exception:
                        pass

                # Snapshot current restricted paths
                with _restrictions_lock:
                    restricted = list(_restricted_paths)
                
                # print(f"[SCANNER-DEBUG] Snapshot of restricted paths: {restricted}", flush=True)

                if restricted:
                    # Normalize all restricted paths once per cycle
                    abs_restricted = [_normalize_user_path(r) for r in restricted]

                    # Restricted filenames mapped to list of paths to resolve same-name collision (like secret.txt in multiple dirs)
                    restricted_name_map = {}
                    def _add_to_name_map(fname, fpath):
                        fname = fname.lower()
                        if fname not in restricted_name_map:
                            restricted_name_map[fname] = []
                        if fpath not in restricted_name_map[fname]:
                            restricted_name_map[fname].append(fpath)

                    for abs_r in abs_restricted:
                        if os.path.isdir(abs_r):
                            _add_to_name_map(os.path.basename(abs_r), abs_r)
                            try:
                                for entry in os.scandir(abs_r):
                                    if entry.is_file():
                                        _add_to_name_map(entry.name, entry.path)
                            except Exception:
                                pass
                        else:
                            name = os.path.basename(abs_r)
                            if name:
                                _add_to_name_map(name, abs_r)

                    # Set to collect alerts active in the current cycle
                    current_alerts = set()

                    # ── LAYER 3: Window Title Scanning (High Priority Fallback for Non-Admin) ──
                    if sys.platform == "win32":
                        def enum_windows_callback(hwnd, lParam):
                            try:
                                if ctypes.windll.user32.IsWindowVisible(hwnd):
                                    length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
                                    if length > 0:
                                        buff = ctypes.create_unicode_buffer(length + 1)
                                        ctypes.windll.user32.GetWindowTextW(hwnd, buff, length + 1)
                                        title = buff.value.lower()
                                        
                                        # Skip common system false positives ONLY if they do not contain restricted filenames
                                        skip_keywords = ["insider detection", "watchers.py", "main.py", "python"]
                                        is_restricted_found = False
                                        matched_name = None
                                        matched_path = None
                                        
                                        paths_list = []
                                        for name, paths in restricted_name_map.items():
                                            if name in title:
                                                is_restricted_found = True
                                                matched_name = name
                                                # Collect ALL paths for this name (same filename in multiple folders)
                                                paths_list = paths
                                                break
                                                
                                        if is_restricted_found and paths_list:
                                            # We prioritize matching restricted file access! Do not skip.
                                            pname = "Window Application"
                                            pid_val = 0
                                            try:
                                                pid = ctypes.c_ulong()
                                                ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                                                if pid.value > 0:
                                                    pid_val = pid.value
                                                    pname = psutil.Process(pid.value).name()
                                            except Exception:
                                                pass
                                            
                                            # Resolve same-named file path collision using process context
                                            matched_path = paths_list[0]
                                            if pid_val > 0:
                                                try:
                                                    # Check open files of the owning process
                                                    p_proc = psutil.Process(pid_val)
                                                    for f in p_proc.open_files():
                                                        f_norm = _normalize_user_path(f.path)
                                                        if f_norm in paths_list:
                                                            matched_path = f_norm
                                                            break
                                                    
                                                    # Fallback: check command line
                                                    if matched_path == paths_list[0]:
                                                        for arg in p_proc.cmdline():
                                                            arg_norm = _normalize_user_path(arg)
                                                            for p_item in paths_list:
                                                                if p_item in arg_norm or arg_norm == p_item:
                                                                    matched_path = p_item
                                                                    break
                                                except Exception:
                                                    pass
                                            
                                            # If still not resolved, check folder context in title bar
                                            if matched_path == paths_list[0] and len(paths_list) > 1:
                                                for p_item in paths_list:
                                                    parent_dir_name = os.path.basename(os.path.dirname(p_item)).lower()
                                                    if parent_dir_name in title:
                                                        matched_path = p_item
                                                        break
                                                
                                            alert_key = (hwnd, matched_path)
                                            current_alerts.add(alert_key)
                                            
                                            with _active_alerts_lock:
                                                if alert_key not in _active_alerts:
                                                    _active_alerts.add(alert_key)
                                                    print(
                                                        f"[SCANNER-GUI] DETECTED '{pname}' Window '{buff.value}' "
                                                        f"accessing restricted: {matched_path}", flush=True
                                                    )
                                                    _fire_restriction_alert(
                                                        proc_name=pname,
                                                        pid=pid_val,
                                                        file_path=matched_path,
                                                        action="Open (Window Title)"
                                                    )
                                        else:
                                            # If not restricted, skip if it matches system keywords
                                            if any(sk in title for sk in skip_keywords):
                                                return True
                            except Exception as e:
                                print(f"[SCANNER-GUI] Callback error: {e}", flush=True)
                            return True
                            
                        _enum_windows_callback_ref = WNDENUMPROC(enum_windows_callback)
                        ctypes.windll.user32.EnumWindows(_enum_windows_callback_ref, 0)

                    # ── LAYERS 1 & 2: Process Handles & Command Lines ──
                    processes_to_scan = psutil.process_iter(['pid', 'name']) if run_heavy_scan else []
                    for proc in processes_to_scan:
                        if _stop_scanner.is_set():
                            break
                        try:
                            proc_name = proc.name().lower()
                            if proc_name in SAFE_PROCS:
                                continue

                            pid = proc.pid
                            try:
                                create_time = proc.create_time()
                            except Exception:
                                create_time = 0

                            # Cache key includes create_time so a new process reusing
                            # the same PID after being killed is never incorrectly skipped
                            cache_key = (pid, create_time)
                            if cache_key in _clean_processes:
                                continue

                            matched_path = None   # the restricted path that triggered

                            # ── LAYER 1: open file handles ──────────────────
                            try:
                                for f in proc.open_files():
                                    f_norm = _normalize_user_path(f.path)
                                    for abs_r in abs_restricted:
                                        if f_norm == abs_r or f_norm.startswith(abs_r + os.sep):
                                            matched_path = f.path
                                            break
                                    if matched_path:
                                        break
                            except (psutil.AccessDenied, psutil.NoSuchProcess):
                                pass
                            except Exception:
                                pass

                            # ── LAYER 2: command-line arguments ─────────────
                            if not matched_path:
                                try:
                                    cmdline = proc.cmdline()
                                    for arg in cmdline[1:]:
                                        if not arg:
                                            continue
                                        
                                        # Direct substring match
                                        arg_norm = _normalize_user_path(arg)
                                        for abs_r in abs_restricted:
                                            if arg_norm == abs_r or arg_norm.startswith(abs_r + os.sep):
                                                matched_path = arg
                                                break
                                        if matched_path:
                                            break
                                            
                                        # Decode potential base64 (e.g. Windows 11 UWP Notepad session args)
                                        decoded = _decode_base64_cmdline(arg)
                                        for dp in decoded:
                                            dp_norm = _normalize_user_path(dp)
                                            for abs_r in abs_restricted:
                                                if dp_norm == abs_r or dp_norm.startswith(abs_r + os.sep) or abs_r in dp_norm:
                                                    matched_path = dp
                                                    break
                                            if matched_path:
                                                break
                                        if matched_path:
                                            break
                                except (psutil.AccessDenied, psutil.NoSuchProcess):
                                    pass
                                except Exception:
                                    pass

                            if matched_path:
                                # Key includes create_time: re-open after kill (new PID or
                                # same PID reused) always generates a fresh alert
                                alert_key = (pid, create_time, _normalize_user_path(matched_path))
                                current_alerts.add(alert_key)

                                with _active_alerts_lock:
                                    if alert_key not in _active_alerts:
                                        _active_alerts.add(alert_key)
                                        print(
                                            f"[SCANNER] DETECTED '{proc.name()}' (PID {proc.pid}) "
                                            f"accessing restricted: {matched_path}", flush=True
                                        )
                                        _fire_restriction_alert(
                                            proc_name=proc.name(),
                                            pid=proc.pid,
                                            file_path=matched_path,
                                            action="Open"
                                        )
                            else:
                                if create_time > 0:
                                    _clean_processes[cache_key] = True

                        except (psutil.NoSuchProcess, psutil.AccessDenied,
                                psutil.ZombieProcess):
                            continue

                    # Purge alert keys for processes that no longer exist
                    if run_heavy_scan:
                        try:
                            active_pids = set(psutil.pids())
                            with _active_alerts_lock:
                                _active_alerts.difference_update(
                                    {k for k in _active_alerts
                                     if isinstance(k, tuple) and len(k) == 3
                                     and k[0] not in active_pids}
                                )
                        except Exception:
                            pass

            except Exception as e:
                print(f"[SCANNER] Error in scan loop: {e}", flush=True)

            # Wait for 0.2s or until woken by a restriction change
            _wake_scanner.wait(timeout=0.2)
            _wake_scanner.clear()

    _scanner_thread = threading.Thread(target=scan_loop, daemon=True, name="AccessScanner")
    _scanner_thread.start()
    print("Process Access Scanner started (open_files + cmdline + win32gui, 0.4s heavy scan, re-open detection fixed).", flush=True)


def stop_access_scanner():
    _stop_scanner.set()


def start_file_watcher():
    """Starts both the psutil access scanner (primary) and watchdog (secondary)."""
    load_restricted_paths()

    # Guard against double-start on uvicorn reload
    if _scanner_thread is not None and _scanner_thread.is_alive():
        print("Access scanner already running, skipping re-start.", flush=True)
    else:
        start_access_scanner()

    # --- SECONDARY: watchdog for file write/create/delete events ---
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler

        class FileAlertHandler(FileSystemEventHandler):
            def on_any_event(self, event):
                if event.is_directory:
                    return
                # Only act on write/create events — not on read events (which don't fire anyway)
                if event.event_type not in ('modified', 'created', 'deleted', 'moved'):
                    return

                event_path = os.path.normpath(event.src_path)

                with _restrictions_lock:
                    for r_path in _restricted_paths:
                        abs_r = (os.path.normpath(r_path) if os.path.isabs(r_path)
                                 else os.path.normpath(os.path.join(BASE_DIR, r_path)))
                        if event_path == abs_r or event_path.startswith(abs_r + os.sep):
                            print(
                                f"[WATCHDOG] Write event '{event.event_type}' "
                                f"on restricted: {event_path}", flush=True
                            )
                            # Prevent write burst duplicate alerts using watchdog specific cooldown
                            now = time.monotonic()
                            with _watchdog_alerts_lock:
                                last = _last_watchdog_alerts.get(event_path, 0)
                                if (now - last) >= WATCHDOG_COOLDOWN_SECONDS:
                                    _last_watchdog_alerts[event_path] = now
                                    should_alert = True
                                else:
                                    should_alert = False

                            if should_alert:
                                trigger_alert(
                                    alert_type="file_restriction",
                                    severity="critical",
                                    message=f"RESTRICTED ACCESS: File '{os.path.basename(event_path)}' was {event.event_type}. Access blocked.",
                                    details={
                                        "path": event_path,
                                        "action": event.event_type.capitalize()
                                    }
                                )
                                show_user_notification(
                                    "\u26a0 Insider Detection System \u2014 Restricted File Access",
                                    f"WARNING: Restricted File Modified!\n\n"
                                    f"File    : {event_path}\n"
                                    f"Action  : {event.event_type.upper()}\n\n"
                                    f"This file is RESTRICTED.\n"
                                    f"Access has been blocked."
                                )
                                force_close_file_access(event_path)
                            break

        global _file_observer, _file_observer_watches, _file_observer_event_handler
        _file_observer_event_handler = FileAlertHandler()
        _file_observer = Observer()

        # Watch the base project dir
        watch = _file_observer.schedule(
            _file_observer_event_handler, path=BASE_DIR, recursive=True
        )
        _file_observer_watches[BASE_DIR] = watch

        # Watch every existing restricted path
        with _restrictions_lock:
            for r_path in _restricted_paths:
                abs_r = (os.path.normpath(r_path) if os.path.isabs(r_path)
                         else os.path.normpath(os.path.join(BASE_DIR, r_path)))
                watch_path = abs_r if os.path.isdir(abs_r) else os.path.dirname(abs_r)
                if os.path.exists(watch_path) and watch_path not in _file_observer_watches:
                    try:
                        w = _file_observer.schedule(
                            _file_observer_event_handler, path=watch_path, recursive=True
                        )
                        _file_observer_watches[watch_path] = w
                        print(f"Watchdog (secondary) watching: {watch_path}", flush=True)
                    except Exception as e:
                        print(f"Watchdog schedule error for {watch_path}: {e}", flush=True)

        _file_observer.start()
        print("Watchdog secondary watcher started.", flush=True)

    except Exception as e:
        print(f"Watchdog secondary watcher unavailable: {e}", flush=True)


def stop_file_watcher():
    """Stops both the scanner and the watchdog observer."""
    stop_access_scanner()
    global _file_observer
    if _file_observer:
        try:
            _file_observer.stop()
            _file_observer.join()
            print("Watchdog File Watcher stopped.")
        except Exception as e:
            print(f"Error stopping file watcher: {e}")

_simulated_file_thread = None
_stop_simulated_file = threading.Event()

def start_simulated_file_watcher():
    """Starts a fallback simulator thread to generate random alerts for demonstration."""
    global _simulated_file_thread
    _stop_simulated_file.clear()
    
    def simulate_loop():
        while not _stop_simulated_file.is_set():
            time.sleep(45)
            if _stop_simulated_file.is_set():
                break
                
            restricted = get_restricted_paths()
            if restricted:
                target_path = restricted[0]
                abs_t = os.path.abspath(os.path.join(BASE_DIR, target_path)) if not os.path.isabs(target_path) else os.path.normpath(target_path)
                
                trigger_alert(
                    alert_type="file_restriction",
                    severity="critical",
                    message="Restricted Access Attempt (Simulated) on restricted location.",
                    details={
                        "path": abs_t,
                        "restricted_rule": target_path,
                        "action": "Modify"
                    }
                )
                
                # Show Windows System Message Box popup to user (even in simulation)
                show_user_notification(
                    "Insider Detection System", 
                    f"Access Denied (Simulated)!\n\nRestricted folder/file access attempt detected:\n{abs_t}"
                )
                
    _simulated_file_thread = threading.Thread(target=simulate_loop, daemon=True)
    _simulated_file_thread.start()
    print("Simulated File Watcher started.")

def stop_simulated_file_watcher():
    _stop_simulated_file.set()


# =============================================================================
# 2. USB MONITOR WATCHER (using win32gui)
# =============================================================================
_usb_watcher_thread = None
_stop_usb_watcher = threading.Event()

# Register device notification structure for Windows
DBT_DEVICEARRIVAL = 0x8000
DBT_DEVICEREMOVECOMPLETE = 0x8004
WM_DEVICECHANGE = 0x0219

SAFE_USBS_PATH = os.path.join(BASE_DIR, "data", "safe_usbs.json")
_safe_usbs = {}
_safe_usbs_lock = threading.Lock()

_active_simulated_usb = None

def load_safe_usbs():
    """Loads whitelisted safe USB devices from JSON."""
    global _safe_usbs
    with _safe_usbs_lock:
        if os.path.exists(SAFE_USBS_PATH):
            try:
                with open(SAFE_USBS_PATH, "r") as f:
                    data = json.load(f)
                    _safe_usbs = {item["serial"]: item["name"] for item in data}
            except Exception as e:
                print(f"Error loading safe USBs: {e}")
                _safe_usbs = {}
        else:
            _safe_usbs = {}
    print(f"Loaded safe USBs: {_safe_usbs}")

def get_safe_usbs():
    """Returns a list of all safe/whitelisted USBs."""
    with _safe_usbs_lock:
        return [{"serial": s, "name": n} for s, n in _safe_usbs.items()]

def add_safe_usb(serial, name):
    """Adds a USB device to the safe whitelist and persists it."""
    global _safe_usbs
    with _safe_usbs_lock:
        _safe_usbs[serial] = name
        try:
            with open(SAFE_USBS_PATH, "w") as f:
                json.dump([{"serial": s, "name": n} for s, n in _safe_usbs.items()], f, indent=2)
        except Exception as e:
            print(f"Error saving safe USBs: {e}")
    print(f"Whitelisted USB: {name} (Serial: {serial})")

def remove_safe_usb(serial):
    """Removes a USB device from the safe whitelist."""
    global _safe_usbs
    with _safe_usbs_lock:
        if serial in _safe_usbs:
            del _safe_usbs[serial]
            try:
                with open(SAFE_USBS_PATH, "w") as f:
                    json.dump([{"serial": s, "name": n} for s, n in _safe_usbs.items()], f, indent=2)
            except Exception as e:
                print(f"Error saving safe USBs: {e}")
    print(f"Removed USB Serial {serial} from whitelist.")

def is_usb_safe(serial):
    """Checks if a USB device serial is whitelisted."""
    with _safe_usbs_lock:
        return serial in _safe_usbs

def get_connected_usbs():
    """Returns currently connected physical/simulated USB drives."""
    drives = []
    if sys.platform == "win32":
        try:
            import win32api
            import win32file
            drive_strings = win32api.GetLogicalDriveStrings()
            for drive in drive_strings.split('\0'):
                if drive and win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                    try:
                        info = win32api.GetVolumeInformation(drive)
                        volume_name = info[0] if info[0] else "Removable Disk"
                        serial = str(info[1])
                    except Exception:
                        volume_name = "Removable Disk"
                        serial = "UNKNOWN"
                    drives.append({
                        "drive": drive,
                        "name": volume_name,
                        "serial": serial
                    })
        except Exception as e:
            print(f"Error checking physical USB drives: {e}")
            
    # Fallback to simulated USB if none exist and simulated is inserted
    if not drives and _active_simulated_usb:
        drives.append(_active_simulated_usb)
        
    return drives

def start_usb_watcher():
    """Starts the USB connection watcher (native Windows win32gui or fallback mock)."""
    global _usb_watcher_thread
    load_safe_usbs()
    
    if sys.platform == "win32":
        try:
            import win32gui
            import win32con
            
            def win32_msg_loop():
                def wnd_proc(hwnd, msg, wparam, lparam):
                    if msg == WM_DEVICECHANGE:
                        if wparam == DBT_DEVICEARRIVAL:
                            time.sleep(1.0)  # Wait for mount
                            drives = get_connected_usbs()
                            if drives:
                                for d in drives:
                                    serial = d["serial"]
                                    if is_usb_safe(serial):
                                        trigger_alert(
                                            alert_type="usb_device",
                                            severity="info",
                                            message=f"Safe USB Connected! Drive {d['drive']} ({d['name']}) is whitelisted.",
                                            details=d
                                        )
                                    else:
                                        trigger_alert(
                                            alert_type="usb_device",
                                            severity="warning",
                                            message=f"Unauthorized USB Connected! Drive {d['drive']} ({d['name']}) detected.",
                                            details=d
                                        )
                                        show_user_notification(
                                            "Insider Detection System",
                                            f"Unauthorized USB Connected!\n\nDrive {d['drive']} ({d['name']}) has been detected.\nThis device is not in the safe whitelist."
                                        )
                            else:
                                trigger_alert(
                                    alert_type="usb_device",
                                    severity="warning",
                                    message="New USB device detected! Drive connection arrival event."
                                )
                        elif wparam == DBT_DEVICEREMOVECOMPLETE:
                            trigger_alert(
                                alert_type="usb_device",
                                severity="info",
                                message="USB device disconnected! Drive removal event completed."
                            )
                    return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)
                
                wc = win32gui.WNDCLASS()
                wc.lpfnWndProc = wnd_proc
                wc.lpszClassName = "USBWatcherClass"
                
                try:
                    class_atom = win32gui.RegisterClass(wc)
                    hwnd = win32gui.CreateWindow(
                        class_atom, "USBWatcherWindow", 0, 0, 0, 0, 0, 0, 0, 0, None
                    )
                    print("Windows native USB Watcher registered window successfully.")
                    
                    while not _stop_usb_watcher.is_set():
                        win32gui.PumpWaitingMessages()
                        time.sleep(0.5)
                        
                except Exception as e:
                    print(f"Error in win32 message loop: {e}")
                    
            _stop_usb_watcher.clear()
            _usb_watcher_thread = threading.Thread(target=win32_msg_loop, daemon=True)
            _usb_watcher_thread.start()
            print("Native Windows win32gui USB Watcher started.")
            return
            
        except ImportError:
            print("pywin32 not installed or not available. Falling back to Simulated USB Watcher.")
    else:
        print("Not running on Windows. Falling back to Simulated USB Watcher.")
        
    start_simulated_usb_watcher()

def stop_usb_watcher():
    """Stops the active USB watcher."""
    _stop_usb_watcher.set()
    stop_simulated_usb_watcher()

_simulated_usb_thread = None
_stop_simulated_usb = threading.Event()

def start_simulated_usb_watcher():
    """Fallback simulation thread that generates periodic USB insertion/removal alerts."""
    global _simulated_usb_thread
    _stop_simulated_usb.clear()
    
    def simulate_usb_loop():
        global _active_simulated_usb
        usb_connected = False
        while not _stop_simulated_usb.is_set():
            # Wait a random duration (between 60s and 120s) to toggle USB insertion
            time.sleep(60)
            if _stop_simulated_usb.is_set():
                break
                
            usb_connected = not usb_connected
            if usb_connected:
                _active_simulated_usb = {
                    "drive": "E:\\",
                    "name": "SanDisk Cruzer",
                    "serial": "1234-5678"
                }
                if is_usb_safe(_active_simulated_usb["serial"]):
                    trigger_alert(
                        alert_type="usb_device",
                        severity="info",
                        message="Safe USB Connected (Simulated)! Drive E:\\ (SanDisk Cruzer) is whitelisted.",
                        details=_active_simulated_usb
                    )
                else:
                    trigger_alert(
                        alert_type="usb_device",
                        severity="warning",
                        message="Unauthorized USB Connected (Simulated)! Drive E:\\ (SanDisk Cruzer) detected.",
                        details=_active_simulated_usb
                    )
                    show_user_notification(
                        "Insider Detection System",
                        f"Unauthorized USB Connected!\n\nDrive E:\\ (SanDisk Cruzer) has been detected.\nThis device is not in the safe whitelist."
                    )
            else:
                if _active_simulated_usb:
                    trigger_alert(
                        alert_type="usb_device",
                        severity="info",
                        message="USB device disconnected! (Simulated drive removal event).",
                        details=_active_simulated_usb
                    )
                _active_simulated_usb = None
                
    _simulated_usb_thread = threading.Thread(target=simulate_usb_loop, daemon=True)
    _simulated_usb_thread.start()
    print("Simulated USB Watcher started.")

def stop_simulated_usb_watcher():
    global _active_simulated_usb
    _stop_simulated_usb.set()
    _active_simulated_usb = None
