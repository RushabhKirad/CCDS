import os
import json
import time
import threading
import sys

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

# ── Alert callbacks ────────────────────────────────────────────────────────────
_alert_callbacks = []

def register_alert_callback(cb):
    _alert_callbacks.append(cb)

def trigger_alert(alert_type, severity, message, details=None):
    event = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "type": alert_type,
        "severity": severity,
        "message": message,
        "details": details or {}
    }
    for cb in _alert_callbacks:
        try:
            cb(event)
        except Exception as e:
            print(f"[CB ERROR] {e}")

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESTRICTIONS_PATH = os.path.join(BASE_DIR, "data", "restricted_files.json")
SAFE_USBS_PATH = os.path.join(BASE_DIR, "data", "safe_usbs.json")

# ── Restricted paths store ─────────────────────────────────────────────────────
_restricted_paths = set()
_lock = threading.Lock()

def _norm(path):
    """Normalize to absolute lowercase path (Windows case-insensitive)."""
    if not path:
        return ""
    p = os.path.normpath(os.path.abspath(path.strip().strip('"').strip("'")))
    if sys.platform == "win32":
        p = p.lower()
        if len(p) >= 2 and p[1] == ':':
            p = p[0].upper() + p[1:]
    return p

def load_restricted_paths():
    global _restricted_paths
    with _lock:
        if os.path.exists(RESTRICTIONS_PATH):
            try:
                with open(RESTRICTIONS_PATH) as f:
                    _restricted_paths = {_norm(p) for p in json.load(f) if p}
            except Exception as e:
                print(f"[WATCHER] Load error: {e}")
                _restricted_paths = set()
        else:
            _restricted_paths = set()
    print(f"[WATCHER] Restricted paths loaded: {_restricted_paths}")

def _save_restricted():
    try:
        with open(RESTRICTIONS_PATH, "w") as f:
            json.dump(list(_restricted_paths), f, indent=2)
    except Exception as e:
        print(f"[WATCHER] Save error: {e}")

def get_restricted_paths():
    with _lock:
        return list(_restricted_paths)

def add_restricted_path(path):
    n = _norm(path)
    if not n:
        return
    with _lock:
        if n not in _restricted_paths:
            _restricted_paths.add(n)
            _save_restricted()
    _wake.set()
    print(f"[WATCHER] Added restriction: {n}")

def remove_restricted_path(path):
    n = _norm(path)
    with _lock:
        if n in _restricted_paths:
            _restricted_paths.discard(n)
            _save_restricted()
    _wake.set()
    print(f"[WATCHER] Removed restriction: {n}")

# ── Desktop notification ───────────────────────────────────────────────────────
def _notify(title, message):
    if sys.platform == "win32":
        def _show():
            try:
                ctypes.windll.user32.MessageBoxW(
                    0, message, title,
                    0x10 | 0x1000 | 0x40000  # MB_ICONERROR | MB_SYSTEMMODAL | MB_TOPMOST
                )
            except Exception:
                pass
        threading.Thread(target=_show, daemon=True).start()

# ── Kill any process with the restricted file open ─────────────────────────────
def _kill_accessors(file_path):
    import psutil
    norm = _norm(file_path)

    SAFE = {
        "system", "svchost.exe", "explorer.exe", "lsass.exe", "wininit.exe",
        "csrss.exe", "services.exe", "smss.exe", "winlogon.exe", "taskhostw.exe",
        "dwm.exe", "sihost.exe", "runtimebroker.exe",
        "python.exe", "python3.exe", "python3.11.exe", "pythonw.exe"
    }

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.name().lower() in SAFE:
                continue
            hit = False
            # Check open file handles
            try:
                for f in proc.open_files():
                    fn = _norm(f.path)
                    if fn == norm or fn.startswith(norm + os.sep):
                        hit = True
                        break
            except Exception:
                pass
            # Check cmdline
            if not hit:
                try:
                    for arg in proc.cmdline()[1:]:
                        an = _norm(arg)
                        if an == norm or an.startswith(norm + os.sep):
                            hit = True
                            break
                except Exception:
                    pass
            if hit:
                proc.kill()
                print(f"[WATCHER] Killed {proc.name()} (PID {proc.pid})", flush=True)
        except Exception:
            pass

# ── Fire alert + kill + notify ─────────────────────────────────────────────────
def _fire_alert(proc_name, pid, file_path):
    # _kill_accessors(file_path)
    fname = os.path.basename(file_path)
    print(f"[ALERT] {proc_name} (PID {pid}) accessed restricted: {file_path}", flush=True)
    trigger_alert(
        alert_type="file_restriction",
        severity="critical",
        message=f"RESTRICTED ACCESS: '{proc_name}' opened '{fname}'. Access blocked.",
        details={"path": file_path, "process": proc_name, "pid": pid}
    )
    _notify(
        "⚠ Insider Detection — Restricted File Access",
        f"WARNING: Restricted file accessed!\n\nProcess: {proc_name} (PID {pid})\nFile: {file_path}\n\nAccess has been blocked."
    )

# ── Scanner ────────────────────────────────────────────────────────────────────
_wake = threading.Event()
_stop = threading.Event()
_scanner_thread = None

# Track active alerts: (pid, create_time, norm_path) — prevents duplicate spam
# while still re-alerting when file is closed and reopened (new create_time or PID)
_active = set()
_active_lock = threading.Lock()

# WNDENUMPROC ref — must be kept alive to prevent GC crash
_enum_cb_ref = None

def _scan_loop():
    import psutil

    SAFE = {
        "system", "svchost.exe", "explorer.exe", "lsass.exe", "wininit.exe",
        "csrss.exe", "services.exe", "smss.exe", "winlogon.exe", "taskhostw.exe",
        "dwm.exe", "sihost.exe", "runtimebroker.exe",
        "python.exe", "python3.exe", "python3.11.exe", "pythonw.exe"
    }

    if sys.platform == "win32":
        WNDENUMPROC = ctypes.WINFUNCTYPE(
            ctypes.wintypes.BOOL,
            ctypes.wintypes.HWND,
            ctypes.wintypes.LPARAM
        )

    global _enum_cb_ref

    while not _stop.is_set():
        try:
            with _lock:
                restricted = list(_restricted_paths)

            if not restricted:
                _wake.wait(timeout=0.5)
                _wake.clear()
                continue

            # Normalize once per cycle
            norm_restricted = [_norm(r) for r in restricted]

            # Build filename → [paths] map for window title matching
            name_map = {}
            for nr in norm_restricted:
                name = os.path.basename(nr).lower()
                if name:
                    name_map.setdefault(name, [])
                    if nr not in name_map[name]:
                        name_map[name].append(nr)
                # If it's a folder, also add children filenames
                if os.path.isdir(nr):
                    try:
                        for entry in os.scandir(nr):
                            if entry.is_file():
                                en = entry.name.lower()
                                name_map.setdefault(en, [])
                                if entry.path not in name_map[en]:
                                    name_map[en].append(entry.path)
                    except Exception:
                        pass

            # ── Layer 1 & 2: psutil open_files + cmdline ──────────────────────
            for proc in psutil.process_iter(['pid', 'name']):
                if _stop.is_set():
                    break
                try:
                    if proc.name().lower() in SAFE:
                        continue

                    pid = proc.pid
                    try:
                        ct = proc.create_time()
                    except Exception:
                        ct = 0

                    matched = None

                    # cmdline first — Notepad/UWP apps close file handle immediately
                    # but keep the path in cmdline for the whole session
                    try:
                        for arg in proc.cmdline()[1:]:
                            an = _norm(arg)
                            for nr in norm_restricted:
                                if an == nr or an.startswith(nr + os.sep):
                                    matched = arg
                                    break
                            if matched:
                                break
                    except Exception:
                        pass

                    # open file handles — catches editors that keep handles open
                    if not matched:
                        try:
                            for f in proc.open_files():
                                fn = _norm(f.path)
                                for nr in norm_restricted:
                                    if fn == nr or fn.startswith(nr + os.sep):
                                        matched = f.path
                                        break
                                if matched:
                                    break
                        except Exception:
                            pass

                    if matched:
                        key = (pid, ct, _norm(matched))
                        with _active_lock:
                            if key not in _active:
                                _active.add(key)
                                _fire_alert(proc.name(), pid, matched)

                except Exception:
                    continue

            # ── Layer 3: window title scan ────────────────────────────────────
            if sys.platform == "win32" and name_map:
                def _win_cb(hwnd, _):
                    try:
                        if not ctypes.windll.user32.IsWindowVisible(hwnd):
                            return True
                        length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
                        if length == 0:
                            return True
                        buf = ctypes.create_unicode_buffer(length + 1)
                        ctypes.windll.user32.GetWindowTextW(hwnd, buf, length + 1)
                        title = buf.value.lower()

                        for fname, paths in name_map.items():
                            if fname in title:
                                # get PID of this window
                                pid_buf = ctypes.c_ulong(0)
                                ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_buf))
                                pid = pid_buf.value
                                pname = "Unknown"
                                ct = 0
                                try:
                                    import psutil as _ps
                                    p = _ps.Process(pid)
                                    pname = p.name()
                                    ct = p.create_time()
                                    if pname.lower() in SAFE:
                                        return True
                                except Exception:
                                    pass

                                fpath = paths[0]
                                key = (pid, ct, _norm(fpath))
                                with _active_lock:
                                    if key not in _active:
                                        _active.add(key)
                                        _fire_alert(pname, pid, fpath)
                                break
                    except Exception:
                        pass
                    return True

                _enum_cb_ref = WNDENUMPROC(_win_cb)
                ctypes.windll.user32.EnumWindows(_enum_cb_ref, 0)

            # ── Purge stale alert keys for dead processes ─────────────────────
            try:
                live_pids = set(psutil.pids())
                with _active_lock:
                    _active.difference_update(
                        {k for k in _active if k[0] not in live_pids}
                    )
            except Exception:
                pass

        except Exception as e:
            print(f"[SCANNER] Error: {e}", flush=True)

        _wake.wait(timeout=0.15)
        _wake.clear()


def start_file_watcher():
    global _scanner_thread
    load_restricted_paths()
    if _scanner_thread and _scanner_thread.is_alive():
        print("[WATCHER] Scanner already running.")
        return
    _stop.clear()
    _scanner_thread = threading.Thread(target=_scan_loop, daemon=True, name="FileScanner")
    _scanner_thread.start()
    print("[WATCHER] File scanner started (0.3s interval).")


def stop_file_watcher():
    _stop.set()
    _wake.set()


# ── USB Watcher ────────────────────────────────────────────────────────────────
_safe_usbs = {}
_usb_lock = threading.Lock()
_stop_usb = threading.Event()
_usb_thread = None

DBT_DEVICEARRIVAL      = 0x8000
DBT_DEVICEREMOVECOMPLETE = 0x8004
WM_DEVICECHANGE        = 0x0219


def load_safe_usbs():
    global _safe_usbs
    with _usb_lock:
        if os.path.exists(SAFE_USBS_PATH):
            try:
                with open(SAFE_USBS_PATH) as f:
                    data = json.load(f)
                    _safe_usbs = {item["serial"]: item["name"] for item in data}
            except Exception:
                _safe_usbs = {}
        else:
            _safe_usbs = {}
    print(f"[USB] Safe USBs loaded: {_safe_usbs}")


def _save_usbs():
    try:
        with open(SAFE_USBS_PATH, "w") as f:
            json.dump([{"serial": s, "name": n} for s, n in _safe_usbs.items()], f, indent=2)
    except Exception as e:
        print(f"[USB] Save error: {e}")


def get_safe_usbs():
    with _usb_lock:
        return [{"serial": s, "name": n} for s, n in _safe_usbs.items()]


def add_safe_usb(serial, name):
    with _usb_lock:
        _safe_usbs[serial] = name
        _save_usbs()
    print(f"[USB] Whitelisted: {name} ({serial})")


def remove_safe_usb(serial):
    with _usb_lock:
        _safe_usbs.pop(serial, None)
        _save_usbs()
    print(f"[USB] Removed from whitelist: {serial}")


def is_usb_safe(serial):
    with _usb_lock:
        return serial in _safe_usbs


def get_connected_usbs():
    drives = []
    if sys.platform == "win32":
        try:
            import win32api, win32file
            for drive in win32api.GetLogicalDriveStrings().split('\0'):
                if drive and win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                    try:
                        info = win32api.GetVolumeInformation(drive)
                        drives.append({
                            "drive": drive,
                            "name": info[0] or "Removable Disk",
                            "serial": str(info[1])
                        })
                    except Exception:
                        drives.append({"drive": drive, "name": "Removable Disk", "serial": "UNKNOWN"})
        except Exception as e:
            print(f"[USB] Drive scan error: {e}")
    return drives


def start_usb_watcher():
    global _usb_thread
    load_safe_usbs()
    _stop_usb.clear()

    if sys.platform == "win32":
        try:
            import win32gui

            def _msg_loop():
                def _wnd_proc(hwnd, msg, wparam, lparam):
                    if msg == WM_DEVICECHANGE:
                        if wparam == DBT_DEVICEARRIVAL:
                            time.sleep(1.0)
                            for d in get_connected_usbs():
                                if is_usb_safe(d["serial"]):
                                    trigger_alert("usb_device", "info",
                                        f"Safe USB connected: {d['drive']} ({d['name']})", d)
                                else:
                                    trigger_alert("usb_device", "warning",
                                        f"Unauthorized USB connected: {d['drive']} ({d['name']})", d)
                                    _notify("Insider Detection — USB Alert",
                                        f"Unauthorized USB connected!\n\nDrive: {d['drive']} ({d['name']})\nNot in safe whitelist.")
                        elif wparam == DBT_DEVICEREMOVECOMPLETE:
                            trigger_alert("usb_device", "info", "USB device disconnected.")
                    return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

                wc = win32gui.WNDCLASS()
                wc.lpfnWndProc = _wnd_proc
                wc.lpszClassName = "USBWatcher"
                try:
                    atom = win32gui.RegisterClass(wc)
                    hwnd = win32gui.CreateWindow(atom, "USBWatcher", 0, 0, 0, 0, 0, 0, 0, 0, None)
                    print("[USB] Native USB watcher started.")
                    while not _stop_usb.is_set():
                        win32gui.PumpWaitingMessages()
                        time.sleep(0.5)
                except Exception as e:
                    print(f"[USB] Window creation error: {e}")

            _usb_thread = threading.Thread(target=_msg_loop, daemon=True)
            _usb_thread.start()
            return
        except ImportError:
            print("[USB] pywin32 not available, USB monitoring disabled.")
    else:
        print("[USB] Non-Windows, USB monitoring disabled.")


def stop_usb_watcher():
    _stop_usb.set()
