from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from app.schemas import DetectionRequest, DetectionResponse, DriftReportResponse, AdminLoginRequest, AdminLoginResponse, RestrictionPathModel, SafeUSBModel
from pipeline.feature_loader import load_dataset, FEATURES
from pipeline.drift import compute_dataset_drift
from pipeline.decision_engine import select_model
from pipeline.explain import generate_explanations
from models_demo.gcn_inference import run_gcn
from models_demo.iso_forest import run_iso_forest
from pipeline.watchers import (
    register_alert_callback, 
    get_restricted_paths, 
    add_restricted_path, 
    remove_restricted_path,
    get_safe_usbs,
    add_safe_usb,
    remove_safe_usb,
    get_connected_usbs
)
import time
import asyncio
from collections import deque
from typing import List
import os
from concurrent.futures import ThreadPoolExecutor

_executor = ThreadPoolExecutor(max_workers=2)

router = APIRouter()

# Global states
active_websockets: List[WebSocket] = []
audit_logs: deque = deque(maxlen=500)  # O(1) append, auto-drops oldest when full
main_loop = None

async def broadcast_alert(alert_event):
    """Sends the alert event as JSON to all connected Websocket clients."""
    for ws in list(active_websockets):
        try:
            await ws.send_json(alert_event)
        except Exception:
            if ws in active_websockets:
                active_websockets.remove(ws)

def on_alert_received(alert_event):
    """Callback function triggered by background watchers when a security event happens."""
    audit_logs.appendleft(alert_event)  # O(1), deque auto-caps at 500
    
    # Schedule the broadcast on the main event loop thread-safely
    if main_loop and active_websockets:
        asyncio.run_coroutine_threadsafe(broadcast_alert(alert_event), main_loop)

# Register the callback in the watchers engine
register_alert_callback(on_alert_received)

@router.post("/run-detection", response_model=DetectionResponse)
async def run_detection(request: DetectionRequest):
    ds_name = request.dataset
    if ds_name not in ["r42_train", "r42_test", "r62"]:
        raise HTTPException(status_code=400, detail="Invalid dataset.")

    def _run():
        df, x_scaled = load_dataset(ds_name)
        drift_results = compute_dataset_drift(df)
        global_psi = drift_results["global_psi"]
        model_name = select_model(global_psi)
        if model_name == "IsolationForest":
            top_users, total_users, df_eval = run_iso_forest(df, x_scaled)
        else:
            top_users, total_users, df_eval = run_gcn(df, x_scaled)
        explanations = generate_explanations(df_eval, top_users, FEATURES)
        enriched_users = [
            {**u, "reasons": e["reasons"], "top_features": e["top_features"], "feature_deviations": e["feature_deviations"]}
            for u, e in zip(top_users, explanations)
        ]
        return DetectionResponse(
            drift_score=global_psi,
            model_used=model_name,
            top_users=enriched_users,
            total_users=total_users,
            feature_names=FEATURES
        )

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_executor, _run)

@router.get("/drift-report", response_model=DriftReportResponse)
def drift_report(dataset: str = "r62"):
    if dataset not in ["r42", "r62"]:
        raise HTTPException(status_code=400, detail="Invalid dataset.")
    df, _ = load_dataset(dataset)
    results = compute_dataset_drift(df)
    return DriftReportResponse(
        global_psi=results["global_psi"],
        psi_per_feature=results["psi_per_feature"],
        top_drift_features=results["top_drifting_features"]
    )

# WebSocket connection endpoint
@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await websocket.accept()
    active_websockets.append(websocket)
    try:
        # Keep alive: sleep 20s then send ping — client never sends data back
        while True:
            await asyncio.sleep(20.0)
            try:
                await websocket.send_json({"type": "ping", "timestamp": time.strftime("%H:%M:%S")})
            except Exception:
                break
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    except Exception:
        pass
    finally:
        if websocket in active_websockets:
            active_websockets.remove(websocket)

# Admin Panel authentication route
@router.post("/admin/login", response_model=AdminLoginResponse)
def admin_login(request: AdminLoginRequest):
    if request.username == "admin" and request.password == "admin123":
        return AdminLoginResponse(success=True, token="admin-token-key-123", message="Login successful!")
    else:
        return AdminLoginResponse(success=False, message="Invalid username or password.")

# Restricted path CRUD routes
@router.get("/admin/restrictions")
def get_restrictions():
    return {"restricted_paths": get_restricted_paths()}

@router.post("/admin/restrictions")
def add_restriction(item: RestrictionPathModel):
    add_restricted_path(item.path)
    return {"status": "success", "message": f"Path '{item.path}' added to restrictions."}

@router.delete("/admin/restrictions")
def remove_restriction(path: str):
    remove_restricted_path(path)
    return {"status": "success", "message": f"Path '{path}' removed from restrictions."}

# Realtime alert logs route
@router.get("/admin/logs")
def get_audit_logs():
    return {"logs": list(audit_logs)}

# Lightweight log count endpoint for efficient frontend polling
@router.get("/admin/log-count")
def get_log_count():
    """Returns just the log count so the frontend can detect new entries cheaply."""
    return {"count": len(audit_logs)}


@router.get("/admin/browse")
def browse_dir(path: str = "C:\\"):
    # Normalize path
    norm_path = os.path.abspath(path)
    
    # Ensure it exists and is directory
    if not os.path.exists(norm_path):
        # Default fallback to C:\ if folder does not exist
        norm_path = "C:\\"
        
    try:
        entries = os.listdir(norm_path)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission Denied to access this directory.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading directory: {str(e)}")
        
    folders = []
    files = []
    
    for entry in entries:
        if entry.startswith('$') or entry.lower() in ('system volume information', 'msocache', 'recycler', 'recycle.bin'):
            continue
        try:
            full_path = os.path.join(norm_path, entry)
            if os.path.isdir(full_path):
                folders.append(entry)
            else:
                files.append(entry)
        except Exception:
            pass
            
    folders.sort(key=str.lower)
    files.sort(key=str.lower)
    
    parent = os.path.dirname(norm_path)
    if os.path.normpath(parent) == os.path.normpath(norm_path):
        parent = None
        
    return {
        "current_path": norm_path,
        "parent_path": parent,
        "folders": folders,
        "files": files
    }


@router.get("/admin/safe-usbs")
def get_safe_usbs_route():
    return {"safe_usbs": get_safe_usbs()}


@router.post("/admin/safe-usbs")
def add_safe_usb_route(item: SafeUSBModel):
    add_safe_usb(item.serial, item.name)
    return {"status": "success", "message": f"USB Device '{item.name}' marked as safe."}


@router.delete("/admin/safe-usbs")
def remove_safe_usb_route(serial: str):
    remove_safe_usb(serial)
    return {"status": "success", "message": f"USB Device '{serial}' removed from safe list."}


@router.get("/admin/detected-usbs")
def get_detected_usbs_route():
    return {"detected_usbs": get_connected_usbs()}


