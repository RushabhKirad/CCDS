from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os
import sys

# Insert project root to sys.path to enable 'app' package resolving when running main.py directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.routes import router

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

app = FastAPI(title="Insider Detection System")

# CORS config 
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routes
app.include_router(router)

# Start and Stop Realtime watchers on app events
import asyncio
from app import routes as app_routes
from pipeline.watchers import start_usb_watcher, start_file_watcher, stop_usb_watcher, stop_file_watcher

@app.on_event("startup")
async def startup_event():
    # Save reference to main loop for websocket async execution in threads
    app_routes.main_loop = asyncio.get_running_loop()
    # Start watchers in threads
    start_usb_watcher()
    start_file_watcher()


@app.on_event("shutdown")
async def shutdown_event():
    # Stop thread loops
    stop_usb_watcher()
    stop_file_watcher()

# Mount frontend to serve vanilla HTML/JS directly
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=5050, reload=True)

