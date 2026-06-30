from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import os
import sys

# Always resolve paths relative to this file — works from any working directory
FILE_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(FILE_DIR)

# Insert project root so 'app', 'pipeline', etc. resolve correctly
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
from app.routes import router

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

# Start and Stop Realtime watchers using lifespan events
import asyncio
from app import routes as app_routes
from pipeline.watchers import start_usb_watcher, start_file_watcher, stop_usb_watcher, stop_file_watcher
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    app_routes.main_loop = asyncio.get_running_loop()
    start_usb_watcher()
    start_file_watcher()
    yield
    stop_usb_watcher()
    stop_file_watcher()

app.router.lifespan_context = lifespan

# Serve frontend files under /static and expose index.html at root
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/")
async def root():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

if __name__ == "__main__":
    import uvicorn

    def start_server(host: str, port: int):
        uvicorn.run(
            "app.main:app",
            host=host,
            port=port,
            reload=True,
            reload_dirs=[BASE_DIR]
        )

    default_port = int(os.getenv("PORT", "5050"))
    try:
        start_server("127.0.0.1", default_port)
    except OSError as exc:
        if exc.errno == 10048 or "address already in use" in str(exc).lower():
            fallback_port = default_port + 1
            print(f"Port {default_port} is already in use. Falling back to port {fallback_port}.")
            start_server("127.0.0.1", fallback_port)
        else:
            raise

