from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os

# Get current directory
current_dir = os.path.dirname(os.path.abspath(__file__))

app = FastAPI(title="Cyber Defense Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files with absolute path
static_dir = os.path.join(current_dir, "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def dashboard():
    html_path = os.path.join(current_dir, "index.html")
    return FileResponse(html_path)

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "dashboard"}

if __name__ == "__main__":
    print(f"Starting dashboard server...")
    print(f"Dashboard URL: http://127.0.0.1:3000")
    uvicorn.run(app, host="127.0.0.1", port=3000)