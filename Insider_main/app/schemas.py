from pydantic import BaseModel
from typing import List, Dict, Optional

class DetectionRequest(BaseModel):
    dataset: str # "r42_train" or "r42_test" or "r62"

class TopUser(BaseModel):
    user: str
    score: float
    reasons: List[str] = []
    top_features: Dict[str, float] = {}
    feature_deviations: Dict[str, float] = {}

class DetectionResponse(BaseModel):
    drift_score: float
    model_used: str
    top_users: List[TopUser]
    total_users: int
    feature_names: List[str] = []

class DriftReportResponse(BaseModel):
    global_psi: float
    psi_per_feature: Dict[str, float]
    top_drift_features: List[str]

class AdminLoginRequest(BaseModel):
    username: str
    password: str

class AdminLoginResponse(BaseModel):
    success: bool
    token: Optional[str] = None
    message: str

class RestrictionPathModel(BaseModel):
    path: str

class RealtimeAlertModel(BaseModel):
    timestamp: str
    type: str
    severity: str
    message: str
    details: Optional[Dict] = None


class SafeUSBModel(BaseModel):
    serial: str
    name: str


