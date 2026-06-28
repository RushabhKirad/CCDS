def select_model(global_psi: float) -> str:
    """
    Core SIEM decision logic based on structural drift.
    """
    if global_psi > 0.2:
        return "IsolationForest"
    else:
        return "GCN"
