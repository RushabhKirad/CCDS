"""
Explainability Engine for Insider Detection System.

Generates human-readable reasons for why a user was flagged as anomalous
by analyzing which behavioral features deviate most from the normal population.
"""

import numpy as np


# Human-readable templates for each feature.
# Maps feature_name -> (label, explanation_template)
# The template uses {value} and {avg} as placeholders.
FEATURE_TEMPLATES = {
    "logon_count": {
        "label": "Unusual Logon Frequency",
        "template": "{value:.0f} logons vs avg {avg:.1f}",
        "icon": "high",
    },
    "after_hours_flag": {
        "label": "After-Hours Login Activity",
        "template": "After-hours access detected",
        "icon": "high",
    },
    "unique_pc_count": {
        "label": "Multiple Workstation Access",
        "template": "{value:.0f} unique PCs vs avg {avg:.1f}",
        "icon": "medium",
    },
    "usb_connect_count": {
        "label": "Excessive USB Connections",
        "template": "{value:.0f} USB connects vs avg {avg:.1f}",
        "icon": "high",
    },
    "usb_disconnect_count": {
        "label": "Unusual USB Disconnect Activity",
        "template": "{value:.0f} USB disconnects vs avg {avg:.1f}",
        "icon": "medium",
    },
    "usb_first_time_flag": {
        "label": "First-Time USB Device Detected",
        "template": "Unknown USB device used for the first time",
        "icon": "high",
    },
    "files_copied": {
        "label": "High Volume File Copies",
        "template": "{value:.0f} files copied vs avg {avg:.1f}",
        "icon": "high",
    },
    "exe_copied_flag": {
        "label": "Executable File Copied",
        "template": "Executable (.exe) file was copied",
        "icon": "high",
    },
    "emails_sent": {
        "label": "Abnormal Email Volume",
        "template": "{value:.0f} emails sent vs avg {avg:.1f}",
        "icon": "medium",
    },
    "external_email_ratio": {
        "label": "High External Email Ratio",
        "template": "{value:.1%} external emails vs avg {avg:.1%}",
        "icon": "medium",
    },
    "http_visit_count": {
        "label": "Excessive Web Browsing",
        "template": "{value:.0f} HTTP visits vs avg {avg:.1f}",
        "icon": "low",
    },
    "job_site_visits": {
        "label": "Job Hunting Activity Detected",
        "template": "{value:.0f} job site visits vs avg {avg:.1f}",
        "icon": "medium",
    },
    "suspicious_url_visits": {
        "label": "Suspicious URL Access",
        "template": "{value:.0f} suspicious URL visits vs avg {avg:.1f}",
        "icon": "high",
    },
}

# Z-score threshold: features with z-score above this are considered anomalous
ZSCORE_THRESHOLD = 1.5

# Maximum number of reasons to return per user
MAX_REASONS = 3


def _compute_population_stats(df, features):
    """Compute mean and std for each feature across the full population."""
    stats = {}
    for f in features:
        vals = df[f].values.astype(float)
        stats[f] = {
            "mean": float(np.mean(vals)),
            "std": float(np.std(vals)) if np.std(vals) > 0 else 1.0,
        }
    return stats


def _get_user_peak_row(df_eval, user_id):
    """
    Get the row for a user that had the highest anomaly score.
    This is the most 'suspicious' observation for that user.
    """
    user_rows = df_eval[df_eval["user"] == user_id]
    if user_rows.empty:
        return None
    # Return the row with the highest score
    return user_rows.loc[user_rows["score"].idxmax()]


def generate_explanations(df_eval, top_users, features):
    """
    Generate human-readable explanations for each flagged user.

    Args:
        df_eval: DataFrame with all user rows and their anomaly scores (has 'score' column)
        top_users: List of dicts with 'user' and 'score' keys (the top N flagged users)
        features: List of feature column names

    Returns:
        List of dicts (one per user in top_users order), each containing:
            - reasons: List[str]  — human-readable explanation strings
            - top_features: Dict[str, float]  — raw feature values for the most deviant features
            - feature_deviations: Dict[str, float]  — z-score values for those features
    """
    pop_stats = _compute_population_stats(df_eval, features)

    results = []
    for user_entry in top_users:
        user_id = user_entry["user"]
        peak_row = _get_user_peak_row(df_eval, user_id)

        if peak_row is None:
            results.append({
                "reasons": ["Insufficient data to explain this prediction."],
                "top_features": {},
                "feature_deviations": {},
            })
            continue

        # Compute z-score for each feature for this user's peak row
        feature_scores = []
        for f in features:
            raw_val = float(peak_row[f])
            mean = pop_stats[f]["mean"]
            std = pop_stats[f]["std"]
            z = (raw_val - mean) / std
            feature_scores.append((f, z, raw_val, mean))

        # Sort by z-score descending (most anomalous first)
        feature_scores.sort(key=lambda x: x[1], reverse=True)

        reasons = []
        top_features = {}
        feature_deviations = {}

        for f_name, z_score, raw_val, avg_val in feature_scores:
            if z_score < ZSCORE_THRESHOLD and len(reasons) > 0:
                # Stop if below threshold and we have at least one reason
                break
            if len(reasons) >= MAX_REASONS:
                break

            tmpl = FEATURE_TEMPLATES.get(f_name)
            if tmpl is None:
                continue

            # Build the reason string
            label = tmpl["label"]
            try:
                detail = tmpl["template"].format(value=raw_val, avg=avg_val)
            except (KeyError, ValueError):
                detail = tmpl["template"]

            reason_str = f"{label}: {detail}"
            reasons.append(reason_str)
            top_features[f_name] = round(raw_val, 4)
            feature_deviations[f_name] = round(z_score, 2)

        # If no features exceeded threshold, provide a generic explanation
        if not reasons:
            # Take the top feature regardless of threshold
            if feature_scores:
                f_name, z_score, raw_val, avg_val = feature_scores[0]
                tmpl = FEATURE_TEMPLATES.get(f_name, {"label": f_name, "template": ""})
                try:
                    detail = tmpl["template"].format(value=raw_val, avg=avg_val)
                except (KeyError, ValueError):
                    detail = tmpl.get("template", "")
                reasons.append(f"{tmpl['label']}: {detail}")
                top_features[f_name] = round(raw_val, 4)
                feature_deviations[f_name] = round(z_score, 2)
            else:
                reasons.append("Anomalous behavioral pattern detected across multiple features.")

        results.append({
            "reasons": reasons,
            "top_features": top_features,
            "feature_deviations": feature_deviations,
        })

    return results
