import pandas as pd
import numpy as np

def detect_rule_attacks(csv_file="auth_logs.csv"):
    alerts = []
    
    # 1. Ingest telemetry
    df = pd.read_csv(csv_file)
    
    # Standardize all column names to lowercase and strip spaces
    # This prevents any KeyError regardless of how Akshan formatted headers
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]

    # Resolve column aliases dynamically
    ts_col = 'timestamp' if 'timestamp' in df.columns else df.columns[0]
    user_col = 'user_id' if 'user_id' in df.columns else ('user' if 'user' in df.columns else df.columns[1])
    ip_col = 'source_ip' if 'source_ip' in df.columns else ('src_ip' if 'src_ip' in df.columns else df.columns[2])
    
    # Identify action / status column
    status_col = 'login_status' if 'login_status' in df.columns else ('action' if 'action' in df.columns else 'status')

    df[ts_col] = pd.to_datetime(df[ts_col])
    
    # Normalize failure/success values
    df['is_failed'] = df[status_col].astype(str).str.upper().isin(['FAILED', 'FAILURE'])
    df['is_success'] = df[status_col].astype(str).str.upper() == 'SUCCESS'

    # ---------------------------------------------------------
    # Detection Layer 1: Password Spraying (MITRE T1110.003)
    # ---------------------------------------------------------
    ip_summary = df.groupby(ip_col).agg(
        unique_targets=(user_col, 'nunique'),
        total_failures=('is_failed', 'sum'),
        total_success=('is_success', 'sum'),
        last_event=(ts_col, 'max')
    ).reset_index()

    sprayers = ip_summary[(ip_summary['unique_targets'] >= 4) & (ip_summary['total_failures'] >= 3)]
    for _, row in sprayers.iterrows():
        severity = "CRITICAL" if row['total_success'] > 0 else "HIGH"
        alerts.append({
            "timestamp": row['last_event'],
            "entity": row[ip_col],
            "attack_type": "Password Spraying",
            "mitre_technique": "T1110.003",
            "severity": severity,
            "details": f"Targeted {row['unique_targets']} unique accounts ({row['total_failures']} fails, {row['total_success']} success)"
        })

    # ---------------------------------------------------------
    # Detection Layer 2: Targeted Brute Force (MITRE T1110.001)
    # ---------------------------------------------------------
    user_summary = df.groupby([ip_col, user_col]).agg(
        failed_logins=('is_failed', 'sum'),
        last_event=(ts_col, 'max')
    ).reset_index()

    brute_targets = user_summary[user_summary['failed_logins'] >= 4]
    for _, row in brute_targets.iterrows():
        alerts.append({
            "timestamp": row['last_event'],
            "entity": f"User {row[user_col]} from {row[ip_col]}",
            "attack_type": "Targeted Brute Force",
            "mitre_technique": "T1110.001",
            "severity": "MEDIUM",
            "details": f"{row['failed_logins']} failed authentication attempts"
        })

    # ---------------------------------------------------------
    # Detection Layer 3: UEBA Anomaly Detection (Statistical Z-Score)
    # ---------------------------------------------------------
    mean_fails = ip_summary['total_failures'].mean()
    std_fails = ip_summary['total_failures'].std()
    
    if std_fails > 0:
        ip_summary['z_score'] = (ip_summary['total_failures'] - mean_fails) / std_fails
        ml_anomalies = ip_summary[ip_summary['z_score'] >= 2.0]
        
        for _, row in ml_anomalies.iterrows():
            already_flagged = any(a['entity'] == row[ip_col] for a in alerts)
            if not already_flagged and row['total_failures'] > 1:
                alerts.append({
                    "timestamp": row['last_event'],
                    "entity": row[ip_col],
                    "attack_type": "UEBA Behavioral Anomaly",
                    "mitre_technique": "T1110 - Statistical Outlier",
                    "severity": "MEDIUM",
                    "details": f"Anomaly Flag: Failure rate deviates from baseline (Z-Score: {row['z_score']:.2f})"
                })

    return pd.DataFrame(alerts)

# Self-testing execution block
if __name__ == "__main__":
    alerts_df = detect_rule_attacks("auth_logs.csv")
    print("\n================ THREAT DETECTION REPORT ================")
    print(f"Total Incidents Raised: {len(alerts_df)}\n")
    if not alerts_df.empty:
        print(alerts_df[['timestamp', 'attack_type', 'entity', 'severity']].to_string(index=False))
    else:
        print("No threats detected. Baseline within normal parameters.")
