import pandas as pd

def detect_rule_attacks(df):
    default_cols = ["timestamp", "entity", "attack_type", "mitre_technique", "severity", "details"]
    if df.empty:
        return pd.DataFrame(columns=default_cols)
    
    # Auto-detect user column name
    user_col = 'user' if 'user' in df.columns else ('username' if 'username' in df.columns else None)
    if not user_col or 'src_ip' not in df.columns:
        return pd.DataFrame(columns=default_cols)

    alerts = []
    
    # 1. Password Spray Detection (MITRE T1110.003)
    spray_grouped = df.groupby('src_ip').agg(
        unique_users=(user_col, 'nunique'),
        failures=('action', lambda x: (x == 'FAILURE').sum()),
        successes=('action', lambda x: (x == 'SUCCESS').sum()),
        last_time=('timestamp', 'max')
    ).reset_index()
    
    sprays = spray_grouped[spray_grouped['unique_users'] >= 5]
    for _, row in sprays.iterrows():
        severity = "CRITICAL" if row['successes'] > 0 else "HIGH"
        alerts.append({
            "timestamp": row['last_time'],
            "entity": row['src_ip'],
            "attack_type": "Password Spraying",
            "mitre_technique": "T1110.003",
            "severity": severity,
            "details": f"Targeted {row['unique_users']} users ({row['failures']} fails, {row['successes']} success)"
        })
        
    # 2. Brute Force Detection (MITRE T1110.001)
    bf_grouped = df.groupby(['src_ip', user_col]).agg(
        failures=('action', lambda x: (x == 'FAILURE').sum()),
        last_time=('timestamp', 'max')
    ).reset_index()
    
    brute_forces = bf_grouped[bf_grouped['failures'] >= 8]
    for _, row in brute_forces.iterrows():
        alerts.append({
            "timestamp": row['last_time'],
            "entity": row[user_col],
            "attack_type": "Brute Force",
            "mitre_technique": "T1110.001",
            "severity": "MEDIUM",
            "details": f"{row['failures']} login failures from IP {row['src_ip']}"
        })
        
    return pd.DataFrame(alerts) if alerts else pd.DataFrame(columns=default_cols)
