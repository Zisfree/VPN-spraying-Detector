import numpy as np
import pandas as pd

def haversine(lat1, lon1, lat2, lon2):
    """
    Calculates the great-circle distance between two points on Earth in kilometers.
    """
    R = 6371.0  # Earth's radius in kilometers
    
    p1, p2 = np.radians(lat1), np.radians(lat2)
    dp = np.radians(lat2 - lat1)
    dl = np.radians(lon2 - lon1)
    
    a = np.sin(dp / 2.0)**2 + np.cos(p1) * np.cos(p2) * np.sin(dl / 2.0)**2
    c = 2 * np.arctan2(np.sqrt(a), np.sqrt(1 - a))
    
    return R * c

def detect_impossible_travel(df):
    """
    Analyzes authentication logs for impossible travel speeds between consecutive user logins.
    """
    alerts = []
    
    # Ensure correct data types and chronological order
    data = df.copy()
    data['timestamp'] = pd.to_datetime(data['timestamp'])
    data = data.sort_values(by=['user', 'timestamp']).reset_index(drop=True)
    
    # Group by user and shift values to compare consecutive logins
    data['prev_time'] = data.groupby('user')['timestamp'].shift(1)
    data['prev_lat'] = data.groupby('user')['lat'].shift(1)
    data['prev_lon'] = data.groupby('user')['lon'].shift(1)
    data['prev_city'] = data.groupby('user')['city'].shift(1)
    
    # Filter for rows where a previous login exists
    valid_pairs = data.dropna(subset=['prev_time']).copy()
    
    if valid_pairs.empty:
        return pd.DataFrame(alerts)
    
    # Calculate time difference in hours
    time_diff_hours = (valid_pairs['timestamp'] - valid_pairs['prev_time']).dt.total_seconds() / 3600.0
    
    # Calculate distance in kilometers
    distances = haversine(
        valid_pairs['prev_lat'], valid_pairs['prev_lon'],
        valid_pairs['lat'], valid_pairs['lon']
    )
    
    # Calculate speed (km/h) - avoid division by zero
    speeds = np.where(time_diff_hours > 0, distances / time_diff_hours, 0)
    
    valid_pairs['distance_km'] = distances
    valid_pairs['speed_kmh'] = speeds
    
    # Threshold: Speed > 850 km/h AND distance > 50 km
    violations = valid_pairs[(valid_pairs['speed_kmh'] > 850) & (valid_pairs['distance_km'] > 50)]
    
    for _, row in violations.iterrows():
        severity = "CRITICAL" if row['action'] == "SUCCESS" else "HIGH"
        alerts.append({
            "timestamp": row['timestamp'],
            "entity": row['user'],
            "attack_type": "Impossible Travel",
            "mitre_technique": "T1078",
            "severity": severity,
            "details": f"Moved {row['distance_km']:.0f} km ({row['prev_city']} ➔ {row['city']}) at {row['speed_kmh']:.0f} km/h"
        })
        
    return pd.DataFrame(alerts)

# Quick local test
if __name__ == "__main__":
    try:
        sample_df = pd.read_csv("auth_logs.csv")
        results = detect_impossible_travel(sample_df)
        print("--- Impossible Travel Detection Results ---")
        print(results)
    except Exception as e:
        print("Run create_data.py first to generate auth_logs.csv!")