import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

num_logs = 1000

# Geo coordinates lookup table
geo_coords = {
    "Delhi, India": {"lat": 28.6139, "lon": 77.2090, "ip_prefix": "103.21.124."},
    "Mumbai, India": {"lat": 19.0760, "lon": 72.8777, "ip_prefix": "103.22.140."},
    "London, UK": {"lat": 51.5074, "lon": -0.1278, "ip_prefix": "185.220.101."},
    "New York, USA": {"lat": 40.7128, "lon": -74.0060, "ip_prefix": "198.51.100."}
}

cities = list(geo_coords.keys())
records = []
base_time = pd.Timestamp("2026-09-01 08:00:00")

# 1. Normal Baseline Traffic
for i in range(num_logs - 50):
    city = random.choice(cities)
    coords = geo_coords[city]
    t = base_time + timedelta(seconds=i * 12)
    records.append({
        "timestamp": t,
        "user": f"user_{random.randint(1000, 1080)}",
        "src_ip": coords["ip_prefix"] + str(random.randint(2, 250)),
        "city": city,
        "lat": coords["lat"],
        "lon": coords["lon"],
        "action": np.random.choice(["SUCCESS", "FAILURE"], p=[0.90, 0.10]),
        "auth_method": np.random.choice(["Password", "MFA"], p=[0.7, 0.3]),
        "vpn_server": np.random.choice(["VPN-01", "VPN-02", "VPN-03"]),
        "is_attack": 0
    })

# 2. Planted Attack: Brute Force (T1110.001)
bf_time = base_time + timedelta(minutes=45)
for i in range(15):
    records.append({
        "timestamp": bf_time + timedelta(seconds=i * 6),
        "user": "user_1099",
        "src_ip": "198.51.100.77",
        "city": "New York, USA",
        "lat": 40.7128,
        "lon": -74.0060,
        "action": "FAILURE",
        "auth_method": "Password",
        "vpn_server": "VPN-01",
        "is_attack": 1
    })

# 3. Planted Attack: Password Spray (T1110.003)
spray_time = base_time + timedelta(minutes=90)
for i in range(15):
    records.append({
        "timestamp": spray_time + timedelta(seconds=i * 5),
        "user": f"user_{1010 + i}",
        "src_ip": "185.220.101.44",
        "city": "London, UK",
        "lat": 51.5074,
        "lon": -0.1278,
        "action": "SUCCESS" if i == 14 else "FAILURE",
        "auth_method": "Password",
        "vpn_server": "VPN-02",
        "is_attack": 1
    })

# 4. Planted Attack: Impossible Travel (Delhi to London in 15 mins)
travel_time = base_time + timedelta(minutes=130)
records.append({
    "timestamp": travel_time,
    "user": "user_1050",
    "src_ip": "103.21.124.15",
    "city": "Delhi, India",
    "lat": 28.6139,
    "lon": 77.2090,
    "action": "SUCCESS",
    "auth_method": "MFA",
    "vpn_server": "VPN-01",
    "is_attack": 0
})
records.append({
    "timestamp": travel_time + timedelta(minutes=15),
    "user": "user_1050",
    "src_ip": "185.220.101.99",
    "city": "London, UK",
    "lat": 51.5074,
    "lon": -0.1278,
    "action": "SUCCESS",
    "auth_method": "Password",
    "vpn_server": "VPN-03",
    "is_attack": 1
})

df = pd.DataFrame(records)
df = df.sort_values(by="timestamp").reset_index(drop=True)
df.to_csv("auth_logs.csv", index=False)
print("Updated auth_logs.csv generated successfully!")