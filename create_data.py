import pandas as pd
import numpy as np

num_logs = 1000

data = {
    "user_id": np.random.randint(1000, 1100, num_logs),      #Every key is converted to coulumn in .csv

    "Source IP": [
        f"192.168.{np.random.randint(0, 255)}.{np.random.randint(1, 255)}"
        for _ in range(num_logs)
    ],
    "Timestamp": pd.date_range(
         start="2026-09-01",
         periods=num_logs,
         freq="5min"
        ),

    "Geolocation": np.random.choice(
        ["Delhi, India", "Mumbai, India", "London, UK", "New York, USA"],
        num_logs
        ),

    "Login Status": np.random.choice(
        ["SUCCESS", "FAILED"],
        num_logs,
        p=[0.85, 0.15]            #This is just an assumption to make the dat more real.
    ),

    "Authentication Method": np.random.choice(
        ["Password", "MFA"],    #MFA = Multi Factor Authentication
        num_logs
    ),

    "VPN Server": np.random.choice(
        ["VPN-01", "VPN-02", "VPN-03"],
        num_logs
    )
}

df = pd.DataFrame(data)
df.to_csv("auth_logs.csv", index=False)
print("Created auth_logs.csv successfully!")
