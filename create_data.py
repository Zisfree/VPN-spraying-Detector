import pandas as pd
import numpy as np

num_logs = 1000

data = {
    "user_id": np.random.randint(1000, 1100, num_logs),      #Every key is converted to coulumn in .csv

    "source_ip": [
        f"192.168.{np.random.randint(0, 255)}.{np.random.randint(1, 255)}"
        for _ in range(num_logs)
    ],

    "login_status": np.random.choice(
        ["SUCCESS", "FAILED"],
        num_logs,
        p=[0.85, 0.15]            #This is just an assumption to make the dat more real.
    ),

    "authentication_method": np.random.choice(
        ["Password", "MFA"],    #MFA = Multi Factor Authentication
        num_logs
    ),

    "vpn_server": np.random.choice(
        ["VPN-01", "VPN-02", "VPN-03"],
        num_logs
    )
}

df = pd.DataFrame(data)
df.to_csv("auth_logs.csv", index=False)
print("Created auth_logs.csv successfully!")
