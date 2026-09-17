import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Direct imports from teammates' local files
from rules import detect_rule_attacks
from travel import detect_impossible_travel

# Page configuration
st.set_page_config(page_title="VPN Threat SIEM", layout="wide")

# Dashboard Header
st.title("🛡️ Enterprise VPN Threat Detection Dashboard")
st.caption("Automated Anomaly Detection, MITRE ATT&CK Correlator & Travel Velocity Guard")

# 1. Load Data
df = pd.read_csv("auth_logs.csv")

# 2. Run Engine Detections
rule_alerts = detect_rule_attacks(df)
travel_alerts = detect_impossible_travel(df)

# Combine alerts into a single DataFrame
alerts = pd.concat([rule_alerts, travel_alerts], ignore_index=True)

# 3. Top Metrics Row
col1, col2, col3, col4 = st.columns(4)

total_logs = len(df)
total_incidents = len(alerts)
critical_alerts = len(alerts[alerts['severity'] == 'CRITICAL']) if not alerts.empty else 0
unique_ips = df['src_ip'].nunique()

col1.metric("Total Logs Processed", f"{total_logs:,}")
col2.metric("Flagged Incidents", f"{total_incidents}")
col3.metric("Critical Threats", f"{critical_alerts}")
col4.metric("Unique IPs Monitored", f"{unique_ips}")

st.markdown("---")

# 4. Activity Timeline Chart
st.subheader("📈 Authentication & Incident Timeline")

df['timestamp'] = pd.to_datetime(df['timestamp'])
timeline = df.groupby([pd.Grouper(key='timestamp', freq='1h'), 'action']).size().unstack(fill_value=0).reset_index()

fig = go.Figure()

if 'SUCCESS' in timeline.columns:
    fig.add_trace(go.Scatter(x=timeline['timestamp'], y=timeline['SUCCESS'], name='Successful Logins', line=dict(color='#2ECC71', width=2)))

if 'FAILURE' in timeline.columns:
    fig.add_trace(go.Scatter(x=timeline['timestamp'], y=timeline['FAILURE'], name='Failed Attempts', line=dict(color='#E74C3C', width=2)))

# Clean color mapping dictionary without special character artifacts
color_map = {"MEDIUM": "#FFB703", "HIGH": "#FB8500", "CRITICAL": "#E63946"}

if not alerts.empty:
    alerts['timestamp'] = pd.to_datetime(alerts['timestamp'])
    for _, alert in alerts.iterrows():
        fig.add_trace(go.Scatter(
            x=[alert['timestamp']],
            y=[15],
            mode='markers+text',
            marker=dict(symbol='triangle-up', size=14, color=color_map.get(alert['severity'], '#FF0000')),
            name=alert['attack_type'],
            text=[f"🚨 {alert['attack_type']}"],
            textposition="top center",
            hovertext=f"Entity: {alert['entity']}<br>MITRE: {alert['mitre_technique']}<br>Details: {alert['details']}"
        ))

fig.update_layout(template="plotly_dark", height=420, margin=dict(l=20, r=20, t=30, b=20))
st.plotly_chart(fig, use_container_width=True)

# 5. Incident Queue Table
st.subheader("🚨 Threat Incident Triage Queue")

if not alerts.empty:
    st.dataframe(alerts[['timestamp', 'severity', 'attack_type', 'mitre_technique', 'entity', 'details']], use_container_width=True)
else:
    st.success("No active threats detected in the current authentication logs.")