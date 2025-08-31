import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.preprocessing import MinMaxScaler
from keras.models import Sequential
from keras.layers import LSTM, Dense

# Page configuration
st.set_page_config(
    page_title="Network Anomaly Detector",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for styling
st.markdown("""
<style>
    .main {
        background-color: #0E1117;
    }
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        font-weight: bold;
        border-radius: 5px;
        padding: 0.5rem 1rem;
    }
    .stFileUploader>section>div>button {
        background-color: #2C3E50;
        color: white;
    }
    .stProgress>div>div>div>div {
        background-color: #4CAF50;
    }
    .stAlert {
        border-radius: 10px;
    }
    .report-box {
        background-color: #1E293B;
        border-radius: 10px;
        padding: 15px;
        margin: 10px 0;
    }
    .ip-highlight {
        color: #FF4B4B;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


def preprocess_data(df):
    try:
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        elif '@timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['@timestamp'])
        else:
            st.error("No timestamp column found in the data")
            return None
    except Exception as e:
        st.error(f"Error processing timestamp: {str(e)}")
        return None

    rename_map = {}
    if 'src_ip' in df.columns:
        rename_map['src_ip'] = 'source_ip'
    if 'domain' in df.columns:
        rename_map['domain'] = 'destination_domain'

    if rename_map:
        df = df.rename(columns=rename_map)

    required_columns = ['timestamp', 'source_ip', 'destination_domain', 'bytes_sent']
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {', '.join(missing)}")
        return None

    df = df[required_columns]
    df.dropna(inplace=True)
    df['date'] = df['timestamp'].dt.floor('h')
    return df


def create_dataset(dataset, look_back=24):
    X, y = [], []
    for i in range(len(dataset) - look_back):
        X.append(dataset[i:i+look_back])
        y.append(dataset[i+look_back])
    return np.array(X), np.array(y)


def train_lstm_on_ip(ip_df, threshold_level=1.0):
    ip_df = ip_df.set_index('date').resample('h').sum().fillna(0)
    if len(ip_df) < 25:
        return None, None, None, None, None

    scaler = MinMaxScaler()
    scaled_data = scaler.fit_transform(ip_df[['total_bytes']])

    look_back = 24
    X, y = create_dataset(scaled_data, look_back)
    if len(X) == 0:
        return None, None, None, None, None

    X = X.reshape((X.shape[0], X.shape[1], 1))

    model = Sequential()
    model.add(LSTM(50, input_shape=(look_back, 1)))
    model.add(Dense(1))
    model.compile(loss='mean_squared_error', optimizer='adam')
    model.fit(X, y, epochs=15, batch_size=8, verbose=0)

    predicted = model.predict(X)
    predicted = scaler.inverse_transform(predicted)
    actual = scaler.inverse_transform(y.reshape(-1, 1))

    residuals = np.abs(actual - predicted)
    threshold = np.mean(residuals) + threshold_level * np.std(residuals)
    anomalies = residuals > threshold
    anomaly_indices = np.where(anomalies)[0]
    anomaly_timestamps = ip_df.index[look_back:][anomaly_indices]

    return anomalies.sum(), threshold, residuals, ip_df.reset_index(), anomaly_timestamps


def main():
    st.title("🛡 Network Anomaly Detection System")
    st.markdown("""
    Detect suspicious IP addresses by analyzing proxy logs for abnormal traffic patterns 
    and connections to known malicious domains.
    """)

    with st.sidebar:
        st.header("Configuration")
        st.subheader("1. Upload Data")
        log_file = st.file_uploader("Proxy Logs (CSV)", type=['csv'])
        domain_file = st.file_uploader("Malicious Domains (TXT)", type=['txt'])

        st.subheader("2. Detection Parameters")
        threshold_level = st.slider("Anomaly Threshold", 1.0, 3.0, 1.0, 0.1)

        st.subheader("3. Run Analysis")
        run_button = st.button("Start Detection", use_container_width=True)

    if 'results' not in st.session_state:
        st.session_state.results = None
        st.session_state.summary_df = None

    if run_button and log_file and domain_file:
        with st.spinner("Processing data..."):
            try:
                df = pd.read_csv(log_file)
                processed_df = preprocess_data(df)
                if processed_df is None:
                    return

                malicious_domains = set(line.decode().strip().lower() for line in domain_file.readlines())
                processed_df['destination_domain_lower'] = processed_df['destination_domain'].str.lower()
                traffic_df = processed_df.groupby(['source_ip', 'date'])['bytes_sent'].sum().reset_index()
                traffic_df.rename(columns={'bytes_sent': 'total_bytes'}, inplace=True)
                all_ips = traffic_df['source_ip'].unique()
                suspicious_summary = []
                st.success(f"Loaded {len(processed_df)} log entries with {len(all_ips)} unique IPs")
            except Exception as e:
                st.error(f"Error loading data: {str(e)}")
                return

        progress_bar = st.progress(0)
        status_text = st.empty()
        results_container = st.container()

        for i, ip in enumerate(all_ips):
            progress = int((i + 1) / len(all_ips) * 100)
            progress_bar.progress(progress)
            status_text.text(f"Analyzing IPs: {i+1}/{len(all_ips)} | Current: {ip}")

            try:
                ip_logs = processed_df[processed_df['source_ip'] == ip]
                contacted_domains = set(ip_logs['destination_domain_lower'].dropna().unique())
                matched_malicious = contacted_domains.intersection(malicious_domains)

                if matched_malicious:
                    ip_df = traffic_df[traffic_df['source_ip'] == ip]
                    anomaly_count, threshold, residuals, full_series, anomaly_times = train_lstm_on_ip(ip_df, threshold_level)

                    relevant_logs = ip_logs[ip_logs['date'].isin(anomaly_times)]
                    overlap_domains = set(relevant_logs['destination_domain_lower'].dropna().unique())
                    domain_overlap = overlap_domains.intersection(malicious_domains)

                    if anomaly_count and domain_overlap:
                        reason = "Data spike + malicious domain"
                    else:
                        anomaly_count = 0
                        reason = "Malicious domain contact only"

                    suspicious_summary.append({
                        "IP": ip,
                        "Anomaly_Count": int(anomaly_count),
                        "First_Anomaly": anomaly_times.min().strftime("%Y-%m-%d %H:%M") if anomaly_count else "N/A",
                        "Last_Anomaly": anomaly_times.max().strftime("%Y-%m-%d %H:%M") if anomaly_count else "N/A",
                        "Matched_Domains": ', '.join(matched_malicious),
                        "Reason": reason
                    })

                    with results_container:
                        with st.expander(f"🚨 Suspicious IP: {ip}", expanded=False):
                            if anomaly_count:
                                st.markdown(f"Anomaly Period: *{anomaly_times.min()} to {anomaly_times.max()}*")
                                st.markdown(f"Total Anomalies: *{int(anomaly_count)}*")
                            st.markdown(f"Malicious Domains: *{', '.join(matched_malicious)}*")
                            if anomaly_count:
                                fig, ax = plt.subplots(figsize=(10, 4))
                                full_series['date'] = pd.to_datetime(full_series['date'])
                                ax.plot(full_series['date'], full_series['total_bytes'], label='Normal Traffic', color='blue')
                                anomaly_points = full_series[full_series['date'].isin(anomaly_times)]
                                ax.scatter(anomaly_points['date'], anomaly_points['total_bytes'], 
                                           color='red', s=50, label='Anomalies', zorder=5)
                                ax.set_title(f"Traffic Pattern for IP: {ip}")
                                ax.set_ylabel("Bytes Sent")
                                ax.legend()
                                ax.grid(True, linestyle='--', alpha=0.7)
                                st.pyplot(fig)
            except Exception as e:
                st.warning(f"Error processing IP {ip}: {str(e)}")
                continue

        if suspicious_summary:
            st.session_state.summary_df = pd.DataFrame(suspicious_summary)
            st.session_state.results = suspicious_summary
            with st.container():
                st.success("✅ Analysis Complete!")
                st.subheader("Detection Summary")
                st.dataframe(st.session_state.summary_df)
                csv = st.session_state.summary_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="Download Report (CSV)",
                    data=csv,
                    file_name="anomaly_report.csv",
                    mime="text/csv",
                    use_container_width=True
                )
        else:
            st.info("ℹ No suspicious IPs detected with current parameters")

if __name__ == "__main__":
    main()