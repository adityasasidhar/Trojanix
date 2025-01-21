import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score
import numpy as np

# Load the pre-trained model and scaler
knn_model = joblib.load('../../models/network_knn_model.joblib')
scaler = joblib.load('../../app scalers/network_scaler_model.joblib')

# Load the new dataset
data = pd.read_csv('../../datasets/evaluation_dataset/evaluation_network_trails')

# List of columns to encode (non-numeric)
categorical_columns = ['#Src_IP', 'DestIP', 'Protocol', 'service', 'hostname', 'sni', 'url', 'path', 'filename']

# Replace any empty lists or invalid values with NaN
data = data.replace(r'^\s*$', np.nan, regex=True)  # Replace empty strings with NaN
data = data.apply(pd.to_numeric, errors='coerce')  # Convert non-numeric values to NaN

# Apply LabelEncoder to non-numeric columns (same as training)
encoder = LabelEncoder()
for column in categorical_columns:
    data[column] = encoder.fit_transform(data[column].astype(str))  # Convert to string before encoding

# Selecting features (same columns as during training)
X_new = data[[
'#Src_IP', 'DestIP', 'Dport', 'Protocol', 'service', 'sportcounts', 'number_of_flows',
    'average_of_duration', 'standard_deviation_duration', 'total_size_of_flows_orig', 'total_size_of_flows_resp',
    'inbound_pckts', 'outbound_pckts', 'ssl_ratio', 'tls_version_ratio', 'is_valid_certificate_during_capture',
    'amount_diff_certificates', 'number_of_domains_in_certificate', 'SNI_ssl_ratio', 'SNI_equal_DstIP',
    'url', 'url_query_names', 'url_query_values', 'hostname', 'sni', 'number_of_downloaded_bytes',
    'number_of_uploaded_bytes', 'number_of_url_flows', 'hostname_digitratio', 'hostname_alpharatio',
    'hostname_specialcharratio', 'sni_digitratio', 'sni_alpharatio', 'sni_specialcharratio', 'dns_noerror',
    'dns_nxdomain'
]]

X_new = X_new.fillna(0)
X_new_scaled = scaler.transform(X_new)
y_true = data['binarylabel']
y_pred = knn_model.predict(X_new_scaled)

accuracy = accuracy_score(y_true, y_pred)

print(f'Model accuracy on the new dataset: {accuracy * 100:.2f}%')
