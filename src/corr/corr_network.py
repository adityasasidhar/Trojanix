import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
import numpy as np

# Load the data
data = pd.read_csv('../../datasets/train_dataset/training_network_trails')

# Define categorical columns
categorical_columns = ['#Src_IP', 'DestIP', 'Protocol', 'service', 'hostname', 'sni', 'url', 'path', 'filename']
numerical_columns = [
    'sportcounts', 'number_of_flows', 'average_of_duration', 'standard_deviation_duration',
    'total_size_of_flows_orig', 'total_size_of_flows_resp', 'inbound_pckts', 'outbound_pckts',
    'ssl_ratio', 'tls_version_ratio', 'is_valid_certificate_during_capture', 'amount_diff_certificates',
    'number_of_domains_in_certificate', 'SNI_ssl_ratio', 'SNI_equal_DstIP', 'number_of_downloaded_bytes',
    'number_of_uploaded_bytes', 'number_of_url_flows', 'hostname_digitratio', 'hostname_alpharatio',
    'hostname_specialcharratio', 'sni_digitratio', 'sni_alpharatio', 'sni_specialcharratio',
    'dns_noerror', 'dns_nxdomain'
]

# Preprocess the data: Replace empty strings with NaN and convert to numeric
data = data.replace(r'^\s*$', np.nan, regex=True)
data = data.apply(pd.to_numeric, errors='coerce')

# Encode categorical columns
encoder = LabelEncoder()
for column in categorical_columns:
    data[column] = encoder.fit_transform(data[column].astype(str))

# Separate features and target
X = data[numerical_columns + categorical_columns]
y = data['binarylabel']

# Scale the features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Create a DataFrame with the scaled data
scaled_data = pd.DataFrame(X_scaled, columns=numerical_columns + categorical_columns)

# Calculate correlation matrix
correlation_matrix = scaled_data.corr()


correlation_with_binarylabel = correlation_matrix['binarylabel'].sort_values(ascending=False)

# Display the correlations
print(correlation_with_binarylabel)
