import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
import numpy as np

data = pd.read_csv('../../datasets/train_dataset/training_network_trails')

# List of columns to encode (non-numeric)
categorical_columns = ['#Src_IP', 'DestIP', 'Protocol', 'service', 'hostname', 'sni', 'url', 'path', 'filename']

# Replace any empty lists or invalid values with a placeholder like 0 or NaN
data = data.replace(r'^\s*$', np.nan, regex=True)  # Replace empty strings with NaN
data = data.apply(pd.to_numeric, errors='coerce')  # Convert non-numeric values to NaN

# Apply LabelEncoder to non-numeric columns
encoder = LabelEncoder()
for column in categorical_columns:
    data[column] = encoder.fit_transform(data[column].astype(str))  # Convert to string before encoding

# Selecting features and target variable
X = data[[
    '#Src_IP', 'DestIP', 'Dport', 'Protocol', 'service',
    'sportcounts', 'number_of_flows',
    'average_of_duration', 'standard_deviation_duration',
    'total_size_of_flows_orig', 'total_size_of_flows_resp',
    'inbound_pckts', 'outbound_pckts', 'ssl_ratio',
    'tls_version_ratio', 'is_valid_certificate_during_capture',
    'amount_diff_certificates',
    'number_of_domains_in_certificate', 'SNI_ssl_ratio', 'SNI_equal_DstIP',
    'url', 'url_query_names', 'url_query_values', 'hostname',
    'sni', 'number_of_downloaded_bytes',
    'number_of_uploaded_bytes', 'number_of_url_flows',
    'hostname_digitratio', 'hostname_alpharatio',
    'hostname_specialcharratio', 'sni_digitratio',
    'sni_alpharatio', 'sni_specialcharratio', 'dns_noerror',
    'dns_nxdomain'
]]
y = data[['binarylabel']]

# Handling missing data: Fill NaN values with 0 or another suitable value
X = X.fillna(0)

# Splitting the data
scaler = StandardScaler()
(X_train, X_test, y_train, y_test) = train_test_split(X, y, test_size=0.2, random_state=42)

# Apply scaling to the features
scaler.fit(X_train)
X_train = scaler.transform(X_train)
X_test = scaler.transform(X_test)

# KNN model training
knn = KNeighborsClassifier(n_neighbors=15)
knn.fit(X_train, y_train)

# Evaluating the model
accuracy = knn.score(X_test, y_test)
print(f'Model accuracy: {accuracy * 100:.2f}%')

# Saving the model and scaler
joblib.dump(knn, '../../models/network_knn_model.joblib')
joblib.dump(scaler, '../../app scalers/network_scaler_model.joblib')
