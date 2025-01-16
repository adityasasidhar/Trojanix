import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.neighbors import KNeighborsClassifier

try:
    data = pd.read_csv('train_dataset/training_network_trails')  # Ensure correct file extension
except FileNotFoundError:
    print("Training dataset not found.")
    exit()

X = data[['num', 'Filename', '#Src_IP', 'DestIP', 'Dport', 'Protocol', 'service', 'sportcounts', 'number_of_flows',
           'average_of_duration', 'standard_deviation_duration', 'percent_of_standard_deviation_duration', 'total_size_of_flows_orig',
             'total_size_of_flows_resp', 'ratio_of_sizes', 'percent_of_established_states', 'inbound_pckts', 'outbound_pckts', 
             'periodicity_average', 'periodicity_standart_deviation', 'ssl_ratio', 'average_public_key', 'tls_version_ratio',
               'average_of_certificate_length', 'standart_deviation_cert_length', 'is_valid_certificate_during_capture',
                 'amount_diff_certificates', 'number_of_domains_in_certificate', 'certificate_ratio', 'number_of_certificate_path', 
                 'x509_ssl_ratio', 'SNI_ssl_ratio', 'self_signed_ratio', 'is_SNIs_in_SNA_dns', 'SNI_equal_DstIP', 'is_CNs_in_SNA_dns',
                   'url', 'url_query_names', 'url_query_values', 'path', 'url_path_length', 'number_of_URL_query_parameters', 'filename', 
                   'filename_length', 'interarrival_time', 'number_of_url_flows', 'number_of_downloaded_bytes', 'number_of_uploaded_bytes',
                     'hostname', 'sni', 'noOffiles', 'filename_digitratio', 'filename_alpharatio', 'filename_specialcharratio', 'filename_caseratio',
                       'filename_vowelchangeratio', 'urldigitratio', 'urlalpharatio', 'urlspecialcharratio', 'urlcaseratio',
                         'urlvowelchangeratio', 'hostname_digitratio', 'hostname_alpharatio', 'hostname_specialcharratio', 'hostname_caseratio',
                           'hostname_vowelchangeratio', 'sni_digitratio', 'sni_alpharatio', 'sni_specialcharratio', 'sni_caseratio', 'sni_vowelchangeratio',
                             'dns_nxdomain_digitratio', 'dns_nxdomain_alpharatio', 'dns_nxdomain_specialcharratio',
                               'dns_nxdomain_caseratio', 'dns_nxdomain_vowelchangeratio', 'dns_success_digitratio', 
                               'dns_success_alpharatio', 'dns_success_specialcharratio', 'dns_success_caseratio', 
                               'dns_success_vowelchangeratio', 'dns_noerror', 'dns_nxdomain', 'dns_othererrors', 'dns_status_ratio',
                                 'cert_subject', 'cert_issuer', 'full_label', 'family_label', 'label', 'binarylabel', 'method',
                                   'family_gene', 'keylog', 'bkdoor', 'infosteal', 'rootkits', 'method_encoded', 'goal_encoded', 'family_encoded', 
                                   'infosteal_encoded', 'Src_P', 'Dest_IP', 'Dest_P']]

Y = data['goal']

# Ensure consistent encoding
X = X.apply(LabelEncoder().fit_transform)

X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2, random_state=42)

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

model = KNeighborsClassifier()
model.fit(X_train, y_train)

accuracy = model.score(X_test, y_test)

try:
    joblib.dump(model, 'network_knn_model.pkl')
    joblib.dump(scaler, 'network_scaler.pkl')
except Exception as e:
    print(f"Error saving model or scaler: {e}")

print(f"Model accuracy: {accuracy}")
