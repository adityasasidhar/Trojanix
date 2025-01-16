import pandas as pd
from sklearn.preprocessing import LabelEncoder
import joblib

def go_through_os():
    eval_os = pd.read_csv('../datasets/evaluation_dataset/evaluation_os_trails')

    scaler = joblib.load('os_scaler.pkl')
    model = joblib.load('os_knn_model.pkl')

    columns_to_encode = ['num', 'Filename', 'Operation', 'Path', 'Result', 'Detail',
                         'encodedOperation', 'Length', 'read', 'write', 'encodedResult',
                         'security', 'network', 'pathindicator', 'option', 'sharemodes',
                         'access', 'label', 'binarylabel', 'full_label', 'method',
                         'family_gene', 'keylog', 'bkdoor', 'infosteal', 'rootkits',
                         'method_encoded', 'goal_encoded', 'family_encoded', 'infosteal_encoded']

    encoders = {col: LabelEncoder() for col in columns_to_encode}

    for col in columns_to_encode:
        eval_os[col] = encoders[col].fit_transform(eval_os[col])

    predictions = []

    for index, row in eval_os.iterrows():
        row_df = pd.DataFrame([row], columns=eval_os.columns)
        row_scaled = scaler.transform(row_df)
        prediction = model.predict(row_scaled)
        predictions.append({'goal': prediction[0]})

    return pd.DataFrame(predictions)

def go_through_network():
    eval_network = pd.read_csv('../datasets/evaluation_dataset/evaluation_network_trails')

    scaler = joblib.load('../scalers/scalers normal/network_scaler.pkl')
    model = joblib.load('network_knn_model.pkl')

    feature_columns = [
        'Dport', 'Protocol', 'service', 'sportcounts', 'number_of_flows',
        'average_of_duration', 'standard_deviation_duration',
        'percent_of_standard_deviation_duration', 'total_size_of_flows_orig',
        'total_size_of_flows_resp', 'ratio_of_sizes', 'percent_of_established_states',
        'inbound_pckts', 'outbound_pckts', 'ssl_ratio', 'tls_version_ratio',
        'is_valid_certificate_during_capture', 'amount_diff_certificates',
        'number_of_domains_in_certificate'
    ]

    X_eval = eval_network[feature_columns]
    X_eval = X_eval.apply(LabelEncoder().fit_transform)
    X_eval_scaled = scaler.transform(X_eval)

    predictions = model.predict(X_eval_scaled)
    return pd.DataFrame({'goal': predictions})

def go_through_hardware():
    eval_hardware = pd.read_csv('../datasets/evaluation_dataset/evaluation_hardware_trails')

    feature_columns = [
        'num', 'Core_cyc', 'Ref_cyc', 'Instruct', 'Ins_Retd', 'ILenStal',
        'DTLBLoadMissWD', 'DTLBStoreMissW', 'DTLBStrMiss_SH', 'DTLBStrMiss_WC',
        'DTLBStrMiss_WD', 'FP_Assist_ANY', 'HW_Intrs_Rcvd', 'ICache_Misses',
        'IDQ_All_DSB_C', 'IDQ_AllMite_UO', 'L1D_P_Miss_Oc', 'L3_LAT_C_Miss',
        'M_Ld_LLCH.XS_M', 'M_Ld_LLCH.XS_N', 'MLdULLCM_LDRAM', 'M_Ld_Ret_L1Hit',
        'M_Ld_Ret_L2Hit', 'M_Ld_Ret_L3Hit', 'Loop_uops', 'Dec_uops', 'Cach_uops',
        'Uops', 'Macrofus', 'Uops_F.D.', 'res.stl.', 'uop_p0', 'uop_p1', 'uop_p2',
        'uop_p3', 'uop_p4', 'uop_p5', 'uop_p05', 'BrMispred', 'Mov_elim', 'BrTaken',
        'Mov_elim-', 'L1D_Miss', 'ITLBMissW', 'ITLBMissS', 'L1D_Rep', 'L2ReqAll',
        'L2ReqPFms', 'Load_Hit_Pre', 'BrMispExec_Any', 'BrMispRetd_All',
        'CPL_CYCLES(R0)', 'CPU_CLK_UNH_RF', 'DSB2MIT_SW_CNT', 'DTLBLoadMiss_W',
        'DTLBLoadMissWC', 'binarylabel', 'method_encoded', 'goal_encoded',
        'family_encoded', 'infosteal_encoded'
    ]

    missing_cols = set(feature_columns) - set(eval_hardware.columns)
    if missing_cols:
        raise ValueError(f"Missing columns in evaluation dataset: {missing_cols}")

    X_eval = eval_hardware[feature_columns]

    scaler = joblib.load('../scalers/scalers normal/hardware_scaler.pkl')
    model = joblib.load('hardware_knn_model.pkl')

    label_enc = LabelEncoder()
    for column in X_eval.select_dtypes(include=['object']).columns:
        X_eval[column] = label_enc.fit_transform(X_eval[column])

    X_eval_scaled = scaler.transform(X_eval)

    predictions = model.predict(X_eval_scaled)
    return pd.DataFrame({'goal': predictions})

# Collect predictions
hardware_predictions = go_through_hardware()
network_predictions = go_through_network()
os_predictions = go_through_os()

# Concatenate predictions in the specified order
final_predictions = pd.concat([hardware_predictions, network_predictions, os_predictions], ignore_index=True)

# Add a new sequential index starting from 1
final_predictions['index'] = range(1, len(final_predictions) + 1)

# Reorder columns to ensure 'index' comes first
final_predictions = final_predictions[['index', 'goal']]

# Save to a single CSV
final_predictions.to_csv('results.csv', index=False)
