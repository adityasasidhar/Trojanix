import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder

# Load data
data = pd.read_csv('datasets/evaluation_dataset/evaluation_hardware_trails')

# Define target columns
target_columns = ['num', 'Filename', 'Core_cyc', 'Ref_cyc', 'Instruct', 'Ins_Retd', 'ILenStal',
                  'DTLBLoadMissWD', 'DTLBStoreMissW', 'DTLBStrMiss_SH', 'DTLBStrMiss_WC',
                  'DTLBStrMiss_WD', 'FP_Assist_ANY', 'HW_Intrs_Rcvd', 'ICache_Misses', 'IDQ_All_DSB_C',
                  'IDQ_AllMite_UO', 'L1D_P_Miss_Oc', 'L3_LAT_C_Miss', 'M_Ld_LLCH.XS_M', 'M_Ld_LLCH.XS_N',
                  'MLdULLCM_LDRAM', 'M_Ld_Ret_L1Hit', 'M_Ld_Ret_L2Hit', 'M_Ld_Ret_L3Hit', 'Loop_uops',
                  'Dec_uops', 'Cach_uops', 'Uops', 'Macrofus', 'Uops_F.D.', 'res.stl.', 'uop_p0', 'uop_p1',
                  'uop_p2', 'uop_p3', 'uop_p4', 'uop_p5', 'uop_p05', 'BrMispred', 'Mov_elim', 'BrTaken',
                  'Mov_elim-', 'L1D_Miss', 'ITLBMissW', 'ITLBMissS', 'L1D_Rep', 'L2ReqAll', 'L2ReqPFms',
                  'Load_Hit_Pre', 'BrMispExec_Any', 'BrMispRetd_All', 'CPL_CYCLES(R0)', 'CPU_CLK_UNH_RF',
                  'DSB2MIT_SW_CNT', 'DTLBLoadMiss_W', 'DTLBLoadMissWC', 'full_label', 'label', 'binarylabel',
                  'method', 'family_gene', 'keylog', 'bkdoor', 'infosteal', 'rootkits', 'method_encoded',
                  'goal_encoded', 'family_encoded', 'infosteal_encoded']

# Select only the target columns
data = data[target_columns]

# Initialize encoders and scalers
label_enc = LabelEncoder()
scaler = StandardScaler()

# Encode categorical columns
for column in data.select_dtypes(include=['object']).columns:
    data[column] = label_enc.fit_transform(data[column])

# Scale numerical columns
data[data.select_dtypes(include=['number']).columns] = scaler.fit_transform(
    data.select_dtypes(include=['number'])
)

# Compute correlation matrix
corr_matrix = data.corr()

# Create a set to hold highly correlated columns
high_corr_columns = set()

# Identify highly correlated columns (absolute correlation > 0.9)
threshold = 0.9
for col in corr_matrix.columns:
    for idx in corr_matrix.index:
        if col != idx and abs(corr_matrix.loc[idx, col]) > threshold:
            high_corr_columns.add(col)
            high_corr_columns.add(idx)

# Convert the set to a sorted list
high_corr_columns = sorted(high_corr_columns)

# Print the list of highly correlated columns
print("List of highly correlated columns (absolute correlation > 0.9):")
print(high_corr_columns)
