import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder

# Load the dataset
data = pd.read_csv('../../datasets/evaluation_dataset/evaluation_hardware_trails')

# Select features (X) and the target variable (Y)
X = data[[
    "Core_cyc", "Ref_cyc", "Instruct", "Ins_Retd", "BrMispred", "BrMispExec_Any",
    "BrMispRetd_All", "BrTaken", "L1D_P_Miss_Oc", "L1D_Miss", "ICache_Misses",
    "ITLBMissW", "ITLBMissS", "DTLBLoadMiss_W", "DTLBLoadMissWC", "L2ReqAll",
    "L2ReqPFms", "M_Ld_Ret_L1Hit", "M_Ld_Ret_L2Hit", "M_Ld_Ret_L3Hit",
    "M_Ld_LLCH.XS_M", "M_Ld_LLCH.XS_N", "MLdULLCM_LDRAM", "Loop_uops",
    "Dec_uops", "Uops", "Mov_elim", "Mov_elim-", "CPL_CYCLES(R0)", "CPU_CLK_UNH_RF",
    "HW_Intrs_Rcvd", "ILenStal", "res.stl.", "IDQ_All_DSB_C", "IDQ_AllMite_UO",
    "uop_p0", "uop_p1", "uop_p2", "uop_p3", "uop_p4", "uop_p5", "uop_p05"
]]
y = data['binarylabel']

label_enc = LabelEncoder()
for column in X.select_dtypes(include=['object']).columns:
    X[column] = label_enc.fit_transform(X[column])

# Scale the features using StandardScaler
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Convert the scaled features into a DataFrame
X_scaled_df = pd.DataFrame(X_scaled, columns=X.columns)

# Calculate the correlation between binarylabel and all other features
correlation_with_y = X_scaled_df.corrwith(y)

# Display the correlation
print("Correlation of each feature with the binarylabel:")
print(correlation_with_y)
