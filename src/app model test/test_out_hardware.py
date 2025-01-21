import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder

# Load the pre-trained model and scaler
model = joblib.load('../../models/hardware_knn_model.pkl')
scaler = joblib.load('../../app scalers/hardware_scaler.pkl')

# Load the new dataset (replace 'new_dataset.csv' with the actual file path)
new_data = pd.read_csv('../../datasets/evaluation_dataset/evaluation_hardware_trails')
label_enc = LabelEncoder()
for column in new_data.select_dtypes(include=['object']).columns:
    new_data[column] = label_enc.fit_transform(new_data[column])

# Extract the same feature columns from the new data
X_new = new_data[["Core_cyc", "Ref_cyc", "Instruct", "Ins_Retd", "BrMispred", "BrMispExec_Any",
                  "BrMispRetd_All", "BrTaken", "L1D_P_Miss_Oc", "L1D_Miss", "ICache_Misses",
                  "ITLBMissW", "ITLBMissS", "DTLBLoadMiss_W", "DTLBLoadMissWC", "L2ReqAll",
                  "L2ReqPFms", "M_Ld_Ret_L1Hit", "M_Ld_Ret_L2Hit", "M_Ld_Ret_L3Hit",
                  "M_Ld_LLCH.XS_M", "M_Ld_LLCH.XS_N", "MLdULLCM_LDRAM", "Loop_uops",
                  "Dec_uops", "Uops", "Mov_elim", "Mov_elim-", "CPL_CYCLES(R0)", "CPU_CLK_UNH_RF",
                  "HW_Intrs_Rcvd", "ILenStal", "res.stl.", "IDQ_All_DSB_C", "IDQ_AllMite_UO",
                  "uop_p0", "uop_p1", "uop_p2", "uop_p3", "uop_p4", "uop_p5", "uop_p05"]]

# Scale the new data using the pre-trained scaler
X_new_scaled = scaler.transform(X_new)

# Predict using the trained model
predictions = model.predict(X_new_scaled)

# If you have a target column in the new dataset, you can evaluate accuracy as well
# Assuming 'binarylabel' is the target in the new dataset
Y_new = new_data['binarylabel']
accuracy = (predictions == Y_new).mean()

# Print the predictions and accuracy
print("Predictions:", predictions)
print("Accuracy on new dataset:", accuracy)
