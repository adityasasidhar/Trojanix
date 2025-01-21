import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
data = pd.read_csv('../../datasets/evaluation_dataset/evaluation_hardware_trails')
X= data[[
    "Core_cyc", "Ref_cyc", "Instruct", "Ins_Retd", "BrMispred", "BrMispExec_Any",
    "BrMispRetd_All", "BrTaken", "L1D_P_Miss_Oc", "L1D_Miss", "ICache_Misses",
    "ITLBMissW", "ITLBMissS", "DTLBLoadMiss_W", "DTLBLoadMissWC", "L2ReqAll",
    "L2ReqPFms", "M_Ld_Ret_L1Hit", "M_Ld_Ret_L2Hit", "M_Ld_Ret_L3Hit",
    "M_Ld_LLCH.XS_M", "M_Ld_LLCH.XS_N", "MLdULLCM_LDRAM", "Loop_uops",
    "Dec_uops", "Uops", "Mov_elim", "Mov_elim-", "CPL_CYCLES(R0)", "CPU_CLK_UNH_RF",
    "HW_Intrs_Rcvd", "ILenStal", "res.stl.", "IDQ_All_DSB_C", "IDQ_AllMite_UO",
    "uop_p0", "uop_p1", "uop_p2", "uop_p3", "uop_p4", "uop_p5", "uop_p05"
]]
Y = data["binarylabel"]
X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2, random_state=42)
label_enc = LabelEncoder()
for column in X.select_dtypes(include=['object']).columns:
    X[column] = label_enc.fit_transform(X[column])
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)
model = KNeighborsClassifier(10)
model.fit(X_train, y_train.to_numpy())
accuracy = model.score(X_test, y_test.to_numpy())
print("Model Accuracy:", accuracy)
joblib.dump(model, '../../models/hardware_knn_model.pkl')
joblib.dump(scaler, '../../app scalers/hardware_scaler.pkl')