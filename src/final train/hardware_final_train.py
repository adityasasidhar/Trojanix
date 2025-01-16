import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.neighbors import KNeighborsClassifier

data = pd.read_csv('../datasets/final eval dataset/train_dataset_final/train_dataset/training_hardware_trails')

X = data[['num', 'Filename', 'Core_cyc', 'Ref_cyc', 'Instruct', 'Ins_Retd', 'ILenStal',
          'DTLBLoadMissWD', 'DTLBStoreMissW', 'DTLBStrMiss_SH', 'DTLBStrMiss_WC', 'DTLBStrMiss_WD',
          'FP_Assist_ANY', 'HW_Intrs_Rcvd', 'ICache_Misses', 'IDQ_All_DSB_C', 'IDQ_AllMite_UO',
          'L1D_P_Miss_Oc', 'L3_LAT_C_Miss', 'M_Ld_LLCH.XS_M', 'M_Ld_LLCH.XS_N', 'MLdULLCM_LDRAM',
          'M_Ld_Ret_L1Hit', 'M_Ld_Ret_L2Hit', 'M_Ld_Ret_L3Hit', 'Loop_uops', 'Dec_uops', 'Cach_uops',
          'Uops', 'Macrofus', 'Uops_F.D.', 'res.stl.', 'uop_p0', 'uop_p1', 'uop_p2', 'uop_p3', 'uop_p4',
          'uop_p5', 'uop_p05', 'BrMispred', 'Mov_elim', 'BrTaken', 'Mov_elim-', 'L1D_Miss', 'ITLBMissW',
          'ITLBMissS', 'L1D_Rep', 'L2ReqAll', 'L2ReqPFms', 'Load_Hit_Pre', 'BrMispExec_Any', 'BrMispRetd_All',
          'CPL_CYCLES(R0)', 'CPU_CLK_UNH_RF', 'DSB2MIT_SW_CNT', 'DTLBLoadMiss_W', 'DTLBLoadMissWC', 'full_label',
          'method', 'family_gene']].copy()

Y = data['goal']

label_enc = LabelEncoder()
for column in X.select_dtypes(include=['object']).columns:
    X.loc[:, column] = label_enc.fit_transform(X[column])

X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2, random_state=42)

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

model = KNeighborsClassifier()
model.fit(X_train, y_train.to_numpy())

accuracy = model.score(X_test, y_test.to_numpy())
print("Model Accuracy:", accuracy)

joblib.dump(model, '../../models/hardware_final_knn_model.pkl')
joblib.dump(scaler, '../../scalers/final scalers/hardware_final_scaler.pkl')
