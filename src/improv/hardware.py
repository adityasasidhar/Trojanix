import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
import joblib

data = pd.read_csv('../datasets/train_dataset_final/train_dataset/training_hardware_trails')
X = data['BrMispExec_Any', 'BrMispRetd_All', 'Cach_uops', 'Core_cyc', 'DTLBLoadMissWC',
     'DTLBLoadMiss_W', 'DTLBStoreMissW', 'DTLBStrMiss_WC', 'Ins_Retd', 'Instruct',
     'L2ReqAll', 'L2ReqPFms', 'Ref_cyc', 'Uops', 'Uops_F.D.', 'method', 'method_encoded',
     'uop_p0', 'uop_p05', 'uop_p1', 'uop_p2', 'uop_p3', 'uop_p4', 'uop_p5']

y= data['goal']
label_enc = LabelEncoder()
for column in X.select_dtypes(include=['object']).columns:
    X.loc[:, column] = label_enc.fit_transform(X[column])
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)
model = KNeighborsClassifier(1)
model.fit(X_train, y_train.to_numpy())

accuracy = model.score(X_test, y_test.to_numpy())
print("Model Accuracy:", accuracy)
joblib.dump(model, '../../models/improv_hardware_final_knn_model.pkl')
joblib.dump(scaler, '../../scalers/final scalers/improv_hardware_final_scaler.pkl')
