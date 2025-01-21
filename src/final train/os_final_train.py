import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.neighbors import KNeighborsClassifier

data = pd.read_csv('../datasets/final eval dataset/train_dataset_final/train_dataset/training_os_trails')
X = data[['num', 'Filename', 'Operation', 'Path', 'Result', 'Detail', 'encodedOperation',
          'Length', 'read', 'write', 'encodedResult', 'security', 'network', 'pathindicator',
          'option', 'sharemodes', 'access', 'full_label', 'method', 'family_gene']
          ]
Y = data['goal']
X = X.apply(LabelEncoder().fit_transform)

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2, random_state=42)

# Standardize features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Train the model
model = KNeighborsClassifier()
model.fit(X_train, y_train)

# Evaluate and save the model and scaler
accuracy = model.score(X_test, y_test)
joblib.dump(model, '../../models/os_final_knn_model.pkl')
joblib.dump(scaler, '../../app scalers/final app model train scalers/os_final_scaler.pkl')
print(accuracy)
