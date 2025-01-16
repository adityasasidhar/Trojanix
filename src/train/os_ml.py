import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.neighbors import KNeighborsClassifier
import joblib

# Load data
data = pd.read_csv('../../datasets/train_dataset/training_os_trails')

# Select features and target
X = data[['num', 'Filename', 'Operation', 'Path', 'Result', 'Detail',
          'encodedOperation', 'Length', 'read', 'write', 'encodedResult',
          'security', 'network', 'pathindicator', 'option', 'sharemodes',
          'access', 'label', 'binarylabel', 'full_label', 'method',
          'family_gene', 'keylog', 'bkdoor', 'infosteal', 'rootkits',
          'method_encoded', 'goal_encoded', 'family_encoded', 'infosteal_encoded']]
Y = data['goal']

# Apply LabelEncoder
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
joblib.dump(model, 'os_knn_model.pkl')
joblib.dump(scaler, 'os_scaler.pkl')
print("Model Accuracy:", accuracy)
