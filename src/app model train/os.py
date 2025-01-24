import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split

data = pd.read_csv('../../datasets/train_dataset/training_os_trails')
columns = data.columns.values.tolist()

print(columns)

X= data[['Filename', 'Operation', 'Path', 'Result', 'Detail', 'Length', 'read', 'write', 'network',
         'pathindicator', 'option', 'sharemodes', 'access', 'security', 'method']
]

y = data['binarylabel']

label_enc = LabelEncoder()

for column in X.select_dtypes(include=['object']).columns:
    X[column] = label_enc.fit_transform(X[column])

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_scaled_df = pd.DataFrame(X_scaled, columns=X.columns)
correlation_with_y = X_scaled_df.corrwith(y)

print("Correlation of each feature with the binarylabel:")
print(correlation_with_y)