import pandas as pd
from sklearn.preprocessing import LabelEncoder

# Load the dataset
data = pd.read_csv('datasets/train_dataset_final/train_dataset/training_network_trails')

# Get the list of columns
columns = data.columns.values.tolist()

# Apply Label Encoding
X = data[columns]
X = X.apply(LabelEncoder().fit_transform)

# Calculate the correlation matrix
correlation_matrix = X.corr()

# Find the pairs of columns with the highest correlation
highest_corr = correlation_matrix.unstack().sort_values(ascending=False)

# Remove self-correlation (correlation of a column with itself)
highest_corr = highest_corr[highest_corr < 1]

# Get the top 30 pairs of columns with the highest correlation
top_30_pairs = highest_corr.head(30)

print("The top 30 pairs of columns with the highest correlation are:")
print(top_30_pairs)

# Save the correlation matrix to a CSV file
X.to_csv('fileon.csv', index=False)
print("CSV saved to 'fileon.csv'")