import pandas as pd
from scipy.io import arff
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

# Load the ARFF file (adjust path as needed)
data, meta = arff.loadarff('C:/Users/Stevens/Desktop/PhishNet-AI/data/Training Dataset.arff')  # Path to your ARFF file
df = pd.DataFrame(data)

# Convert byte columns to strings
df = df.apply(lambda x: x.decode() if isinstance(x, bytes) else x)

# Remove rows with NaN in the 'Result' column
df = df.dropna(subset=['Result'])

# Convert 'Result' column to integers and map to 0 (phishing) and 1 (safe)
df['Result'] = df['Result'].apply(lambda x: x.decode() if isinstance(x, bytes) else x).astype(int)
df['Result'] = df['Result'].map({-1: 0, 1: 1})

# Separate features and target
X = df.drop('Result', axis=1)  # 'Result' is the target column
y = df['Result']

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train a Random Forest classifier
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f'Model Accuracy: {accuracy:.2f}')

# Save the model
joblib.dump(model, 'backend/models/url_model.pkl')
print("Model saved as 'url_model.pkl'")
