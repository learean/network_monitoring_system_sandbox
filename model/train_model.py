import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, accuracy_score
import tensorflow as tf
import joblib

# Load and preprocess the dataset
flow_dataset = pd.read_csv('dataset.csv')

flow_dataset.iloc[:, 2] = flow_dataset.iloc[:, 2].str.replace('.', '')
flow_dataset.iloc[:, 3] = flow_dataset.iloc[:, 3].str.replace('.', '')
flow_dataset.iloc[:, 5] = flow_dataset.iloc[:, 5].str.replace('.', '')

X_flow = flow_dataset.iloc[:, :-1].values
X_flow = X_flow.astype('float64')

y_flow = flow_dataset.iloc[:, -1].values

# Split the data
X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25, random_state=0)

# Scale the data
scaler = StandardScaler()
X_flow_train = scaler.fit_transform(X_flow_train)
X_flow_test = scaler.transform(X_flow_test)

# Save the fitted scaler
joblib.dump(scaler, 'flow_scaler.pkl')

# Build the MLP model
model = tf.keras.Sequential([
    tf.keras.layers.Dense(128, activation='relu', input_shape=(X_flow_train.shape[1],)),
    tf.keras.layers.Dense(64, activation='relu'),
    tf.keras.layers.Dense(1, activation='sigmoid')
])

# Compile the model
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Train the model
model.fit(X_flow_train, y_flow_train, epochs=10, batch_size=32, validation_split=0.1)

# Evaluate the model
y_flow_pred = (model.predict(X_flow_test) > 0.5).astype("int32")

cm = confusion_matrix(y_flow_test, y_flow_pred)
acc = accuracy_score(y_flow_test, y_flow_pred)

print("Confusion Matrix:")
print(cm)
print("Accuracy: {:.2f}%".format(acc * 100))

# Save the model
model.save('flow_mlp_model.h5')
