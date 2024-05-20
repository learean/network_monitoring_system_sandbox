import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, accuracy_score
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping

# Load and preprocess the dataset
flow_dataset = pd.read_csv('dataset.csv')

# Replace dots in specific columns
flow_dataset.iloc[:, 2] = flow_dataset.iloc[:, 2].str.replace('.', '')
flow_dataset.iloc[:, 3] = flow_dataset.iloc[:, 3].str.replace('.', '')
flow_dataset.iloc[:, 5] = flow_dataset.iloc[:, 5].str.replace('.', '')

X_flow = flow_dataset.iloc[:, :-1].values
X_flow = X_flow.astype('float64')

y_flow = flow_dataset.iloc[:, -1].values

X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25, random_state=0)

# Build the enhanced neural network
model = Sequential([
    Dense(128, input_dim=X_flow_train.shape[1], activation='relu'),
    Dropout(0.5),
    Dense(64, activation='relu'),
    Dropout(0.5),
    Dense(32, activation='relu'),
    Dense(1, activation='sigmoid')
])

model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Early stopping to avoid overfitting
early_stopping = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)

# Train the model with early stopping
model.fit(X_flow_train, y_flow_train, epochs=10, batch_size=32, validation_split=0.2, callbacks=[early_stopping], verbose=1)

# Evaluate the model
y_flow_pred = (model.predict(X_flow_test) > 0.5).astype("int32")

print("Confusion matrix")
cm = confusion_matrix(y_flow_test, y_flow_pred)
print(cm)

acc = accuracy_score(y_flow_test, y_flow_pred)
print("Success accuracy = {0:.2f} %".format(acc * 100))
fail = 1.0 - acc
print("Fail accuracy = {0:.2f} %".format(fail * 100))

# Save the model
model.save('flow_model.h5')
print("Model saved to flow_model.h5")
