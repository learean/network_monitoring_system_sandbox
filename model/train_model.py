import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, accuracy_score
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
import joblib

# Load dataset
flow_dataset = pd.read_csv('dataset.csv')

# Preprocess dataset
flow_dataset.iloc[:, 2] = flow_dataset.iloc[:, 2].str.replace('.', '')
flow_dataset.iloc[:, 3] = flow_dataset.iloc[:, 3].str.replace('.', '')
flow_dataset.iloc[:, 5] = flow_dataset.iloc[:, 5].str.replace('.', '')

X_flow = flow_dataset.iloc[:, :-1].values.astype('float64')
y_flow = flow_dataset.iloc[:, -1].values

X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25, random_state=0)

# Define the neural network model
model = Sequential()
model.add(Dense(64, input_dim=X_flow_train.shape[1], activation='relu'))
model.add(Dense(32, activation='relu'))
model.add(Dense(1, activation='sigmoid'))

model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

# Train the model
model.fit(X_flow_train, y_flow_train, epochs=10, batch_size=10, verbose=1)

# Evaluate the model
y_flow_pred = (model.predict(X_flow_test) > 0.5).astype("int32")

print("------------------------------------------------------------------------------")
print("Confusion Matrix")
cm = confusion_matrix(y_flow_test, y_flow_pred)
print(cm)

acc = accuracy_score(y_flow_test, y_flow_pred)
print(f"Success accuracy = {acc * 100:.2f} %")
fail = 1.0 - acc
print(f"Fail accuracy = {fail * 100:.2f} %")
print("------------------------------------------------------------------------------")

# Save the model
model.save('ddos_detection_model.h5')
