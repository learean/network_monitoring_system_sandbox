import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, accuracy_score
from sklearn.utils import class_weight
import tensorflow as tf
import joblib
import numpy as np
from tensorflow.keras.callbacks import EarlyStopping

# Enable mixed precision if applicable (usually for GPU, but no harm on CPU)
tf.keras.mixed_precision.set_global_policy('mixed_float16')

# Load and preprocess the dataset
flow_dataset = pd.read_csv('dataset4.csv')

# Preprocess IP addresses
flow_dataset.iloc[:, 2] = flow_dataset.iloc[:, 2].str.replace('.', '', regex=False)
flow_dataset.iloc[:, 3] = flow_dataset.iloc[:, 3].str.replace('.', '', regex=False)
flow_dataset.iloc[:, 5] = flow_dataset.iloc[:, 5].str.replace('.', '', regex=False)

# Check class distribution
class_counts = flow_dataset.iloc[:, -1].value_counts()
print("Class distribution:")
print(class_counts)

X_flow = flow_dataset.iloc[:, :-1].values.astype('float64')
y_flow = flow_dataset.iloc[:, -1].values

# Split the data
X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25, random_state=0)

# Scale the data
scaler = StandardScaler()
X_flow_train = scaler.fit_transform(X_flow_train)
X_flow_test = scaler.transform(X_flow_test)

# Save the fitted scaler
joblib.dump(scaler, 'flow_scaler.pkl')

# Compute class weights
class_weights = class_weight.compute_class_weight('balanced', classes=np.unique(y_flow_train), y=y_flow_train)
class_weights_dict = dict(enumerate(class_weights))

def build_model():
    model = tf.keras.Sequential([
        tf.keras.layers.InputLayer(input_shape=(X_flow_train.shape[1],)),
        tf.keras.layers.Dense(64, activation='relu'),
        tf.keras.layers.Dropout(0.3),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.Dense(32, activation='relu'),
        tf.keras.layers.Dropout(0.3),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.Dense(1, activation='sigmoid', dtype='float32')  # Ensure final layer outputs float32
    ])

    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model

early_stopping = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)

model = build_model()

# Train the model
history = model.fit(
    X_flow_train, y_flow_train,
    epochs=10,
    batch_size=64,
    validation_split=0.1,
    class_weight=class_weights_dict,
    callbacks=[early_stopping]
)

# Evaluate the model on the test data
test_loss, test_accuracy = model.evaluate(X_flow_test, y_flow_test)
print(f"Test Accuracy: {test_accuracy:.2f}")

# Evaluate the model on the training data
train_loss, train_accuracy = model.evaluate(X_flow_train, y_flow_train)
print(f"Train Accuracy: {train_accuracy:.2f}")

# Predict on the test data
y_flow_pred = (model.predict(X_flow_test) > 0.5).astype("int32")

cm = confusion_matrix(y_flow_test, y_flow_pred)
acc = accuracy_score(y_flow_test, y_flow_pred)

print("Confusion Matrix:")
print(cm)
print("Accuracy: {:.2f}%".format(acc * 100))

# Save the model
model.save('flow_mlp_model.h5')
