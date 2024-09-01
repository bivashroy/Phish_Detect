from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import pickle
import numpy as np
import logging

# Import the feature extraction function
from FeatureExtraction import featureExtractions

# Initialize FastAPI app
app = FastAPI()

# Load the XGBoost model
with open('XGBoostClassifier.pkl', 'rb') as file:
    model = pickle.load(file)

# Directory for templates
templates = Jinja2Templates(directory="templates")

# Define request model
class PhishingRequest(BaseModel):
    url: str

# Root endpoint
@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "message": "Welcome to the Phishing Detection API"})

# Prediction endpoint
@app.post("/predict")
def predict(request: PhishingRequest):
    try:
        # Extract features from the URL
        features = featureExtractions(request.url)
        features.pop(0)  # Remove the getDomain(url) feature

        # Check the feature length
        if len(features) != 15:
            raise ValueError(f"Expected 15 features, got {len(features)}")

        # Convert list of features to a numpy array
        features_array = np.array(features)

        # Reshape the array to the appropriate format
        features_array = features_array.reshape(1, -1)

        # Make prediction
        prediction = model.predict(features_array)
        result = "Legitimate" if int(prediction[0]) == 1 else "Phishing"
        
        return {"prediction": result}
    except Exception as e:
        logging.error(f"Error during prediction: {e}")
        raise HTTPException(status_code=400, detail=str(e))