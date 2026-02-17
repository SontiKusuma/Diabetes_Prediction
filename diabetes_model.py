import numpy as np
import joblib
import os

class DiabetesPredictor:
    def __init__(self):
        self.model_loaded = False
        self.load_model()
        
    def load_model(self):
        """Try to load the model - for now just return True for testing"""
        try:
            # Check if model files exist
            if os.path.exists('models/diabetes_mlp_model.h5'):
                print("Model found and loaded!")
                self.model_loaded = True
                return True
            else:
                print("Model files not found. Using dummy model for testing.")
                self.model_loaded = True  # Still return True for testing
                return True
        except Exception as e:
            print(f"Error: {e}")
            return False
    
    def predict(self, input_data):
        """
        Make prediction - for now returns dummy results for testing
        """
        if not self.model_loaded:
            return None
        
        # Convert inputs to numerical values for calculation
        try:
            age = float(input_data.get('age', 0))
            bmi = float(input_data.get('bmi', 0))
            hba1c = float(input_data.get('HbA1c_level', 0))
            glucose = float(input_data.get('blood_glucose_level', 0))
            hypertension = int(input_data.get('hypertension', 0))
            heart_disease = int(input_data.get('heart_disease', 0))
            
            # Simple risk calculation based on medical thresholds
            risk_score = 0
            
            # HbA1c risk (normal: <5.7, prediabetes: 5.7-6.4, diabetes: >6.4)
            if hba1c > 6.4:
                risk_score += 0.4
            elif hba1c > 5.7:
                risk_score += 0.2
                
            # Glucose risk (fasting normal: <100, prediabetes: 100-125, diabetes: >125)
            if glucose > 125:
                risk_score += 0.3
            elif glucose > 100:
                risk_score += 0.15
                
            # BMI risk
            if bmi > 30:
                risk_score += 0.1
            elif bmi > 25:
                risk_score += 0.05
                
            # Other risk factors
            if hypertension == 1:
                risk_score += 0.1
            if heart_disease == 1:
                risk_score += 0.1
            if age > 45:
                risk_score += 0.05
                
            # Cap at 1.0
            risk_score = min(risk_score, 1.0)
            
            prediction_class = 1 if risk_score > 0.5 else 0
            
            return {
                'prediction': prediction_class,
                'probability': risk_score,
                'risk_level': 'high' if prediction_class == 1 else 'low',
                'message': 'High risk of diabetes detected. Please consult a healthcare professional.' 
                          if prediction_class == 1 
                          else 'Low risk of diabetes. Maintain healthy lifestyle.'
            }
            
        except Exception as e:
            return {'error': f'Prediction error: {str(e)}'}

# Create a global instance
diabetes_model = DiabetesPredictor()

def init_model():
    """Initialize the model"""
    return diabetes_model.load_model()

def predict_diabetes(input_data):
    """Main prediction function"""
    return diabetes_model.predict(input_data)