from diabetes_model import DiabetesPredictor

def main():
    print("Training diabetes prediction model...")
    
    predictor = DiabetesPredictor()
    predictor.train_and_save("dataset.csv")
    
    print("Model training completed successfully!")

if __name__ == "__main__":
    main()