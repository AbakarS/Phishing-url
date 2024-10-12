"""
This module performs feature selection, model optimization, 
and evaluation for a phishing URL dataset.

Key steps:
1. Import necessary libraries for data processing, model selection, and evaluation.
2. Load the dataset and preprocess it by removing constant columns and checking for missing values.
3. Split the dataset into training and testing sets.
4. Define a machine learning pipeline for feature selection, scaling, and classification.
5. Use GridSearchCV to find the best model and hyperparameters through cross-validation.
6. Evaluate the optimized model on the test set.
7. Save the best model using joblib for later use.
"""

import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.pipeline import Pipeline
from sklearn.model_selection import KFold
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
import joblib


class PhishingURLAnalyzer:
    """
    A class to analyze phishing URLs using machine learning techniques.

    This class handles the entire workflow for loading data, 
    preprocessing, feature selection, model optimization, and evaluation 
    for a phishing URL dataset.

    Attributes:
        data_path (str): Path to the CSV file containing the dataset.
        test_size (float): Proportion of the dataset to include in the test split.
        random_state (int): Random state for reproducibility.
        x_train (pd.DataFrame): Training features.
        x_test (pd.DataFrame): Testing features.
        y_train (pd.Series): Training labels.
        y_test (pd.Series): Testing labels.
        best_model (sklearn.pipeline.Pipeline): The best model after optimization.
    """

    def __init__(self, data_path: str, test_size: float = 0.2, random_state: int = 42):
        self.data_path = data_path
        self.test_size = test_size
        self.random_state = random_state
        self.x_train = None
        self.x_test = None
        self.y_train = None
        self.y_test = None
        self.best_model = None
        
        # Initialize the pipeline and param_grid here
        self.pipeline = None
        self.param_grid = None

    def load_data(self):
        """Load and preprocess the dataset."""
        data_urls = pd.read_csv(self.data_path)
        data_urls = data_urls.sample(frac=0.20, random_state=self.random_state)
        X = data_urls.drop(["URL", "label"], axis=1)
        y = data_urls["label"]

        # Identifying and removing constant columns
        constant_columns = [col for col in X.columns if X[col].nunique() == 1]
        X = X.drop(columns=constant_columns)
        print(f"\nColumns with constant values : {constant_columns}\n")

        # Checking for missing values
        print(f"Checking for missing values :  \n{X.isnull().sum()}\n")

        self.x_train, self.x_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=self.test_size, random_state=self.random_state
        )

    def define_pipeline(self):
        """Define the preprocessing and modeling pipeline."""
        self.pipeline = Pipeline(
            steps=[
                ("feature_selection", SelectKBest(score_func=f_classif, k=20)),
                ("scaling", StandardScaler()),
                ("classifier", LogisticRegression(random_state=self.random_state, solver='lbfgs', max_iter=100))
            ],
            memory='cache'  # Use a memory cache to speed up repeated calls
        )

    def define_param_grid(self):
        """Define the parameter grid for GridSearchCV."""
        self.param_grid = [
            {
                'classifier': [LogisticRegression(solver='lbfgs', max_iter=100, random_state=self.random_state)],
                'classifier__C': [0.1, 1]
            },
            {
                'classifier': [SVC(random_state=self.random_state)],  # Include random_state here
                'classifier__C': [0.5, 1, 10],
                'classifier__kernel': ['linear', 'rbf']
            },
            {
                'classifier': [RandomForestClassifier(random_state=self.random_state)],  # Include random_state here
                'classifier__n_estimators': [50, 100, 150],
                'classifier__max_features': ['sqrt', 'log2']
            }
        ]

    def optimize_model(self):
        """Optimize the model using GridSearchCV."""
        cross_validation_design = KFold(n_splits=5, shuffle=True, random_state=self.random_state)
        grid_search = GridSearchCV(
            self.pipeline, self.param_grid, cv=cross_validation_design, n_jobs=-1, verbose=1
        )
        grid_search.fit(self.x_train, self.y_train)
        
        # Access and save the best model
        self.best_model = grid_search.best_estimator_
        print(f"\nBest settings found : {grid_search.best_params_}")
        print(f"\nBest cross-validation score : {grid_search.best_score_}\n")

    def evaluate_model(self):
        """Evaluate the optimized model on the test set."""
        y_pred = self.best_model.predict(self.x_test)
        
        # Print the classification report
        print("Classification report:\n", classification_report(self.y_test, y_pred))
        
        # Calculate accuracy
        accuracy = accuracy_score(self.y_test, y_pred)
        print("\nAccuracy:", accuracy)
        
        # Return the accuracy to be used in the test
        return accuracy

    def save_model(self, filename='best_model.pkl'):
        """Save the best model for later use."""
        joblib.dump(self.best_model, filename)
        print(f"\nModel saved as {filename}")

    def run(self):
        """Run the entire analysis pipeline."""
        self.load_data()
        self.define_pipeline()
        self.define_param_grid()
        self.optimize_model()
        self.evaluate_model()
        self.save_model()


if __name__ == "__main__":
    DATA_FILE_PATH = "C:/Users/HP/OneDrive/Bureau/phishing_url_analyzer/phishing_url_analyzer/features_extracting/featuresextract_df.csv"
    analyzer = PhishingURLAnalyzer(DATA_FILE_PATH)
    analyzer.run()
    