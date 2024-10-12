import pytest

from phishing_url_analyzer.model.phishing_url_analyzer import PhishingURLAnalyzer


@pytest.fixture
def data_path():
    """Fixture that provides the path to the test dataset."""
    # Assurez-vous que le fichier de données de test est bien présent dans le chemin spécifié.
    return "C:/Users/HP/OneDrive/Bureau/phishing_url_analyzer/phishing_url_analyzer/features_extracting/features_df.csv"

@pytest.fixture
def analyzer(data_path):
    """Fixture to instantiate the PhishingURLAnalyzer class."""
    return PhishingURLAnalyzer(data_path=data_path)

def test_load_data(analyzer):
    """Test the data loading and preprocessing functionality."""
    analyzer.load_data()
    
    # Vérifiez que les données sont bien chargées
    assert analyzer.x_train is not None
    assert analyzer.x_test is not None
    assert analyzer.y_train is not None
    assert analyzer.y_test is not None
    
    # Teste si le nombre d'échantillons de test est correct
    assert len(analyzer.x_test) > 0

def test_pipeline_definition(analyzer):
    """Test the pipeline definition."""
    analyzer.define_pipeline()
    assert analyzer.pipeline is not None
    assert "classifier" in analyzer.pipeline.named_steps

def test_param_grid_definition(analyzer):
    """Test the parameter grid definition."""
    analyzer.define_param_grid()
    assert analyzer.param_grid is not None
    assert len(analyzer.param_grid) > 0

def test_model_optimization(analyzer):
    """Test the model optimization functionality."""
    analyzer.load_data()  # Load data first
    analyzer.define_pipeline()  # Define pipeline
    analyzer.define_param_grid()  # Define param grid

    # Optimizing the model and testing if the best model is found
    analyzer.optimize_model()
    assert analyzer.best_model is not None

def test_model_evaluation(analyzer):
    """Test the model evaluation after optimization."""
    analyzer.load_data()  # Load data
    analyzer.define_pipeline()  # Define pipeline
    analyzer.define_param_grid()  # Define param grid
    analyzer.optimize_model()  # Optimize model

    # Evaluate the model and assert accuracy score is above a threshold
    accuracy = analyzer.evaluate_model()
    assert accuracy >= 0.5  # Expected accuracy threshold (modify as needed)
