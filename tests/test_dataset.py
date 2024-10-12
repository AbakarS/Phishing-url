"""
This module contains tests for the phishing detection model.

It includes the function `test_load_data`, which verifies that the data 
is correctly loaded from the dataset and checks for required columns.
"""
from phishing_url_analyzer.features_extracting.features_extract import data_import

def test_load_data():
    """ 
    Tests the `data_export` function to ensure it correctly loads the data.
    
    The test checks:
    - That the data is not empty.
    - That the 'url' and 'label' columns are present in the loaded data.
    """
    data = data_import('C:/Users/HP/OneDrive/Bureau/phishing_url_analyzer/phishing_url_analyzer/data/data.csv')
    print(data)
    assert data is not None, "Data should not be None"
    assert 'URL' in data.columns, "The 'url' column should be present in the data"
    assert 'label' in data.columns, "The 'label' column should be present in the data"
