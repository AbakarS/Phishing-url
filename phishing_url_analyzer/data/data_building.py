"""
This module retrieves the PHIUSIIL Phishing URL Dataset from UCI Machine Learning Repository, 
manipulates the data to extract URLs and their corresponding labels, 
and exports the processed dataset to a CSV file.

It contains the following:
- Fetching the dataset.
- Manipulating data (extracting URLs and labels).
- Exporting the processed data.
"""
# DATA SOURCE : https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset

# Packages for retrieving and manipulating data
from ucimlrepo import fetch_ucirepo
import pandas as pd

# Fetch dataset
phiusiil_phishing_url_website = fetch_ucirepo(id=967)

print(phiusiil_phishing_url_website)

# Build the X and y data
X = phiusiil_phishing_url_website.data.features
y = phiusiil_phishing_url_website.data.targets

# Concatenate the URL and label columns to create a new data table
data = pd.concat([X["URL"], y], axis=1)

# Exporting created data
def data_export(path):
    """Export the created dataset to the specified file path"""
    return data.to_csv(path, index=False)

data_export(r'phishing_url_analyzer\data\data.csv')
