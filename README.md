# Phishing-url
This repository presents a project for analyzing phishing URLs. In this project, we use poetry to manage dependencies specific to this project.

This project is structured as follows :

1. The **phishing_url_analyzer** folder contains:
- The **data** folder : **data.csv** and **data_building.py** (file showing how the data is built and exported)
- The **features_extracting** folder : **featuresextract_df.csv** and **phishing_feature_extract.py** (file used to extract the essential characteristics of Urls, to build and export the dataset)
- The **model** folder : **best_model.pkl** and **phishing_url_analyzer.py** (file used to train, choose the best model and save this model using the joblib library)

2. The **test** folder contains :
- **test_dataset.py** : this file is used to verify that the data is correctly loaded using the pytest test framework
- **test_phishing_url_analyzer.py** : this file verifies that the data is loaded correctly, the pipeline is defined, the parameters for model optimization are correctly configured, the model is optimized, and finally, its performance is evaluated while using the pytest testing framework

3. **poetry.lock** : stores the exact versions of my project's dependencies and their subdependencies. This ensures that every time someone installs my project, they get the exact same versions of libraries, which helps keep the environment consistent and reproducible.

4. **pyproject.toml** : This file plays a crucial role in managing dependencies, configuring my project, and managing metadata.


I cleaned this project from some folders and files that were created when running python files. You might want to check the **commit** for more information.
