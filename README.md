# Phishing Detector

A Flask app for checking pasted email content with a local scikit-learn Logistic Regression pipeline. Enter the sender and message body; the subject is optional. The current pipeline combines word TF-IDF with URL, domain-pattern, urgency, credential-request, and financial-request signals.

## Run locally

From this folder in PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000> in a browser.

## Add the trained model

The trained pipeline is expected at `models/email_classifier.pkl`. It accepts raw email strings, exposes `predict()` and `predict_proba()`, and uses binary classes `0` (legitimate) and `1` (phishing). Its custom `EmailSecurityFeatures` transformer is defined in `phishing_detector.py`, which must stay beside `app.py` when loading the artifact. The active model file is included in the deployment repository; other `.pkl` files remain ignored.

The displayed confidence is the probability of the predicted verdict. The app loads the model on the first scan and reloads it if the file changes. To use another path, set `PHISHING_MODEL_PATH` before starting Flask:

```powershell
$env:PHISHING_MODEL_PATH = "C:\models\email_classifier.pkl"
python app.py
```

Pickle and joblib files can run code while loading. Only load model artifacts you created or trust.

## Explore the dataset

The `training` folder contains `CEAS_08_EDA.ipynb` for CEAS_08 EDA and `CEAS_08_EDA_copy.ipynb` for the MeAJOR preprocessing and Logistic Regression workflow. The latter now includes the engineered security-feature experiment and exports the website pipeline. It expects `meajor_cleaned_preprocessed.parquet.gzip` in the same folder and imports `phishing_detector.py` from the project root. The feature comparison tables are saved in `training/MeAJOR_feature_engineering_validation_test.csv` and `training/MeAJOR_feature_engineering_external_tests.csv`.

To run the model notebook, activate `.venv`, install `requirements-dev.txt`, then register the environment as a notebook kernel:

```powershell
python -m pip install -r requirements-dev.txt
python -m ipykernel install --user --name phishing-detector --display-name "Python (Phishing Detector)"
```

Select **Python (Phishing Detector)** as the notebook kernel. In Colab, upload `phishing_detector.py` along with the notebook and data files.

The dataset CSV is ignored by Git because it is a large raw email corpus. The notebook is tracked normally.

## Run checks

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

The checks use a small in-memory pipeline and do not require a trained model file.

## Run the generated live-site suite

Install the development dependencies and Playwright's Chromium browser:

```powershell
python -m pip install -r requirements-dev.txt
python -m playwright install chromium
```

Start the Flask site in terminal 1:

```powershell
python app.py
```

Run the suite from terminal 2:

```powershell
python training/run_generated_feature_site_suite.py
```

The suite sends 500 unique generated emails through `/scan` (100 each for URL counts, suspicious URL patterns, urgency wording, password/code requests, and financial-detail requests). It saves the generated corpus, per-email website results, a group summary, and a mobile screenshot in `training/`. The generated label scores are a stress check, not a held-out accuracy estimate.
