# Phishing Detector

A Flask app for checking pasted email content with a local scikit-learn Logistic Regression pipeline. Users create accounts and sign in through Supabase Auth. Every completed scan is stored in Supabase, and accounts promoted to admin can view the shared scan dataset. The current pipeline combines word TF-IDF with URL, domain-pattern, urgency, credential-request, and financial-request signals.

## Connect Supabase

1. Create a Supabase project.
2. Open **SQL Editor** in Supabase and run [`supabase/schema.sql`](supabase/schema.sql). This creates user profiles, scan records, account-role handling, and row-level security policies.
3. In **Project Settings → API Keys**, copy the Project URL and publishable key. These are the `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` values.
4. Copy `.env.example` to `.env` in the project folder and fill in those values. Keep `.env` private; it is excluded from Git. The app uses only the publishable key and each user's signed-in token; it does not need a secret/service-role key.
5. In Supabase **Authentication → URL Configuration**, set the site URL to your deployed app address. For local email confirmation, add `http://127.0.0.1:5000` to the allowed redirect URLs. Email confirmation can remain enabled.
6. Start the app and create accounts from the registration page. New accounts receive the `user` role. To promote a trusted account, first register and confirm it, then run this in Supabase SQL Editor (replace the address):

   ```sql
   update public.profiles
   set role = 'admin'
   where email = lower('admin@example.com');
   ```

   That account will see the **dataset** link after signing in. Do not promote a user through the public signup form.

Scans include the sender, subject, full email body, verdict, confidence, and top supporting words. The admin page can display this content, so tell users before they scan. Supabase row-level security lets users insert and read only their own rows, while admins can read all scans. Passwords are handled by Supabase Auth and are never stored by this app.

## Run locally

Use Python **3.13.7** (the version recorded in `.python-version`). To run the website, someone needs `app.py`, `phishing_detector.py`, `requirements.txt`, `.env` with their own Supabase settings, `supabase/schema.sql` already applied to the Supabase project, all three templates in `templates/`, the files in `static/`, and `models/email_classifier.pkl`. The `training/` folder and `requirements-dev.txt` are not needed to run the website.

From this folder in Windows PowerShell:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000> in a browser.

The project reads Supabase settings and the Flask secret from `.env` automatically. Set `COOKIE_SECURE=false` for local HTTP; the Render configuration sets it to `true` for HTTPS.

On macOS or Linux, use:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

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

## Deploy on Render

The `render.yaml` file declares the web service and requests the environment values `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY`. Add those in the Render service environment after creating the Supabase project. Render generates `SECRET_KEY` and enables secure cookies. Add the Render app URL to Supabase's allowed redirect URLs.

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
