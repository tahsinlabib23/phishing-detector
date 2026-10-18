"""Flask application for inspecting pasted email text."""

import os
from pathlib import Path

from flask import Flask, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge

from phishing_detector import (
    ModelLoadError,
    ModelNotAvailable,
    PredictionError,
    PhishingModel,
)


BASE_DIR = Path(__file__).resolve().parent
MAX_EMAIL_CHARS = 50_000


def create_app(config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        MODEL_PATH=os.environ.get(
            "PHISHING_MODEL_PATH", BASE_DIR / "models" / "email_classifier.pkl"
        ),
        MAX_CONTENT_LENGTH=256 * 1024,
        MAX_EMAIL_CHARS=MAX_EMAIL_CHARS,
        TEMPLATES_AUTO_RELOAD=True,
    )
    if config:
        app.config.update(config)

    classifier = app.config.get("CLASSIFIER") or PhishingModel(app.config["MODEL_PATH"])

    def render_page(
        *, email_from="", email_subject="", email_body="", email_length=0,
        result=None, error=None, status=200
    ):
        return (
            render_template(
                "index.html",
                email_from=email_from,
                email_subject=email_subject,
                email_body=email_body,
                email_length=email_length,
                result=result,
                error=error,
                max_email_chars=app.config["MAX_EMAIL_CHARS"],
            ),
            status,
        )

    @app.get("/")
    def index():
        return render_page()

    @app.post("/scan")
    def scan():
        email_from = request.form.get("email_from", "")
        email_subject = request.form.get("email_subject", "")
        email_body = request.form.get("email_body", "")
        email_headers = []
        if email_from.strip():
            email_headers.append(f"From: {email_from.strip()}")
        if email_subject.strip():
            email_headers.append(f"Subject: {email_subject.strip()}")
        body = email_body.strip()
        email_text = "\n".join(email_headers)
        if body:
            email_text = f"{email_text}\n\n{body}" if email_text else body
        form_values = {
            "email_from": email_from,
            "email_subject": email_subject,
            "email_body": email_body,
            "email_length": len(email_text),
        }

        if not email_from.strip():
            return render_page(
                **form_values,
                error={
                    "kind": "input",
                    "title": "Sender required",
                    "message": "Enter the sender shown in the email’s From field before scanning.",
                },
                status=400,
            )

        if not email_body.strip():
            return render_page(
                **form_values,
                error={
                    "kind": "input",
                    "title": "Message body needed",
                    "message": "Paste the email message body before scanning. Subject is optional.",
                },
                status=400,
            )

        if len(email_text) > app.config["MAX_EMAIL_CHARS"]:
            return render_page(
                **form_values,
                error={
                    "kind": "input",
                    "title": "Message is too long",
                    "message": f"Keep the combined email under {app.config['MAX_EMAIL_CHARS']:,} characters.",
                },
                status=400,
            )

        try:
            result = classifier.analyze(email_text)
        except ModelNotAvailable:
            return render_page(
                **form_values,
                error={
                    "kind": "model-missing",
                    "title": "The classifier is not installed",
                    "message": "Add your trained pipeline at models/email_classifier.pkl, then restart the app.",
                },
                status=503,
            )
        except ModelLoadError:
            app.logger.exception("The configured phishing model could not be loaded")
            return render_page(
                **form_values,
                error={
                    "kind": "model-error",
                    "title": "The classifier could not be loaded",
                    "message": "Check that the configured file is a trusted, compatible scikit-learn pipeline.",
                },
                status=503,
            )
        except PredictionError:
            app.logger.exception("The phishing model failed to analyze an email")
            return render_page(
                **form_values,
                error={
                    "kind": "model-error",
                    "title": "This message could not be analyzed",
                    "message": "Check that the pipeline accepts raw email text and returns binary probabilities.",
                },
                status=500,
            )

        return render_page(**form_values, result=result)

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error):
        return render_page(
            error={
                "kind": "input",
                "title": "Email is too large",
                "message": "The submitted request exceeded the server limit. Paste a shorter message and try again.",
            },
            status=413,
        )

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=False)
