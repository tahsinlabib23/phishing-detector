"""Flask website for authenticated phishing scans backed by Supabase."""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from dotenv import load_dotenv
from flask import Flask, abort, g, jsonify, redirect, render_template, request, url_for
from werkzeug.exceptions import RequestEntityTooLarge

from phishing_detector import (
    MODEL_BENCHMARKS,
    ModelLoadError,
    ModelNotAvailable,
    PhishingModel,
    PredictionError,
    THREAT_CATEGORIES,
    THREAT_CATEGORY_LABELS,
    classify_threat_category,
)


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
MAX_EMAIL_CHARS = 50_000
SUPABASE_TIMEOUT_SECONDS = 8
SESSION_CACHE_TTL_SECONDS = 60


class SupabaseUnavailable(Exception):
    """Raised when the configured Supabase service cannot be reached."""


class SupabaseResponseError(Exception):
    """Raised when Supabase rejects a request."""

    def __init__(self, status: int, message: str = ""):
        super().__init__(message)
        self.status = status


def create_app(config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "local-development-key-change-me"),
        MODEL_PATH=os.environ.get(
            "PHISHING_MODEL_PATH", BASE_DIR / "models" / "email_classifier.pkl"
        ),
        SUPABASE_URL=os.environ.get("SUPABASE_URL", "").rstrip("/"),
        SUPABASE_PUBLISHABLE_KEY=(
            os.environ.get("SUPABASE_PUBLISHABLE_KEY")
            or os.environ.get("SUPABASE_ANON_KEY", "")
        ),
        COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
        MAX_CONTENT_LENGTH=256 * 1024,
        MAX_EMAIL_CHARS=MAX_EMAIL_CHARS,
        TEMPLATES_AUTO_RELOAD=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    if config:
        app.config.update(config)

    classifier = app.config.get("CLASSIFIER") or PhishingModel(app.config["MODEL_PATH"])
    user_session_cache: dict[str, tuple[float, dict]] = {}

    def supabase_ready():
        return bool(app.config["SUPABASE_URL"] and app.config["SUPABASE_PUBLISHABLE_KEY"])

    def supabase_request(path, *, method="GET", access_token=None, payload=None, query=None):
        """Call Supabase Auth or PostgREST using the public key and user JWT."""
        if not supabase_ready():
            raise SupabaseUnavailable("Supabase is not configured")
        endpoint = f"{app.config['SUPABASE_URL']}{path}"
        if query:
            endpoint = f"{endpoint}?{urlencode(query)}"
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {
            "apikey": app.config["SUPABASE_PUBLISHABLE_KEY"],
            "Accept": "application/json",
        }
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = Request(endpoint, data=body, headers=headers, method=method)
        try:
            with urlopen(req, timeout=SUPABASE_TIMEOUT_SECONDS) as response:
                raw = response.read()
                data = json.loads(raw.decode("utf-8")) if raw else None
                return data, response.status
        except HTTPError as exc:
            raw = exc.read()
            try:
                data = json.loads(raw.decode("utf-8")) if raw else {}
            except (UnicodeDecodeError, json.JSONDecodeError):
                data = {}
            message = data.get("msg") or data.get("message") or data.get("error_description") or ""
            raise SupabaseResponseError(exc.code, str(message)) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise SupabaseUnavailable("Supabase request failed") from exc

    def set_auth_cookies(response, auth_data):
        access_token = auth_data.get("access_token")
        refresh_token = auth_data.get("refresh_token")
        if not access_token or not refresh_token:
            return response
        response.set_cookie(
            "sb_access_token",
            access_token,
            max_age=max(60, int(auth_data.get("expires_in", 3600))),
            httponly=True,
            secure=app.config["COOKIE_SECURE"],
            samesite="Lax",
            path="/",
        )
        response.set_cookie(
            "sb_refresh_token",
            refresh_token,
            max_age=60 * 60 * 24 * 30,
            httponly=True,
            secure=app.config["COOKIE_SECURE"],
            samesite="Lax",
            path="/",
        )
        return response

    def clear_auth_cookies(response):
        for name in ("sb_access_token", "sb_refresh_token"):
            response.delete_cookie(name, path="/", httponly=True, secure=app.config["COOKIE_SECURE"], samesite="Lax")
        return response

    @app.before_request
    def protect_authenticated_posts():
        # SameSite cookies help, and this origin check blocks cross-site form posts.
        if request.method == "POST" and request.cookies.get("sb_access_token"):
            origin = request.headers.get("Origin")
            if not origin or urlsplit(origin).netloc.lower() != request.host.lower():
                abort(403)

    @app.after_request
    def refresh_auth_cookie(response):
        renewed = getattr(g, "renewed_auth", None)
        if renewed:
            set_auth_cookies(response, renewed)
        return response

    def current_user():
        if hasattr(g, "current_user"):
            return g.current_user
        g.current_user = None
        if not supabase_ready():
            return None

        access_token = request.cookies.get("sb_access_token")
        if not access_token:
            return None
        cached_entry = user_session_cache.get(access_token)
        if cached_entry and cached_entry[0] > time.monotonic():
            g.supabase_access_token = access_token
            g.current_user = dict(cached_entry[1])
            return g.current_user
        try:
            user_data, _status = supabase_request("/auth/v1/user", access_token=access_token)
        except SupabaseResponseError as exc:
            if exc.status != 401:
                app.logger.warning("Supabase rejected session verification (HTTP %s)", exc.status)
                return None
            refresh_token = request.cookies.get("sb_refresh_token")
            if not refresh_token:
                return None
            try:
                renewed, _status = supabase_request(
                    "/auth/v1/token?grant_type=refresh_token",
                    method="POST",
                    payload={"refresh_token": refresh_token},
                )
                g.renewed_auth = renewed
                access_token = renewed["access_token"]
                user_data = renewed.get("user")
                if not user_data:
                    user_data, _status = supabase_request("/auth/v1/user", access_token=access_token)
            except (SupabaseUnavailable, SupabaseResponseError, KeyError, TypeError):
                return None
        except SupabaseUnavailable:
            app.logger.warning("Supabase is unavailable while verifying a session")
            return None

        user_id = user_data.get("id") if isinstance(user_data, dict) else None
        if not user_id:
            return None
        try:
            rows, _status = supabase_request(
                "/rest/v1/profiles",
                access_token=access_token,
                query={"select": "id,email,role,created_at", "id": f"eq.{user_id}", "limit": "1"},
            )
            profile = rows[0] if rows else {}
        except (SupabaseUnavailable, SupabaseResponseError):
            app.logger.warning("Could not load the signed-in user's profile")
            profile = {}
        user_meta = user_data.get("user_metadata") if isinstance(user_data.get("user_metadata"), dict) else {}
        g.supabase_access_token = access_token
        g.current_user = {
            "id": user_id,
            "email": user_data.get("email", ""),
            "role": profile.get("role", "user"),
            "created_at": profile.get("created_at") or user_data.get("created_at", ""),
            "last_sign_in_at": user_data.get("last_sign_in_at", ""),
            "display_name": str(user_meta.get("display_name") or ""),
            "organization": str(user_meta.get("organization") or ""),
        }
        if len(user_session_cache) > 256:
            user_session_cache.clear()
        user_session_cache[access_token] = (time.monotonic() + SESSION_CACHE_TTL_SECONDS, dict(g.current_user))
        return g.current_user

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if user:
                return view(*args, **kwargs)
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"error": "Sign in to scan emails."}), 401
            return redirect(url_for("login", next=url_for("index")))

        return wrapped

    def admin_required(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if current_user()["role"] != "admin":
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    def safe_next(value):
        parsed = urlsplit(value or "")
        if value and value.startswith("/") and not value.startswith("//") and not parsed.netloc and not parsed.scheme:
            return value
        return url_for("index")

    def render_page(
        *, email_from="", email_subject="", email_body="", email_length=0,
        result=None, error=None, storage_notice=None, status=200,
    ):
        return (
            render_template(
                "index.html",
                user=current_user(),
                email_from=email_from,
                email_subject=email_subject,
                email_body=email_body,
                email_length=email_length,
                result=result,
                error=error,
                storage_notice=storage_notice,
                max_email_chars=app.config["MAX_EMAIL_CHARS"],
            ),
            status,
        )

    @app.get("/login")
    def login():
        if current_user():
            return redirect(safe_next(request.args.get("next")))
        return render_template(
            "auth.html", mode="login", configured=supabase_ready(),
            next_url=safe_next(request.args.get("next")), message=request.args.get("message", ""), error=None,
        )

    @app.post("/login")
    def login_submit():
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        next_url = safe_next(request.form.get("next"))
        error = None
        auth_data = None
        if not supabase_ready():
            error = "Supabase is not configured yet. Add SUPABASE_URL and SUPABASE_ANON_KEY to the app environment."
        elif not email or not password:
            error = "Enter both your email and password."
        else:
            try:
                auth_data, _status = supabase_request(
                    "/auth/v1/token?grant_type=password",
                    method="POST",
                    payload={"email": email, "password": password},
                )
            except SupabaseResponseError as exc:
                error = "Email or password did not match." if exc.status in (400, 401) else "Sign-in is temporarily unavailable."
            except SupabaseUnavailable:
                error = "Could not connect to Supabase. Check the project URL and network."
        if not auth_data:
            return render_template(
                "auth.html", mode="login", configured=supabase_ready(), next_url=next_url,
                message="", error=error, email=email,
            ), 503 if not supabase_ready() else 401
        response = redirect(next_url)
        return set_auth_cookies(response, auth_data)

    @app.get("/register")
    def register():
        if current_user():
            return redirect(url_for("index"))
        return render_template(
            "auth.html", mode="register", configured=supabase_ready(), next_url=url_for("index"),
            message=request.args.get("message", ""), error=None,
        )

    @app.post("/register")
    def register_submit():
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        error = None
        auth_data = None
        if not supabase_ready():
            error = "Supabase is not configured yet. Add SUPABASE_URL and SUPABASE_ANON_KEY to the app environment."
        elif not email or len(password) < 8:
            error = "Enter an email and a password with at least 8 characters."
        else:
            try:
                auth_data, _status = supabase_request(
                    "/auth/v1/signup",
                    method="POST",
                    payload={"email": email, "password": password},
                )
            except SupabaseResponseError as exc:
                reason = str(exc).casefold()
                if any(marker in reason for marker in (
                    "weak_password", "password should", "password must", "password is too short",
                )):
                    category = "weak_password"
                    error = "Supabase rejected that password. Try a longer password with uppercase and lowercase letters, a number, and a symbol."
                elif "email" in reason and any(marker in reason for marker in (
                    "invalid", "not valid", "malformed",
                )):
                    category = "invalid_email"
                    error = "Supabase says this email address is invalid. Check its spelling and use an address you can access."
                elif any(marker in reason for marker in (
                    "already registered", "already been registered", "already exists", "user already exists",
                )):
                    category = "existing_account"
                    error = "An account with this email may already exist. Try signing in instead."
                elif "rate limit" in reason or "rate_limit" in reason:
                    category = "email_rate_limit"
                    error = "Supabase is temporarily limiting signup emails. Wait a few minutes, then try again."
                else:
                    category = "other"
                    error = "Supabase rejected the signup. Check the email and project password requirements, then try again."
                app.logger.info(
                    "Supabase signup rejected (HTTP %s; category=%s)", exc.status, category
                )
            except SupabaseUnavailable:
                error = "Could not connect to Supabase. Check the project URL and network."
        if not auth_data:
            return render_template(
                "auth.html", mode="register", configured=supabase_ready(), next_url=url_for("index"),
                message="", error=error, email=email,
            ), 503 if not supabase_ready() else 400
        if auth_data.get("access_token"):
            return set_auth_cookies(redirect(url_for("index")), auth_data)
        return redirect(url_for("login", message="Account created. Check your email to confirm it, then sign in."))

    @app.post("/logout")
    @login_required
    def logout():
        token = g.supabase_access_token
        user_session_cache.pop(token, None)
        try:
            supabase_request("/auth/v1/logout", method="POST", access_token=token)
        except (SupabaseUnavailable, SupabaseResponseError):
            app.logger.info("Supabase logout endpoint was unavailable; clearing local auth cookies")
        return clear_auth_cookies(redirect(url_for("login", message="You have signed out.")))

    @app.get("/")
    @login_required
    def index():
        return render_page()

    @app.post("/scan")
    @login_required
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
            return render_page(**form_values, error={"kind": "input", "title": "Sender required", "message": "Enter the sender shown in the email’s From field before scanning."}, status=400)
        if not body:
            return render_page(**form_values, error={"kind": "input", "title": "Message body needed", "message": "Paste the email message body before scanning. Subject is optional."}, status=400)
        if len(email_text) > app.config["MAX_EMAIL_CHARS"]:
            return render_page(**form_values, error={"kind": "input", "title": "Message is too long", "message": f"Keep the combined email under {app.config['MAX_EMAIL_CHARS']:,} characters."}, status=400)

        try:
            result = classifier.analyze(email_text)
        except ModelNotAvailable:
            return render_page(**form_values, error={"kind": "model-missing", "title": "The classifier is not installed", "message": "Add your trained pipeline at models/email_classifier.pkl, then restart the app."}, status=503)
        except ModelLoadError:
            app.logger.exception("The configured phishing model could not be loaded")
            return render_page(**form_values, error={"kind": "model-error", "title": "The classifier could not be loaded", "message": "Check that the configured file is a trusted, compatible scikit-learn pipeline."}, status=503)
        except PredictionError:
            app.logger.exception("The phishing model failed to analyze an email")
            return render_page(**form_values, error={"kind": "model-error", "title": "This message could not be analyzed", "message": "Check that the pipeline accepts raw email text and returns binary probabilities."}, status=500)

        storage_notice = None
        try:
            model_terms = [
                f"{m['name']}: {m['badge']} ({m['confidence_percent']}%)"
                for m in result.get("models", [])
            ]
            supabase_request(
                "/rest/v1/email_scans",
                method="POST",
                access_token=g.supabase_access_token,
                payload={
                    "user_id": current_user()["id"],
                    "sender": email_from.strip(),
                    "subject": email_subject.strip(),
                    "email_body": body,
                    "verdict": result["verdict"],
                    "confidence_percent": result["confidence_percent"],
                    "top_terms": model_terms or result.get("top_terms", []),
                },
            )
            result["saved"] = True
        except (SupabaseUnavailable, SupabaseResponseError):
            app.logger.exception("Could not save a completed email scan")
            result["saved"] = False
            storage_notice = "The result is ready, but this scan could not be saved to the shared dataset."
        return render_page(**form_values, result=result, storage_notice=storage_notice)

    def enrich_scan_rows(raw_scans):
        enriched = []
        for row in raw_scans or []:
            combined_text = "\n".join(
                part for part in (
                    f"From: {row.get('sender', '').strip()}" if row.get("sender") else "",
                    f"Subject: {row.get('subject', '').strip()}" if row.get("subject") else "",
                    str(row.get("email_body", "")),
                ) if part
            )
            verdict_val = row.get("verdict", "legitimate")
            saved_cat = row.get("threat_category")
            if saved_cat in THREAT_CATEGORY_LABELS:
                cat_slug = saved_cat
                cat_label = THREAT_CATEGORY_LABELS[saved_cat]
            else:
                threat_info = classify_threat_category(combined_text, verdict_val)
                cat_slug = threat_info["threat_category"]
                cat_label = threat_info["threat_category_label"]

            created_str = str(row.get("created_at") or "")
            scan_date = created_str[:10] if len(created_str) >= 10 else ""
            enriched_row = dict(row)
            enriched_row["threat_category"] = cat_slug
            enriched_row["threat_category_label"] = cat_label
            enriched_row["scan_date"] = scan_date
            enriched.append(enriched_row)
        return enriched

    def render_profile_page(*, notice=None, error=None, status=200):
        user = current_user()
        raw_scans = []
        load_error = None
        try:
            raw_scans, _status = supabase_request(
                "/rest/v1/email_scans",
                access_token=g.supabase_access_token,
                query={
                    "select": "id,user_id,sender,subject,email_body,verdict,confidence_percent,top_terms,created_at",
                    "user_id": f"eq.{user['id']}",
                    "order": "created_at.desc",
                    "limit": "200",
                },
            )
        except SupabaseUnavailable:
            load_error = "Could not connect to Supabase to load your scan statistics."
        except SupabaseResponseError:
            app.logger.exception("Profile scan history query failed")
            load_error = "Your personal scan history could not be loaded."

        user_scans = enrich_scan_rows(raw_scans)
        total_scans = len(user_scans)
        phishing_count = sum(1 for r in user_scans if r.get("verdict") == "phishing")
        legitimate_count = total_scans - phishing_count
        phishing_pct = round(phishing_count / total_scans * 100, 1) if total_scans else 0.0
        legitimate_pct = round(legitimate_count / total_scans * 100, 1) if total_scans else 0.0
        avg_conf = (
            round(
                sum(float(r.get("confidence_percent") or 0.0) for r in user_scans) / total_scans,
                1,
            )
            if total_scans
            else 0.0
        )
        last_scan_at = user_scans[0].get("created_at", "") if user_scans else ""

        profile_stats = {
            "total_scans": total_scans,
            "phishing_count": phishing_count,
            "phishing_pct": phishing_pct,
            "legitimate_count": legitimate_count,
            "legitimate_pct": legitimate_pct,
            "avg_confidence": avg_conf,
            "last_scan_at": last_scan_at,
        }
        return (
            render_template(
                "profile.html",
                user=user,
                profile_stats=profile_stats,
                recent_scans=user_scans[:5],
                load_error=load_error,
                notice=notice,
                error=error,
            ),
            status,
        )

    @app.get("/profile")
    @login_required
    def profile():
        return render_profile_page()

    @app.post("/profile")
    @login_required
    def profile_submit():
        form_action = request.form.get("form_action", "profile").strip().lower()
        if form_action == "password":
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")
            if len(new_password) < 8:
                return render_profile_page(
                    error="Enter a new password with at least 8 characters.",
                    status=400,
                )
            if new_password != confirm_password:
                return render_profile_page(
                    error="New password and confirmation did not match.",
                    status=400,
                )
            try:
                supabase_request(
                    "/auth/v1/user",
                    method="PUT",
                    access_token=g.supabase_access_token,
                    payload={"password": new_password},
                )
            except SupabaseResponseError as exc:
                reason = str(exc).casefold()
                if "weak" in reason or "password" in reason:
                    msg = "Supabase rejected that password. Use a stronger password with upper/lowercase letters, a number, and a symbol."
                else:
                    msg = "Could not update your password right now. Try signing in again."
                return render_profile_page(error=msg, status=400)
            except SupabaseUnavailable:
                return render_profile_page(
                    error="Could not connect to Supabase to update your password.",
                    status=503,
                )
            return render_profile_page(notice="Your account password has been updated.")

        display_name = request.form.get("display_name", "").strip()[:80]
        organization = request.form.get("organization", "").strip()[:100]
        try:
            supabase_request(
                "/auth/v1/user",
                method="PUT",
                access_token=g.supabase_access_token,
                payload={
                    "data": {
                        "display_name": display_name,
                        "organization": organization,
                    }
                },
            )
            g.current_user["display_name"] = display_name
            g.current_user["organization"] = organization
            if getattr(g, "supabase_access_token", None):
                user_session_cache[g.supabase_access_token] = (
                    time.monotonic() + SESSION_CACHE_TTL_SECONDS,
                    dict(g.current_user),
                )
        except (SupabaseResponseError, SupabaseUnavailable):
            return render_profile_page(
                error="Could not save your profile settings right now.",
                status=503,
            )
        return render_profile_page(notice="Profile details saved.")

    def render_reporting_dashboard(*, endpoint_name: str, is_admin_dataset: bool):
        raw_scans = []
        load_error = None
        user = current_user()
        query_params = {
            "select": "id,user_id,profiles(email),sender,subject,email_body,verdict,confidence_percent,top_terms,created_at",
            "order": "created_at.desc",
            "limit": "200",
        }
        if not is_admin_dataset and user:
            query_params["user_id"] = f"eq.{user['id']}"

        try:
            raw_scans, _status = supabase_request(
                "/rest/v1/email_scans",
                access_token=g.supabase_access_token,
                query=query_params,
            )
        except SupabaseUnavailable:
            load_error = "Could not connect to Supabase to load the dataset."
        except SupabaseResponseError:
            app.logger.exception("Dashboard dataset query failed")
            load_error = "The dataset could not be loaded. Check the Supabase schema and access policies."

        enriched_scans = enrich_scan_rows(raw_scans)

        preset = request.args.get("preset", "all").strip().lower()
        if preset not in ("all", "today", "7d", "30d"):
            preset = "all"
        date_from = request.args.get("date_from", "").strip()
        date_to = request.args.get("date_to", "").strip()

        now_utc = datetime.now(timezone.utc).date()
        if not date_from and preset in ("today", "7d", "30d"):
            if preset == "today":
                date_from = now_utc.isoformat()
            elif preset == "7d":
                date_from = (now_utc - timedelta(days=7)).isoformat()
            elif preset == "30d":
                date_from = (now_utc - timedelta(days=30)).isoformat()

        result_filter = request.args.get("result", "all").strip().lower()
        if result_filter not in ("all", "phishing", "legitimate"):
            result_filter = "all"

        category_filter = request.args.get("category", "all").strip().lower()
        if category_filter != "all" and category_filter not in THREAT_CATEGORY_LABELS:
            category_filter = "all"

        filtered_scans = []
        for row in enriched_scans:
            if date_from and row["scan_date"] and row["scan_date"] < date_from:
                continue
            if date_to and row["scan_date"] and row["scan_date"] > date_to:
                continue
            if result_filter != "all" and row.get("verdict") != result_filter:
                continue
            if category_filter != "all" and row.get("threat_category") != category_filter:
                continue
            filtered_scans.append(row)

        total_scans = len(filtered_scans)
        phishing_count = sum(1 for r in filtered_scans if r.get("verdict") == "phishing")
        legitimate_count = total_scans - phishing_count
        phishing_pct = round(phishing_count / total_scans * 100, 1) if total_scans else 0.0
        legitimate_pct = round(legitimate_count / total_scans * 100, 1) if total_scans else 0.0
        avg_conf = (
            round(
                sum(float(r.get("confidence_percent") or 0.0) for r in filtered_scans) / total_scans,
                1,
            )
            if total_scans
            else 0.0
        )

        cat_counts = {slug: 0 for slug, _label in THREAT_CATEGORIES}
        for r in filtered_scans:
            c_slug = r.get("threat_category", "clean")
            if c_slug in cat_counts:
                cat_counts[c_slug] += 1

        category_breakdown = [
            {
                "slug": slug,
                "label": label,
                "count": cat_counts[slug],
                "percent": round(cat_counts[slug] / total_scans * 100, 1) if total_scans else 0.0,
            }
            for slug, label in THREAT_CATEGORIES
        ]

        filters = {
            "preset": preset,
            "date_from": date_from,
            "date_to": date_to,
            "result": result_filter,
            "category": category_filter,
            "active": bool(date_from or date_to or result_filter != "all" or category_filter != "all" or preset != "all"),
        }
        stats = {
            "total_scans": total_scans,
            "unfiltered_total": len(enriched_scans),
            "phishing_count": phishing_count,
            "phishing_pct": phishing_pct,
            "legitimate_count": legitimate_count,
            "legitimate_pct": legitimate_pct,
            "avg_confidence": avg_conf,
        }

        return render_template(
            "admin.html",
            user=user,
            scans=filtered_scans,
            load_error=load_error,
            filters=filters,
            stats=stats,
            category_breakdown=category_breakdown,
            threat_categories=THREAT_CATEGORIES,
            model_benchmarks=MODEL_BENCHMARKS,
            endpoint_name=endpoint_name,
            is_admin_dataset=is_admin_dataset,
        )

    @app.get("/dashboard")
    @login_required
    def dashboard():
        is_admin = current_user()["role"] == "admin"
        return render_reporting_dashboard(endpoint_name="dashboard", is_admin_dataset=is_admin)

    @app.get("/admin")
    @admin_required
    def admin():
        return render_reporting_dashboard(endpoint_name="admin", is_admin_dataset=True)

    @app.errorhandler(403)
    def forbidden(_error):
        if current_user() and current_user()["role"] != "admin":
            return render_template("auth.html", mode="forbidden", configured=supabase_ready(), next_url=url_for("index"), message="", error="This page is only available to admin accounts."), 403
        return "Forbidden", 403

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error):
        if current_user():
            return render_page(error={"kind": "input", "title": "Email is too large", "message": "The submitted request exceeded the server limit. Paste a shorter message and try again."}, status=413)
        return "Request too large", 413

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=False)
