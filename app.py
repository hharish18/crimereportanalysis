import os
import uuid
from datetime import datetime, timezone
from functools import wraps
from io import BytesIO

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from sqlalchemy import String, cast, func
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from config import Config
from models import Complaint, Feedback, Notification, Officer, User, db

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.abspath(os.path.dirname(__file__)), "templates"),
    static_folder=os.path.join(os.path.abspath(os.path.dirname(__file__)), "static"),
)
app.config.from_object(Config)

db.init_app(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.context_processor
def inject_globals():
    unread_count = 0
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    return {"csrf_token": generate_csrf, "unread_notifications": unread_count}


@app.errorhandler(SQLAlchemyError)
def handle_sqlalchemy_error(error):
    # Keep session usable after failed flush/commit.
    db.session.rollback()
    app.logger.exception("SQLAlchemy error", exc_info=error)
    flash("A database error occurred. Please try again.", "danger")
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]


def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role.lower() not in {r.lower() for r in roles}:
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for("dashboard"))
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def create_notification(user_id, title, message):
    note = Notification(user_id=user_id, title=title, message=message)
    db.session.add(note)


def send_email_notification(user, subject, body):
    if app.config["MAIL_ENABLED"]:
        # Integrate SMTP or a transactional provider here.
        print(f"[EMAIL to {user.email}] {subject}\n{body}")
    else:
        print(f"[MAIL_DISABLED] to={user.email} subject={subject} body={body}")


def generate_complaint_code():
    year = datetime.now().year
    prefix = f"CMP-{year}-"
    last = (
        Complaint.query.filter(Complaint.complaint_id.like(f"{prefix}%"))
        .order_by(Complaint.id.desc())
        .first()
    )
    next_no = 1
    if last:
        try:
            next_no = int(last.complaint_id.split("-")[-1]) + 1
        except ValueError:
            next_no = Complaint.query.count() + 1
    return f"{prefix}{next_no:04d}"


def parse_incident_datetime(value):
    # Accept HTML datetime-local format.
    return datetime.strptime(value, "%Y-%m-%dT%H:%M")


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "citizen").strip().lower()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()

        if role not in {"citizen", "police", "admin"}:
            flash("Invalid role selected.", "danger")
            return redirect(url_for("register"))
        if len(full_name) < 2:
            flash("Full name is required.", "danger")
            return redirect(url_for("register"))
        if "@" not in email:
            flash("Enter a valid email.", "danger")
            return redirect(url_for("register"))
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "warning")
            return redirect(url_for("register"))

        user = User(
            full_name=full_name,
            email=email,
            password_hash=generate_password_hash(password),
            role=role,
            phone=phone or None,
            address=address or None,
        )
        db.session.add(user)
        db.session.flush()

        if role == "police":
            badge_number = f"BDG-{user.id:05d}"
            officer = Officer(user_id=user.id, badge_number=badge_number, department="General")
            db.session.add(officer)

        db.session.commit()
        flash("Registration successful. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        role = request.form.get("role", "").strip().lower()

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid email or password.", "danger")
            return redirect(url_for("login"))
            
        if user.role != role:
            flash(f"Invalid role selected. This account is registered as '{user.role}'.", "danger")
            return redirect(url_for("login"))

        login_user(user)
        flash("Login successful.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        current_user.full_name = request.form.get("full_name", current_user.full_name).strip()
        current_user.phone = request.form.get("phone", "").strip() or None
        current_user.address = request.form.get("address", "").strip() or None

        new_password = request.form.get("new_password", "")
        if new_password:
            if len(new_password) < 6:
                flash("New password must be at least 6 characters.", "danger")
                return redirect(url_for("profile"))
            current_user.password_hash = generate_password_hash(new_password)

        db.session.commit()
        flash("Profile updated.", "success")
        return redirect(url_for("profile"))

    return render_template("profile.html")


@app.route("/dashboard")
@login_required
def dashboard():
    base_query = Complaint.query
    if current_user.role == "citizen":
        base_query = base_query.filter_by(user_id=current_user.id)
    elif current_user.role == "police":
        if current_user.officer_profile:
            base_query = base_query.filter_by(assigned_officer_id=current_user.officer_profile.id)
        else:
            base_query = base_query.filter(Complaint.id == -1)

    complaints = base_query.all()
    total = len(complaints)
    pending = sum(1 for c in complaints if c.status == "Pending")
    investigating = sum(1 for c in complaints if c.status == "Investigating")
    resolved = sum(1 for c in complaints if c.status == "Resolved")
    rejected = sum(1 for c in complaints if c.status == "Rejected")

    category_rows = (
        base_query.with_entities(Complaint.crime_type, func.count(Complaint.id))
        .group_by(Complaint.crime_type)
        .all()
    )
    location_rows = (
        base_query.with_entities(Complaint.location, func.count(Complaint.id))
        .group_by(Complaint.location)
        .all()
    )
    bind = db.session.get_bind()
    dialect = bind.dialect.name if bind else ""
    if dialect == "sqlite":
        month_expr = func.strftime("%Y-%m", Complaint.created_at)
    elif dialect in {"postgresql", "postgres"}:
        month_expr = func.to_char(Complaint.created_at, "YYYY-MM")
    elif dialect in {"mysql", "mariadb"}:
        month_expr = func.date_format(Complaint.created_at, "%Y-%m")
    else:
        month_expr = func.substr(cast(Complaint.created_at, String), 1, 7)

    trend_rows = (
        base_query.with_entities(month_expr, func.count(Complaint.id))
        .group_by(month_expr)
        .order_by(month_expr)
        .all()
    )

    return render_template(
        "dashboard.html",
        total=total,
        pending=pending,
        investigating=investigating,
        resolved=resolved,
        rejected=rejected,
        category_labels=[r[0] for r in category_rows],
        category_data=[r[1] for r in category_rows],
        location_labels=[r[0] for r in location_rows],
        location_data=[r[1] for r in location_rows],
        trend_labels=[r[0] for r in trend_rows],
        trend_data=[r[1] for r in trend_rows],
    )


@app.route("/report-crime", methods=["GET", "POST"])
@login_required
@role_required("citizen")
def report_crime():
    crime_types = ["Theft", "Assault", "Fraud", "Vandalism", "Cyber Crime", "Other"]

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        crime_type = request.form.get("crime_type", "").strip()
        location = request.form.get("location", "").strip()
        incident_raw = request.form.get("incident_datetime", "").strip()
        file = request.files.get("evidence")

        if not all([title, description, crime_type, location, incident_raw]):
            flash("All required fields must be completed.", "danger")
            return redirect(url_for("report_crime"))
        if crime_type not in crime_types:
            flash("Invalid crime type selected.", "danger")
            return redirect(url_for("report_crime"))

        try:
            incident_dt = parse_incident_datetime(incident_raw)
        except ValueError:
            flash("Invalid incident date/time format.", "danger")
            return redirect(url_for("report_crime"))

        evidence_file = None
        if file and file.filename:
            if not allowed_file(file.filename):
                flash("Unsupported file type for evidence upload.", "danger")
                return redirect(url_for("report_crime"))
            original = secure_filename(file.filename)
            evidence_file = f"{uuid.uuid4().hex}_{original}"
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], evidence_file)
            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
            file.save(save_path)

        complaint = Complaint(
            complaint_id=generate_complaint_code(),
            user_id=current_user.id,
            title=title,
            description=description,
            crime_type=crime_type,
            location=location,
            incident_datetime=incident_dt,
            evidence_file=evidence_file,
            status="Pending",
        )
        db.session.add(complaint)
        db.session.flush()

        for admin in User.query.filter_by(role="admin").all():
            create_notification(
                admin.id,
                "New Complaint Submitted",
                f"{current_user.full_name} submitted complaint {complaint.complaint_id}.",
            )

        create_notification(
            current_user.id,
            "Complaint Submitted",
            f"Your complaint {complaint.complaint_id} has been submitted successfully.",
        )
        db.session.commit()

        send_email_notification(
            current_user,
            "Complaint Submitted",
            f"Your complaint {complaint.complaint_id} is now in Pending status.",
        )

        flash(f"Complaint submitted successfully. ID: {complaint.complaint_id}", "success")
        return redirect(url_for("complaints"))

    return render_template("report_crime.html", crime_types=crime_types)


@app.route("/complaints")
@login_required
def complaints():
    q = Complaint.query.join(User, Complaint.user_id == User.id)

    if current_user.role == "citizen":
        q = q.filter(Complaint.user_id == current_user.id)
    elif current_user.role == "police":
        if current_user.officer_profile:
            q = q.filter(Complaint.assigned_officer_id == current_user.officer_profile.id)
        else:
            q = q.filter(Complaint.id == -1)

    complaint_id = request.args.get("complaint_id", "").strip()
    user_name = request.args.get("user_name", "").strip()
    location = request.args.get("location", "").strip()
    status = request.args.get("status", "").strip()
    crime_type = request.args.get("crime_type", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    if complaint_id:
        q = q.filter(Complaint.complaint_id.ilike(f"%{complaint_id}%"))
    if user_name:
        q = q.filter(User.full_name.ilike(f"%{user_name}%"))
    if location:
        q = q.filter(Complaint.location.ilike(f"%{location}%"))
    if status:
        q = q.filter(Complaint.status == status)
    if crime_type:
        q = q.filter(Complaint.crime_type == crime_type)
    if date_from:
        try:
            q = q.filter(Complaint.created_at >= datetime.strptime(date_from, "%Y-%m-%d"))
        except ValueError:
            pass
    if date_to:
        try:
            q = q.filter(Complaint.created_at <= datetime.strptime(date_to, "%Y-%m-%d"))
        except ValueError:
            pass

    rows = q.order_by(Complaint.created_at.desc()).all()
    officers = Officer.query.join(User).order_by(User.full_name).all()
    statuses = ["Pending", "Investigating", "Resolved", "Rejected"]
    crime_types = ["Theft", "Assault", "Fraud", "Vandalism", "Cyber Crime", "Other"]

    return render_template(
        "complaints.html",
        complaints=rows,
        officers=officers,
        statuses=statuses,
        crime_types=crime_types,
    )


@app.route("/complaints/<int:complaint_db_id>/update", methods=["POST"])
@login_required
@role_required("admin", "police")
def update_complaint(complaint_db_id):
    complaint = db.session.get(Complaint, complaint_db_id)
    if not complaint:
        flash("Complaint not found.", "danger")
        return redirect(url_for("complaints"))

    if current_user.role == "police":
        if not current_user.officer_profile:
            flash("Officer profile not found.", "danger")
            return redirect(url_for("complaints"))
        if complaint.assigned_officer_id not in (None, current_user.officer_profile.id):
            flash("You can only update your assigned cases.", "danger")
            return redirect(url_for("complaints"))

    new_status = request.form.get("status", complaint.status).strip()
    remarks = request.form.get("remarks", "").strip()
    officer_id = request.form.get("assigned_officer_id", "").strip()

    if new_status not in {"Pending", "Investigating", "Resolved", "Rejected"}:
        flash("Invalid complaint status.", "danger")
        return redirect(url_for("complaints"))

    complaint.status = new_status
    complaint.remarks = remarks or complaint.remarks

    if officer_id:
        try:
            officer_id_int = int(officer_id)
        except ValueError:
            flash("Invalid officer selected.", "danger")
            return redirect(url_for("complaints"))
        officer = db.session.get(Officer, officer_id_int)
        if officer:
            complaint.assigned_officer_id = officer.id
            create_notification(
                officer.user_id,
                "Case Assigned",
                f"You have been assigned complaint {complaint.complaint_id}.",
            )

    create_notification(
        complaint.user_id,
        "Complaint Status Updated",
        f"Complaint {complaint.complaint_id} status changed to {complaint.status}.",
    )
    db.session.commit()

    reporter = db.session.get(User, complaint.user_id)
    if reporter:
        send_email_notification(
            reporter,
            "Complaint Status Updated",
            f"Your complaint {complaint.complaint_id} is now {complaint.status}.",
        )

    flash("Complaint updated successfully.", "success")
    return redirect(url_for("complaints"))


@app.route("/notifications")
@login_required
def notifications():
    notes = (
        Notification.query.filter_by(user_id=current_user.id)
        .order_by(Notification.created_at.desc())
        .all()
    )
    return render_template("notifications.html", notifications=notes)


@app.route("/notifications/<int:note_id>/read", methods=["POST"])
@login_required
def mark_notification_read(note_id):
    note = db.session.get(Notification, note_id)
    if not note or note.user_id != current_user.id:
        flash("Notification not found.", "danger")
        return redirect(url_for("notifications"))
    note.is_read = True
    db.session.commit()
    return redirect(url_for("notifications"))


@app.route("/feedback/<int:complaint_db_id>", methods=["GET", "POST"])
@login_required
@role_required("citizen")
def feedback(complaint_db_id):
    complaint = db.session.get(Complaint, complaint_db_id)
    if not complaint or complaint.user_id != current_user.id:
        flash("Complaint not found.", "danger")
        return redirect(url_for("complaints"))
    if complaint.status != "Resolved":
        flash("Feedback can only be submitted after resolution.", "warning")
        return redirect(url_for("complaints"))

    existing = Feedback.query.filter_by(complaint_id=complaint.id, user_id=current_user.id).first()
    if request.method == "POST":
        try:
            rating = int(request.form.get("rating", "0"))
        except ValueError:
            rating = 0
        comments = request.form.get("comments", "").strip()
        if rating < 1 or rating > 5:
            flash("Rating must be between 1 and 5.", "danger")
            return redirect(url_for("feedback", complaint_db_id=complaint.id))
        if existing:
            existing.rating = rating
            existing.comments = comments
        else:
            db.session.add(
                Feedback(
                    complaint_id=complaint.id,
                    user_id=current_user.id,
                    rating=rating,
                    comments=comments or None,
                )
            )
        db.session.commit()
        flash("Feedback saved.", "success")
        return redirect(url_for("complaints"))

    return render_template("feedback.html", complaint=complaint, existing=existing)


@app.route("/feedback-analysis")
@login_required
@role_required("admin")
def feedback_analysis():
    rows = (
        db.session.query(Feedback.rating, func.count(Feedback.id))
        .group_by(Feedback.rating)
        .order_by(Feedback.rating)
        .all()
    )
    avg = db.session.query(func.avg(Feedback.rating)).scalar() or 0
    feedback_items = Feedback.query.order_by(Feedback.created_at.desc()).all()
    return render_template(
        "feedback_analysis.html",
        rating_labels=[str(r[0]) for r in rows],
        rating_data=[r[1] for r in rows],
        avg_rating=round(float(avg), 2),
        feedback_items=feedback_items,
    )


@app.route("/download-report")
@login_required
@role_required("admin", "police")
def download_report():
    complaints = Complaint.query.order_by(Complaint.created_at.desc()).all()

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 50
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(40, y, "Crime Report Summary")
    y -= 24
    pdf.setFont("Helvetica", 10)
    pdf.drawString(40, y, f"Generated on: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    y -= 20

    for c in complaints:
        line = f"{c.complaint_id} | {c.crime_type} | {c.location} | {c.status}"
        pdf.drawString(40, y, line[:110])
        y -= 16
        if y < 60:
            pdf.showPage()
            y = height - 50
            pdf.setFont("Helvetica", 10)

    pdf.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="crime_report_summary.pdf",
        mimetype="application/pdf",
    )


@app.route("/init-db")
def init_db():
    db.create_all()
    if not User.query.filter_by(email="admin@crime.local").first():
        admin = User(
            full_name="System Admin",
            email="admin@crime.local",
            password_hash=generate_password_hash("Admin@123"),
            role="admin",
        )
        db.session.add(admin)
    if not User.query.filter_by(email="police@crime.local").first():
        police = User(
            full_name="Duty Officer",
            email="police@crime.local",
            password_hash=generate_password_hash("Police@123"),
            role="police",
        )
        db.session.add(police)
        db.session.flush()
        if not Officer.query.filter_by(user_id=police.id).first():
            db.session.add(Officer(user_id=police.id, badge_number="BDG-00001", department="Central"))
    db.session.commit()
    return "Database initialized. Default users created if missing."


if __name__ == "__main__":
    os.makedirs("database", exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    with app.app_context():
        db.create_all()
    app.run(debug=True)
