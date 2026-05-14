from flask import Flask, render_template, request, redirect, session

from flask_bcrypt import Bcrypt

from detector import check_phishing
from database import cursor, db

app = Flask(__name__)

# Secret key
app.secret_key = "supersecretkey"

# Password hashing
bcrypt = Bcrypt(app)


# ======================================
# DEFAULT ROUTE
# Opens login page first
# ======================================
@app.route("/")
def start():

    # If already logged in
    if "user" in session:
        return redirect("/home")

    return redirect("/login")


# ======================================
# HOME PAGE
# ======================================
@app.route("/home", methods=["GET", "POST"])
def home():

    # User must login first
    if "user" not in session:
        return redirect("/login")

    result = ""

    if request.method == "POST":

        url = request.form["url"]

        # Analyze URL
        result = check_phishing(url)

        # Save scan history
        sql = """
        INSERT INTO scan_history (url, result)
        VALUES (%s, %s)
        """

        values = (url, result)

        cursor.execute(sql, values)

        db.commit()

    return render_template(
        "index.html",
        result=result,
        user=session.get("user"),
        role=session.get("role")
    )


# ======================================
# HISTORY PAGE
# ======================================
@app.route("/history")
def history():

    if "user" not in session:
        return redirect("/login")

    cursor.execute("""
        SELECT *
        FROM scan_history
        ORDER BY scan_date DESC
    """)

    data = cursor.fetchall()

    return render_template(
        "history.html",
        data=data
    )


# ======================================
# DASHBOARD PAGE
# ======================================
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
    """)

    total_scans = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE result LIKE '%PHISHING%'
    """)

    phishing_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE result LIKE '%SUSPICIOUS%'
    """)

    suspicious_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE result LIKE '%LEGITIMATE%'
    """)

    legitimate_count = cursor.fetchone()[0]

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        phishing_count=phishing_count,
        suspicious_count=suspicious_count,
        legitimate_count=legitimate_count
    )


# ======================================
# REGISTER PAGE
# ======================================
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        sql = """
        INSERT INTO users (username, email, password)
        VALUES (%s, %s, %s)
        """

        values = (
            username,
            email,
            hashed_password
        )

        cursor.execute(sql, values)

        db.commit()

        return redirect("/login")

    return render_template("register.html")


# ======================================
# LOGIN PAGE
# ======================================
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        sql = """
        SELECT *
        FROM users
        WHERE email = %s
        """

        cursor.execute(sql, (email,))

        user = cursor.fetchone()

        if user:

            # Verify password
            if bcrypt.check_password_hash(user[3], password):

                session["user"] = user[1]
                session["role"] = user[4]

                return redirect("/home")

    return render_template("login.html")


# ======================================
# LOGOUT
# ======================================
@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# ======================================
# ADMIN PANEL
# ======================================
@app.route("/admin")
def admin():

    # User must login first
    if "user" not in session:
        return redirect("/login")

    # Only admin allowed
    if session.get("role") != "admin":
        return "ACCESS DENIED"

    # Get users
    cursor.execute("""
        SELECT id, username, email, role
        FROM users
    """)

    users = cursor.fetchall()

    # Get scans
    cursor.execute("""
        SELECT *
        FROM scan_history
        ORDER BY scan_date DESC
    """)

    scans = cursor.fetchall()

    return render_template(
        "admin.html",
        users=users,
        scans=scans
    )


# ======================================
# START APPLICATION
# ======================================
if __name__ == "__main__":
    app.run(debug=True)
