from flask import Flask, jsonify, request
from config import Config
from extensions import db
import requests
from models import CovidStat, User
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
from utils import role_required
import logging
from logging.handlers import RotatingFileHandler


app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)


app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "dev-jwt-secret")
jwt = JWTManager(app)

# ---------- ROUTES ---------- #

# ROOT / HOME ROUTE
@app.route("/")
def home():
      return """
    <h1>Week 3 Assignment - Backend Development </h1>
    <p>Try the endpoints:</p>
    <ul>
        <li><a href="/covid">Covid Data </a> – view all saved COVID entries (GET)</li>
        <li><a href="/covid/fetch">/covid/fetch</a> – fetch live COVID stats & save to DB (GET)</li>
    </ul>
    """


@app.route("/covid/fetch", methods=["GET"])
def fetch_covid_data():
    url = "https://disease.sh/v3/covid-19/countries/USA"
    response = requests.get(url)

    if response.status_code != 200:
        return jsonify({"error": "Failed to fetch data"}), response.status_code

    data = response.json()

    # validate
    if not validate_covid_data(data):
        return jsonify({"error": "Invalid data format"}), 400

    # save to DB
    covid_stat = CovidStat(
        country=data["country"],
        cases=data["cases"],
        deaths=data["deaths"],
        recovered=data["recovered"],
        active=data["active"]
    )
    db.session.add(covid_stat)
    db.session.commit()

    return jsonify({"message": "Data fetched & saved", "data": data})


def validate_covid_data(data):
    required_fields = ["cases", "deaths", "recovered", "active", "country"]
    for field in required_fields:
        if field not in data:
            return False
        if not isinstance(data[field], (int, str)):
            return False
    return True


# ---------- CRUD ENDPOINTS ---------- #

# CREATE
@app.route("/covid", methods=["POST"])
@jwt_required()
def add_covid_stat():
    data = request.get_json()
    covid_stat = CovidStat(
        country=data["country"],
        cases=data["cases"],
        deaths=data["deaths"],
        recovered=data["recovered"],
        active=data["active"]
    )
    db.session.add(covid_stat)
    db.session.commit()
    return jsonify({"message": "Record added", "id": covid_stat.id}), 201


# READ (all records)
@app.route("/covid", methods=["GET"])
def get_all_covid():
    stats = CovidStat.query.all()
    return jsonify([{
        "id": s.id,
        "country": s.country,
        "cases": s.cases,
        "deaths": s.deaths,
        "recovered": s.recovered,
        "active": s.active
    } for s in stats])


# UPDATE
@app.route("/covid/<int:id>", methods=["PUT"])
def update_covid(id):
    stat = CovidStat.query.get_or_404(id)
    data = request.get_json()
    stat.country = data.get("country", stat.country)
    stat.cases = data.get("cases", stat.cases)
    stat.deaths = data.get("deaths", stat.deaths)
    stat.recovered = data.get("recovered", stat.recovered)
    stat.active = data.get("active", stat.active)
    db.session.commit()
    return jsonify({"message": "Record updated"})


# DELETE
@app.route("/covid/<int:id>", methods=["DELETE"])
@role_required("admin")
def delete_covid(id):
    stat = CovidStat.query.get_or_404(id)
    db.session.delete(stat)
    db.session.commit()
    return jsonify({"message": "Record deleted"})


# ---------- AUTH ---------- #

@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"msg": "username and password required"}), 400
    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"msg": "username already exists"}), 409
    user = User(username=data["username"], email=data.get("email"))
    user.set_password(data["password"])
    db.session.add(user)
    db.session.commit()
    return jsonify({"msg": "user created"}), 201


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"msg": "username and password required"}), 400
    user = User.query.filter_by(username=data["username"]).first()
    if not user or not user.check_password(data["password"]):
        return jsonify({"msg": "bad username/password"}), 401
    access_token = create_access_token(identity={"id": user.id, "role": user.role})
    return jsonify(access_token=access_token), 200


# ---------- LOGGING & ERRORS ---------- #

# Logging
handler = RotatingFileHandler('week3.log', maxBytes=1000000, backupCount=3)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

# Error handlers
@app.errorhandler(400)
def bad_request(e):
    app.logger.warning(f"400: {e}")
    return jsonify({"error":"bad request"}), 400

@app.errorhandler(401)
def unauthorized(e):
    app.logger.warning(f"401: {e}")
    return jsonify({"error":"unauthorized"}), 401

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error":"not found"}), 404

@app.errorhandler(500)
def server_error(e):
    app.logger.error(f"500: {e}", exc_info=True)
    return jsonify({"error":"internal server error"}), 500


# ---------- MAIN ---------- #
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
