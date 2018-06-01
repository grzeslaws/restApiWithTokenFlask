from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config["SECRET_KEY"] = "thisissecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////Users/grzesiek/tests/flaskRestApi/data.db"

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]
            print(jwt.decode(token, "thisissecretkey"))

        if not token:
            jsonify({"message": "Token is missing!"})

        try:
            data = jwt.decode(
                token, app.config["SECRET_KEY"], algorithms=['HS256'])
            print(data)
            current_user = User.query.filter_by(
                public_id=data["public_id"]).first()
        except:
            return jsonify({"message": "Token is invalid!"}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route("/user", methods=["GET"])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({"message": "Cannoot perform that function!"})

    data = []
    users = User.query.all()

    if not users:
        return jsonify({"message": "No users found!"})

    for user in users:
        user_data = {}
        user_data["name"] = user.name
        user_data["password"] = user.password
        user_data["public_id"] = user.public_id
        user_data["admin"] = user.admin
        data.append(user_data)

    return jsonify({"users": data})


@app.route("/user/<public_id>", methods=["GET"])
def get_one_user(public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message": "No user found!"})

    user_data = {}
    user_data["name"] = user.name
    user_data["password"] = user.password
    user_data["public_id"] = user.public_id
    user_data["admin"] = user.admin
    return jsonify({"user": user_data})


@app.route("/user", methods=["POST"])
def create_user():

    data = request.get_json()
    hashed_password = generate_password_hash(data["password"], method="sha256")
    user = User(public_id=str(uuid.uuid4()),
                name=data["name"], password=hashed_password, admin=False)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "New user created!"})


@app.route("/user/<public_id>", methods=["PUT"])
def promote_user(public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message": "No user found!"})

    user.admin = True
    db.session.commit()

    return jsonify({"message": "User has been promoted!"})


@app.route("/user/<public_id>", methods=["DELETE"])
def delete_user(public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message": "No user found!"})

    db.session.delete(user)
    db.session.commit()

    return jsonify({"message": "User has been deleted!"})


@app.route("/login")
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response("Could not verify", 401, {"WWW-Authenticate": 'Basic realm="Logi requireed!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response("Could not verify", 401, {"WWW-Authenticate": 'Basic realm="Logi requireed!"'})

    if (check_password_hash(user.password, auth.password)):
        data = {"public_id": user.public_id,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=90)}
        token = jwt.encode(data, "thisissecretkey", 'HS256').decode('utf-8')

        return jsonify({"token": token})

    return make_response("Could not verify", 401, {"WWW-Authenticate": 'Basic realm="Logi requireed!"'})


@app.route("/todo", methods=["GET"])
def get_all_todo():
    todos = Todo.query.all()
    todos_return = []

    for item in todos:
        todo = {}
        todo["id"] = item.id
        todo["text"] = item.text
        todo["complete"] = item.complete
        todo["user_id"] = item.user_id
        todos_return.append(todo)

    return jsonify({"todos": todos_return})


@app.route("/todo", methods=["POST"])
@token_required
def add_todo(current_user):
    data = request.get_json()

    todo = Todo(text=data["text"], complete=data["complete"], user_id=current_user.public_id)
    db.session.add(todo)
    db.session.commit()
    return jsonify({"message": "Todo was created!"})


@app.route("/todo/<id>", methods=["PUT"])
def get_one_todo(id):

    data = request.get_json()
    todo = Todo.query.filter_by(id=id).first()

    if not todo:
        return jsonify({"message": "No todo found!"})

    todo.complete = True
    db.session.commit()

    return jsonify({"message": "Todo was changed!"})


@app.route("/todo/<id>", methods=["DELETE"])
def delete_todo(id):

    todo = Todo.query.filter_by(id=id).first()

    if not todo:
        return jsonify({"message": "No todo found!"})
    db.session.delete(todo)
    db.session.commit()

    return jsonify({"message": "Todo was deleted!"})


if __name__ == "__main__":
    app.run(debug=True)
