import math
from dataclasses import dataclass
from datetime import timedelta

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import hashlib
from flask_cors import CORS

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'alksjdfasjdfopijasdfopijIOPJKDIOPKAdpjoiAJDIOJsd'
app.config['JWT_VERIFY_SUB'] = False
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=30) #simplification to use without jwt refresh токена

db = SQLAlchemy(app)
CORS(app)
jwt = JWTManager(app)

@dataclass
class Task(db.Model):
    id: int
    username: str
    email: str
    description: str
    completed: bool


    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    completed = db.Column(db.Boolean, default=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

@app.route('/tasks', methods=['GET'])
def get_tasks():
    sort_by = request.args.get('sort_by', 'id')
    page = int(request.args.get('page', 1))
    per_page = 3
    tasks = Task.query.order_by(getattr(Task, sort_by)).paginate(page=page, per_page=per_page, error_out=False).items
    return jsonify({
        'tasks': tasks,
        'pages': math.ceil(Task.query.count() / per_page)
    })

@app.route('/tasks', methods=['POST'])
def create_task():
    data = request.json
    new_task = Task(username=data['username'], email=data['email'], description=data['description'])
    db.session.add(new_task)
    db.session.commit()
    return jsonify({"message": "Task created successfully"}), 201

@app.route('/tasks/<int:task_id>', methods=['PUT'])
@jwt_required()
def update_task(task_id):
    current_user = User.query.filter_by(username=get_jwt_identity().get('username')).one_or_none()
    if current_user.is_admin:
        task = Task.query.get_or_404(task_id)
        data = request.json
        task.description = data.get('description', task.description)
        task.completed = data.get('completed', task.completed)
        db.session.commit()
        return jsonify({"message": "Task updated successfully"})
    return jsonify({"error": "Invalid rights"}), 401

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and user.password_hash == hashlib.sha256(data['password'].encode()).hexdigest():
        access_token = create_access_token(identity={'username': user.username})
        return jsonify(access_token=access_token)
    return jsonify({"error": "Invalid credentials"}), 401

@app.cli.command('create-admin')
def create_admin():
    db.create_all()
    username = input('Enter admin username: ')
    password = input('Enter admin password: ')
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    new_admin = User(username=username, password_hash=password_hash, is_admin=True)
    db.session.add(new_admin)
    db.session.commit()
    print(f"Admin {username} created successfully.")

if __name__ == '__main__':
    app.run(debug=True)
