from flask import Flask, request, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Ktr9xIBj1ZP-S8GM3mYKdSToiT2tZPOevIh2wX_YVd8'

# Mapping function for sqlite3 to return rows as dictionary
def dict_factory(cursor, row):
    fields = [column[0] for column in cursor.description]
    return {key: value for key, value in zip(fields, row)}

# Creates connection to DB
def get_db_connection():
    con = sqlite3.connect('database.db')
    con.row_factory = dict_factory
    return con

# function to insert data into users table
def insert_user(username, password):
    con = get_db_connection()
    cur = con.cursor()
    hashed_password = generate_password_hash(password)
    query = "INSERT INTO users (username, password) VALUES (?, ?)"
    cur.execute(query, (username, hashed_password))
    con.commit()
    cur.close()
    con.close()

# Selects a row by matching the username
def select_by_username(username, cur):
    print(f"Selecting user with username: {username}")
    data = cur.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    print(f"Selected user data: {data}")
    return data

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']
            print(token)
        if not token:
            return jsonify({'message': 'a valid token is missing'})
        try:
            print(token)
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            username = data['username']
            #password = data['password']
            con = get_db_connection()
            current_user = select_by_username(username, con.cursor())
            con.close()
        except:
            return jsonify({'message': 'token is invalid'})
        return f(current_user, *args, **kwargs)
    return decorator

@app.route('/newuser', methods=['POST'])
def new_user():
    # Throw 400 error when no username and password is provided
    if not request.json or "username" not in request.json or "password" not in request.json:
        return jsonify({"error": "username and/or password not found in request"}), 400

    # Retrieve username and password from the API request body
    username = request.json["username"]
    password = request.json["password"]

    # If user exists in the DB, return data
    con = get_db_connection()
    data = select_by_username(username, con.cursor())
    con.close()
    if data:
        return jsonify({"error": "User already exists"}), 400

    # Insert user into the DB
    insert_user(username, password)
    token = jwt.encode({'username': username, 'password': password, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")
    return jsonify({'message': 'registration successful', 'token': token})

@app.route('/trylogin', methods=['POST'])
def login():
    # Throw 400 error when no username and password is provided
    if not request.json or "username" not in request.json or "password" not in request.json:
        return jsonify({"error": "username and/or password not found in request"}), 400

    # Retrieve username and password from the API request body
    username = request.json["username"]
    password = request.json["password"]

    # Check if the user exists in the DB and the password is correct
    con = get_db_connection()
    data = select_by_username(username, con.cursor())
    con.close()
    if not data or not check_password_hash(data['password'], password):
        return jsonify({"error": "Invalid username or password"}), 401

    # Generate token with a 30-minute expiration time
    token = jwt.encode({'username': username, 'password': password, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")

    # Return token in the response
    return jsonify({'message': 'login successful', 'token': token})
import jwt
@app.route('/getdetails')
@token_required
def get_user(current_user):
    token = request.headers['x-access-tokens']
    data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    username = data['username']
    con = get_db_connection()
    current_user = select_by_username(username, con.cursor())
    con.close()
    return jsonify({'message': f'Welcome {current_user["username"]}!'})

# Start flask app automatically when run with python
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
