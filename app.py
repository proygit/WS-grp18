from flask import Flask, request, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from flask import Flask, request, redirect, jsonify
import sqlite3
import re
import json
from hashids import Hashids
from time import time
import random

SALT = "Very $$**^91@ sEcret SaaaLltT"  # Salt used to create hashes
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
# Selects a row by matching the link


def select_by_link(link, cur):
    data = cur.execute("SELECT * FROM urls WHERE link=?", (link, )).fetchone()
    return data


# Selects a row by matching the id
def select_by_id(id, cur):
    data = cur.execute("SELECT * FROM urls WHERE id=?", (id, )).fetchone()
    return data

# Selects a row by matching the username


def select_by_username(username, cur):
    print(f"Selecting user with username: {username}")
    data = cur.execute("SELECT * FROM users WHERE username=?",
                       (username,)).fetchone()
    print(f"Selected user data: {data}")
    return data


def select_password_by_username(username, cursor):
    print(f"Selecting password for user: {username}")
    data = cursor.execute(
        "SELECT password FROM users WHERE username=?", (username,)).fetchone()
    if data:
        print(f"Selected password: {data['password']}")
        return data['password']
    else:
        return None


def update_password(username, new_password, cur):
    print(f"Updating password for user with username: {username}")
    hashed_password = generate_password_hash(new_password)
    query = "UPDATE users SET password=? WHERE username=?"
    cur.execute(query, (username, hashed_password))
    cur.connection.commit()
    print("Password updated successfully!")
    cur.close()

# Regex from Django open source code (https://github.com/django/django/blob/stable/1.3.x/django/core/validators.py/#L45)


def is_valid_url(url):
    regex = re.compile(
        r'^(?:http)s?://'  # scheme
        # domain...
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    return bool(regex.match(url))


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']
            print(token)
        if not token:
            return jsonify({'message': 'Access token is missing'}), 403
        try:
            print(token)
            data = jwt.decode(
                token, app.config['SECRET_KEY'], algorithms=["HS256"])
            username = data['username']
            #password = data['password']
            con = get_db_connection()
            current_user = select_by_username(username, con.cursor())
            con.close()
        except:
            return jsonify({'message': 'Token is invalid'}), 403
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
        return jsonify({"error": "User already exists"}), 409

    # Insert user into the DB
    insert_user(username, password)
    token = jwt.encode({'username': username, 'password': password, 'exp': datetime.datetime.utcnow(
    ) + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")
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
    token = jwt.encode({'username': username, 'password': password, 'exp': datetime.datetime.utcnow(
    ) + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")

    # Return token in the response
    return jsonify({'message': 'login successful', 'token': token})


@app.route('/changePassword', methods=['PUT'])
@token_required
def changePassword(current_user):
    token = request.headers['x-access-tokens']
    if not token:
        return jsonify({'message': 'Access token is missing'}), 403
    try:
        data = jwt.decode(
            token, app.config['SECRET_KEY'], algorithms=["HS256"])
        # Throw 400 error when no username and password is provided
        if not request.json or "username" not in request.json or "password" not in request.json or "new_password" not in request.json:
            return jsonify({"error": "username, password, and new_password not found in request"}), 400

        username = data['username']
        username_given = request.json["username"]
        old_password = request.json["password"]
        new_password = request.json["new_password"]
        con = get_db_connection()
        current_user_db = select_by_username(username, con.cursor())

        if username != current_user_db['username'] or username != username_given or not check_password_hash(current_user_db['password'], old_password):
            return jsonify({"error": "Forbidden ,Invalid username or password"}), 403
        else:
            update_password(username, new_password, con.cursor())
            return jsonify({'message': f'Welcome {username_given}! Password is updated.'}), 200

    except:
        return jsonify({'message': 'Token is invalid'}), 403


@app.route('/getdetails', methods=['GET'])
@token_required
def get_user(current_user):
    token = request.headers['x-access-tokens']
    data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    username = data['username']
    password = data['password']
    con = get_db_connection()
    current_user = select_by_username(username, con.cursor())
    hashedPasswrd = select_password_by_username(username, con.cursor())
    check = check_password_hash(hashedPasswrd, password)
    con.close()
    return jsonify({'message': f'Welcome {current_user["username"]}!', 'password': hashedPasswrd, 'Result': check})


# URL shortner methods
# Creates a new (id, short url, orignal url) tuple if possible
@app.route('/', methods=['POST'])
@token_required
def shorten_link(current_user):
    token = request.headers.get('x-access-tokens')
    if not token:
        return jsonify({'message': 'Access token is missing'}), 403
    try:
        data = jwt.decode(
            token, app.config['SECRET_KEY'], algorithms=["HS256"])

        # Throw 400 error when no link is provided
        if not request.data or not request.json or "link" not in request.json:
            return jsonify({"error": "no url found in request"}), 400

        # Retrieve link from the API request body
        link = request.json["link"]

        # Throw 400 error if the link is not valid
        if not is_valid_url(link):
            return jsonify({"error": "URL is not valid"}), 400

        # Connect to DB
        con = get_db_connection()
        cur = con.cursor()

        # If link exists in the DB, return data
        data = select_by_link(link, cur)
        if data:
            return jsonify({"short_url": data["short_url"], "id": data["id"]}), 200

        # Create new short url for the link
        number = int(round(time() * 1000)) + random.randint(0, 1e8)
        hashids = Hashids(min_length=8, salt=SALT)
        hashid = hashids.encode(number)

        # Insert into the DB
        query = "INSERT INTO urls (link, short_url) VALUES (?, ?)"
        data = cur.execute(query, (link, hashid))
        con.commit()
        cur.close()
        con.close()

        # Return created url and id in DB
        return jsonify({"short_url": hashid, "id": data.lastrowid}), 201

    except:
        return jsonify({'message': 'Token is invalid'}), 403


@app.route('/', methods=['GET'])
@token_required
def get_all(current_user):
    token = request.headers.get('x-access-tokens')
    if not token:
        return jsonify({'message': 'Access token is missing'}), 403

    try:
        # Connect to DB
        con = get_db_connection()
        cur = con.cursor()

        # Get all rows from DB
        query = "SELECT * FROM urls"
        cur.execute(query)
        data = cur.fetchall()

        # Close DB
        cur.close()
        con.close()

        # Return data
        return json.dumps([dict(ix) for ix in data]), 200

    except:
        return jsonify({'message': 'Token is invalid'}), 403


# Responds with error code when attempt to request DELETE to path "/"
@app.route('/',  methods=['DELETE'])
@token_required
def delete(current_user):
    token = request.headers.get('x-access-tokens')
    if not token:
        return jsonify({'message': 'Access token is missing'}), 403

    try:

        return jsonify({"error": "not found"}), 404

    except:
        return jsonify({'message': 'Token is invalid'}), 403
# Redirects to a website associated with a given id if possible


@app.route('/<id>',  methods=['GET'])
@token_required
def get_id(current_user):
    token = request.headers.get('x-access-tokens')
    if not token:
        return jsonify({'message': 'Access token is missing'}), 403
    # Throw 400 error when no username and password is provided
    if not request.json or "id" not in request.json :
        return jsonify({"error": "id to look up is not provided"}), 400

    
    try:
        id = request.json["id"]
        # Conect to DB
        con = get_db_connection()
        cur = con.cursor()

        # Get row with matching id
        data = select_by_id(id, cur)

        # Close DB
        cur.close()
        con.close()

        # Throw 404 error if id is not found in DB
        if not data:
            return jsonify({"error": "No data found"}), 404

        # Redirect to the original link if id found in DB
        return redirect(data["link"], code=301)

    except:
        return jsonify({'message': 'Token is invalid'}), 403

# Updates the associated original url of the id if possible


@app.route('/<id>', methods=['PUT'])
@token_required
def update_id(id,current_user):
    token = request.headers.get('x-access-tokens')
    if not token:
        return jsonify({'message': 'Access token is missing'}), 403

    try:
        # Throw 400 error if a link is not provided
        if not request.data or not request.json or not request.json["link"]:
            return jsonify({"error": "no url is found in request."}), 400

        link = request.json["link"]

        # Connect to DB
        con = get_db_connection()
        cur = con.cursor()

        # Throw 400 error if the link is not valid
        if not is_valid_url(link):
            return jsonify({"response": "url is not valid in request."}), 400

        # Update the link in the DB
        query = "UPDATE urls SET link=? WHERE id=?"
        cur.execute(query, (link, id))
        con.commit()

        # Close DB
        cur.close()
        con.close()

        # Return 200 if a row was updated
        if cur.rowcount:
            return jsonify({"response": "updated."}), 200

        # Throw 404 error if id was not found in DB
        return jsonify({"response": "id not found in table."}), 404

    except:
        return jsonify({'message': 'Token is invalid'}), 403

# Deletes the row with matching id if possible


@app.route('/<id>',  methods=['DELETE'])
@token_required
def delete_id(id,current_user):
    token = request.headers.get('x-access-tokens')
    if not token:
        return jsonify({'message': 'Access token is missing'}), 403

    try:
        # connect to DB
        con = get_db_connection()
        cur = con.cursor()

        # Delete row with match id
        query = "Delete FROM urls WHERE id = ?"
        cur.execute(query, (id, ))
        con.commit()

        # Close DB
        cur.close()
        con.close()

        # Return 204 status if a row was deleted
        if cur.rowcount:
            return jsonify({"response": "deleted."}), 204

        # Throw 404 error if id was not found in DB
        return jsonify({"response": "id not found in table."}), 404
    except:
        return jsonify({'message': 'Token is invalid'}), 403


# Deletes all rows present in the DB
@app.route('/deleteAllUrls', methods=['DELETE'])
@token_required
def delete_all(current_user):
    token = request.headers.get('x-access-tokens')
    if not token:
        return jsonify({'message': 'Access token is missing'}), 403

    try:
        # connect to DB
        con = get_db_connection()
        cur = con.cursor()

        # Delete all rows in DB
        query = "Delete FROM urls;"
        cur.execute(query)
        con.commit()

        # Close DB
        cur.close()
        con.close()

        # Return 204 status if succesfully deleted
        if cur.rowcount:
            return jsonify({"response": "all rows deleted."}), 204
        # DB is already empty
        return jsonify({"response": "id not found in table."}), 200
    except:
        return jsonify({'message': 'Token is invalid'}), 403

# Start flask app automatically when run with python
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
