from flask import Flask, request, jsonify, make_response
# from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'Th1s1ss3cr3t'


class User:
    def __init__(self, public_id, name, password, admin):
        self.public_id = public_id
        self.name = name
        self.password = password
        self.admin = admin

    id = 0
    public_id = 0
    name = ""
    password = ""
    admin = False


class Author:
    id = 0
    name = ""
    book = ""
    country = ""
    booker_prize = False
    user_id = 0


users = {}
authors = {}


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms="HS256")

            current_user = None

            for u in users.values():
                if u.public_id == data['public_id']:
                    current_user = u

            # users.query.filter_by(public_id=data['public_id']).first()

        except Exception as ex:

            return jsonify({'message': 'token is invalid', 'exception': ex})

        return f("uname", *args, **kwargs)

    return decorator


@app.route('/register', methods=['GET', 'POST'])
def signup_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    users[new_user.name] = new_user

    return jsonify({'message': 'registered successfully'})


@app.route('/login', methods=['GET', 'POST'])
def login_user():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    user = users.get(auth.username)

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})
        # return jsonify({'token': token.decode('UTF-8')})

    return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    print(current_user)
    return "yes"
    #return jsonify({'users': users.values()})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
