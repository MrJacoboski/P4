import string
import unittest
from io import StringIO
from pydoc import html
from random import random, choices, randint

from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import time
import itertools

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

def UserName(id):
    users = User.query.get(id)
    return users

# Алфавит для шифрования
ALPHABET = " ,.:(_)-0123456789АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(30), unique=True, nullable=False)
    secret = db.Column(db.String(30), nullable=False)

class Method(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    caption = db.Column(db.String(50), nullable=False)
    json_params = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    method_id = db.Column(db.Integer, db.ForeignKey('method.id'), nullable=True)
    data_in = db.Column(db.Text, nullable=False)
    params = db.Column(db.String(200), nullable=True)
    data_out = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    time_op = db.Column(db.Float, nullable=False)
    parent_id = db.Column(db.Integer, nullable=True)

# Вспомогательные функции для шифрования
def caesar_cipher(text, shift, decrypt=False):
    if decrypt:
        shift = -shift
    return ''.join(ALPHABET[(ALPHABET.index(c) + shift) % len(ALPHABET)] if c in ALPHABET else c for c in text)

def vigenere_cipher(text, key, decrypt=False):
    key = key.upper()
    key_indices = [ALPHABET.index(k) for k in key if k in ALPHABET]
    key_length = len(key_indices)
    result = []
    for i, char in enumerate(text):
        if char in ALPHABET:
            text_index = ALPHABET.index(char)
            key_index = key_indices[i % key_length]
            if decrypt:
                new_index = (text_index - key_index) % len(ALPHABET)
            else:
                new_index = (text_index + key_index) % len(ALPHABET)
            result.append(ALPHABET[new_index])
        else:
            result.append(char)
    return ''.join(result)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/users', methods=['POST'])
def add_user():
    login = request.form['login']
    secret = request.form['secret']
    if 3 <= len(login) <= 30 and 3 <= len(secret) <= 30:
        if User.query.filter_by(login=login).first():
            flash('User already exists!')
        else:
            new_user = User(login=login, secret=secret)
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully!')
    else:
        flash('Login и секрет должны быть от 3 до 30 символов.')
    return redirect(url_for('list_users'))

@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    useridList = []
    for user in users:
        useridList.append(user.login)
    return jsonify([{"login": user.login} for user in useridList]), 200

@app.route('/users/list', methods=['GET'])
def list_users():
    users = User.query.all()
    useridList =[]
    for user in users:
        useridList.append(user.login)
    return render_template('users.html', users=useridList)

@app.route('/add_user_form', methods=['GET'])
def add_user_form():
    return render_template('add_user.html')

@app.route('/methods', methods=['GET'])
def get_methods():
    methods = Method.query.all()
    return render_template('methods.html', methods=methods)

@app.route('/encrypt', methods=['GET'])
def encrypt_form():
    method_id = request.args.get('method_id')
    method = Method.query.get(method_id)
    if method:
        users = User.query.all()
        useridList = []
        for user in users:
            useridList.append(user.login)
        return render_template('encrypt.html', method=method, users=useridList)
    else:
        return redirect(url_for('get_methods'))

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.form
    user_id = data['user_id']
    method_id = data['method_id']
    action = data['action']
    data_in = data['data_in']
    parent_id = data.get('parent_id')
    params = {}

    user = User.query.get(1)
    method = Method.query.get(method_id)
    print(User.query)

    if user and method and len(data_in) <= 1000 :
        data_in_filtered = ''.join([c for c in data_in.upper() if c in ALPHABET])
        start_time = time.time()
        wrong = bool()
        for c in data_in.upper():
            if c not in ALPHABET:
                return redirect(url_for('encrypt'))
        if method.caption == 'Caesar':
            shift = int(data['shift'])
            params['shift'] = shift
            data_out = caesar_cipher(data_in_filtered, shift, decrypt=(action == 'decrypt'))
        elif method.caption == 'Vigenere':
            key = data['key']
            params['key'] = key
            data_out = vigenere_cipher(data_in_filtered, key, decrypt=(action == 'decrypt'))
        else:
            return jsonify({"message": "Invalid method"}), 400

        end_time = time.time()
        new_session = Session(
            user_id=user_id,
            method_id=method_id,
            data_in=data_in,
            params=str(params),
            data_out=data_out,
            status='completed',
            time_op=end_time - start_time,
            parent_id=parent_id
        )
        db.session.add(new_session)
        db.session.commit()
        return redirect(url_for('get_sessions'))
    else:
        return jsonify({"message": "Invalid input"}), 400

@app.route('/sessions', methods=['GET'])
def get_sessions():
    sessions = Session.query.all()
    return render_template('sessions.html', sessions=sessions)

@app.route('/sessions/<int:session_id>', methods=['GET'])
def get_session(session_id):
    session = Session.query.get(session_id)
    if session:
        return render_template('session.html', session=session)
    else:
        return jsonify({"message": "Session not found"}), 404

@app.route('/sessions/<int:session_id>', methods=['DELETE'])
def delete_session(session_id):
    session = Session.query.get(session_id)
    if session:
        secret = request.form['secret']
        user = User.query.get(session.user_id)
        if user and user.secret == secret:
            db.session.delete(session)
            db.session.commit()
            return jsonify({"message": "Сессия прошла успешно"}), 200
        else:
            return jsonify({"message": "Неправильно набран секрет"}), 400
    else:
        return jsonify({"message": "Сессия не найдена"}), 404

@app.route('/sessions/<int:session_id>/delete', methods=['POST'])
def delete_session_form(session_id):
    session = Session.query.get(session_id)
    if session:
        secret = request.form['secret']
        user = User.query.get(session.user_id)
        if user and user.secret == secret:
            db.session.delete(session)
            db.session.commit()
            return redirect(url_for('get_sessions'))
        else:
            return render_template('session.html', session=session, error="Invalid secret")
    else:
        return jsonify({"message": "Сессия не найдена"}), 404

@app.route('/hack_caesar', methods=['GET'])
def hack_caesar_form():
    users = User.query.all()
    useridList = []
    for user in users:
        useridList.append(user.login)
    return render_template('hack_caesar.html', users=useridList)

@app.route('/hack_caesar', methods=['POST'])
def hack_caesar():
    data = request.form
    user_id = data['user_id']
    data_in = data['data_in']
    keyword = data['keyword']
    parent_id = data.get('parent_id')

    user = User.query.get(1)

    if user and len(data_in) <= 1000:
        data_in_filtered = ''.join([c for c in data_in.upper() if c in ALPHABET])
        possible_results = []
        start_time = time.time()

        for shift in range(len(ALPHABET)):
            decrypted_text = caesar_cipher(data_in_filtered, shift, decrypt=True)
            if keyword.upper() in decrypted_text:
                possible_results.append({'shift': shift, 'decrypted_text': decrypted_text})

        end_time = time.time()
        new_session = Session(
            user_id=user_id,
            method_id="Caesar",
            data_in=data_in,
            status='completed',
            time_op=end_time - start_time,
            parent_id=parent_id
        )
        db.session.add(new_session)
        db.session.commit()
        return render_template('hack_results.html', results=possible_results, session_id=new_session.id)
    else:
        return jsonify({"message": "Invalid input"}), 400

@app.route('/hack_vigenere', methods=['GET'])
def hack_vigenere_form():
    users = User.query.all()
    useridList = []
    for user in users:
        useridList.append(user.login)
    return render_template('hack_vigenere.html', users=useridList)

@app.route('/hack_vigenere', methods=['POST'])
def hack_vigenere():
    data = request.form
    user_id = data['user_id']
    data_in = data['data_in']
    keyword = data['keyword']
    parent_id = data.get('parent_id')

    user = User.query.get(1)

    if user and len(data_in) <= 1000:
        data_in_filtered = ''.join([c for c in data_in.upper() if c in ALPHABET])
        possible_results = []
        start_time = time.time()

        key_lengths = range(3, 31)

        def generate_vigenere_keys():
            for key_length in key_lengths:
                for key_tuple in itertools.product(ALPHABET, repeat=key_length):
                    yield ''.join(key_tuple)

        for key in generate_vigenere_keys():
            decrypted_text = vigenere_cipher(data_in_filtered, key, decrypt=True)
            if keyword.upper() in decrypted_text:
                possible_results.append({'key': key, 'decrypted_text': decrypted_text})
                if len(possible_results) >= 10:
                    break
            if len(possible_results) >= 10:
                break

        end_time = time.time()
        new_session = Session(
            user_id=user_id,
            method_id="Vigenere",
            data_in=data_in,
            status='completed',
            time_op=end_time - start_time,
            parent_id=parent_id
        )
        db.session.add(new_session)
        db.session.commit()
        return render_template('hack_results.html', results=possible_results, session_id=new_session.id)
    else:
        return jsonify({"message": "Invalid input"}), 400

@app.route('/tests', methods=['GET'])
def run_tests():
    class EncryptionTests(unittest.TestCase):
        def setUp(self):
            self.app = app.test_client()
            self.app.testing = True
            self.random_text = ''.join(choices(string.ascii_uppercase + ALPHABET, k=20))
            self.random_shift = randint(1, len(ALPHABET) - 1)
            self.random_key = ''.join(choices(ALPHABET, k=5))
            self.keyword = 'КЛЮЧ'

        def test_caesar_cipher(self):
            encrypted_text = caesar_cipher(self.random_text, self.random_shift)
            decrypted_text = caesar_cipher(encrypted_text, self.random_shift, decrypt=True)
            self.assertEqual(decrypted_text, self.random_text)

        def test_vigenere_cipher(self):
            encrypted_text = vigenere_cipher(self.random_text, self.random_key)
            decrypted_text = vigenere_cipher(encrypted_text, self.random_key, decrypt=True)
            self.assertEqual(decrypted_text, self.random_text)

        def test_hack_caesar(self):
            encrypted_text = caesar_cipher(f'{self.random_text} {self.keyword}', self.random_shift)
            data = {
                'user_id': 1,  # Change this to a valid user ID or ensure user exists
                'data_in': encrypted_text,
                'keyword': self.keyword
            }
            response = self.app.post('/hack_caesar', data=data)
            self.assertEqual(response.status_code, 200)
            self.assertIn(self.keyword, response.get_data(as_text=True))

        def test_hack_vigenere(self):
            encrypted_text = vigenere_cipher(f'{self.random_text} {self.keyword}', self.random_key)
            data = {
                'user_id': 1,  # Change this to a valid user ID or ensure user exists
                'data_in': encrypted_text,
                'keyword': self.keyword
            }
            response = self.app.post('/hack_vigenere', data=data)
            self.assertEqual(response.status_code, 200)
            self.assertIn(self.keyword, response.get_data(as_text=True))

    suite = unittest.TestLoader().loadTestsFromTestCase(EncryptionTests)
    test_result = StringIO()
    unittest.TextTestRunner(stream=test_result, verbosity=2).run(suite)
    test_result_str = test_result.getvalue()

    test_result_str = html.escape(test_result_str).replace('\n', '<br>')

    return render_template('test_results.html', test_result=test_result_str)

if __name__ == '__main__':
    # Добавляем методы шифрования по умолчанию
    with app.app_context():
        db.create_all()
        if not Method.query.filter_by(caption='Caesar').first():
            db.session.add(Method(caption='Caesar', json_params='{"shift": "int"}', description='Шифр Цезаря'))
        if not Method.query.filter_by(caption='Vigenere').first():
            db.session.add(Method(caption='Vigenere', json_params='{"key": "str"}', description='Шифр Виженера'))
        db.session.commit()

    app.run(debug=True)