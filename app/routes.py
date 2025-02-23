from flask import render_template, redirect, url_for, session
from app import app
from app.reading import read_db

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=["GET", "POST"])
def register():
    return render_template('form.html')


@app.route('/login', methods=["GET"])
def login():
    return render_template("login.html")


@app.route('/edit_user/<email>', methods=['GET'])
def edit_user(email):
    db = read_db("db.txt")
    user_info = db[email]
    dni = user_info.get('dni')

    return render_template('edit_user.html', user_data=user_info, email=email)

