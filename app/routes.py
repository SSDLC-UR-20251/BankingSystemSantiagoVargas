from flask import request, render_template, redirect, url_for, session
from app import app
from app.encryption import decrypt_aes, ofuscar_dni
from app.reading import read_db


# app.secret_key = 'your_secret_key'

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/deposit', methods=['GET'])
def deposit():

    return render_template('deposit.html')


@app.route('/register', methods=["GET", "POST"])
def register():
    return render_template('form.html')


@app.route('/login', methods=["GET"])
def login():
    return render_template("login.html")


@app.route('/edit_user/<email>', methods=['POST', 'GET'])
def edit_user(email):

    db = read_db("db.txt")

    if email not in db:
        return redirect(url_for('records', message="Usuario no encontrado"))

    #  Verificar si el DNI está encriptado y desencriptarlo antes de mostrarlo
    dni_descifrado = ""
    if isinstance(db[email]["dni"], list):  # Si es una lista, significa que está encriptado
        dni_cifrado, nonce, clave = db[email]["dni"]
        try:
            clave = bytes.fromhex(clave) 
            dni_descifrado = decrypt_aes(dni_cifrado, nonce, clave).strip()  # Desencriptar correctamente
        except Exception as e:
            print(f" Error al desencriptar el DNI de {email}: {e}")
            dni_descifrado = "ERROR"
    else:
        dni_descifrado = db[email]["dni"]  # Si no está encriptado, usarlo directamente

    if request.method == 'GET':
        return render_template('edit_user.html', 
                               user_data=db[email], 
                               email=email, 
                               dni=dni_descifrado,  #  Pasamos el DNI ya desencriptado
                               darkmode=request.cookies.get('darkmode', 'light'))
        
    else:    
        user_info = db[email]
        return render_template('edit_user.html', user_data=user_info, email=email)


# Formulario de retiro
@app.route('/withdraw', methods=['GET'])
def withdraw():
    email = session.get('email')
    print(email)
    transactions = read_db("transaction.txt")
    current_balance = sum(float(t['balance']) for t in transactions.get(email, []))
    return render_template('withdraw.html', balance=current_balance)
