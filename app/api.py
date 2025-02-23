from datetime import datetime, timedelta
import time
from app.validation import *
from app.reading import *
from flask import request, jsonify, redirect, url_for, render_template, session, make_response
from app import app


# Variables globales
MAX_ATTEMPTS = 3  # Número máximo de intentos permitidos
BLOCK_TIME = 5  # Tiempo de bloqueo en minutos
users_status = {}  # Diccionario que guarda los intentos y tiempos de bloqueo de los usuarios


app.secret_key = 'your_secret_key'


@app.route('/api/users', methods=['POST'])
def create_record():
    data = request.form
    email = data.get('email')
    username = data.get('username')
    nombre = data.get('nombre')
    apellido = data.get('Apellidos')
    password = data.get('password')
    dni = data.get('dni')
    dob = data.get('dob')
    errores = []
    print(data)
    # Validaciones
    if not validate_email(email):
        errores.append("Email inválido")
    if not validate_pswd(password):
        errores.append("Contraseña inválida")
    if not validate_dob(dob):
        errores.append("Fecha de nacimiento inválida")
    if not validate_dni(dni):
        errores.append("DNI inválido")
    if not validate_user(username):
        errores.append("Usuario inválido")
    if not validate_name(nombre):
        errores.append("Nombre inválido")
    if not validate_name(apellido):
        errores.append("Apellido inválido")

    if errores:
        return render_template('form.html', error=errores)

    email = normalize_input(email)

    db = read_db("db.txt")
    db[email] = {
        'nombre': normalize_input(nombre),
        'apellido': normalize_input(apellido),
        'username': normalize_input(username),
        'password': normalize_input(password),
        "dni": dni,
        'dob': normalize_input(dob),
        "role":"admin"
    }

    write_db("db.txt", db)
    return redirect("/login")


# Endpoint para el login
@app.route('/api/login', methods=['POST'])
def api_login():
    email = normalize_input(request.form['email'])
    password = normalize_input(request.form['password'])

    # Comprobamos si el usuario está bloqueado
    error = None  # Aseguramos que la variable `error` esté definida
    if email in users_status:
        user_data = users_status[email]
        if user_data['tiempoBloqueo'] > datetime.now():
            # Si el usuario está bloqueado, mostrar mensaje de espera
            time_left = user_data['tiempoBloqueo'] - datetime.now()
            error = f"Cuenta bloqueada. Intenta nuevamente en {time_left.seconds // 60} minutos."
            return render_template('login.html', error=error)
    
    # Leer la base de datos (db.txt)
    db = read_db("db.txt")
    if email not in db:
        error = "Credenciales inválidas"
        return render_template('login.html', error=error)

    password_db = db.get(email)["password"]
    if "role" not in db[email]:
        db[email]["role"] = "user"
        write_db("db.txt", db)

    # Si la contraseña es correcta
    if password_db == password:
        # Restablecer los intentos fallidos en el diccionario
        if email in users_status:
            del users_status[email]
        session['role'] = db[email]['role'] # Almacenar el rol en la sesión
        session['email'] = email  # Guardar email en sesión para autorización
        return redirect(url_for('customer_menu'))
    
    # Si la contraseña es incorrecta
    else:
        # Registrar intento fallido
        if email not in users_status:
            users_status[email] = {"intentos": 0, "tiempoBloqueo": datetime.now()}
        
        users_status[email]["intentos"] += 1

        # Si el número de intentos supera el máximo, bloquear al usuario
        if users_status[email]["intentos"] >= MAX_ATTEMPTS:
            users_status[email]["tiempoBloqueo"] = datetime.now() + timedelta(minutes=BLOCK_TIME)
            error = f"Demasiados intentos fallidos. Tu cuenta está bloqueada por {BLOCK_TIME} minutos."
            return render_template('login.html', error=error)
        else:
            error = "Credenciales inválidas"
            return render_template('login.html', error=error)
        

# Página principal del menú del cliente
@app.route('/customer_menu')
def customer_menu():

    db = read_db("db.txt")

    transactions = read_db("transaction.txt")
    current_balance = 100
    last_transactions = []
    message = request.args.get('message', '')
    error = request.args.get('error', 'false').lower() == 'true'
    return render_template('customer_menu.html',
                           message=message,
                           nombre="",
                           balance=current_balance,
                           last_transactions=last_transactions,
                           error=error,)


# Endpoint para leer un registro
@app.route('/records', methods=['GET'])
def read_record():
    if 'role' not in session:
        return redirect(url_for('api_login'))
    
    db = read_db("db.txt")
    message = request.args.get('message', '')
    
    if session['role'] == 'admin':
        return render_template('records.html', users=db, role=session.get('role', 'user'), message=message)
    else:
        user_data = {session['email']: db.get(session['email'], {})}
        return render_template('records.html', users=user_data, role=session.get('role', 'user'), message=message)
    
# Endpoint para ELIMINAR un registro (solo Admin)
@app.route('/delete_user/<email>', methods=['POST'])
def delete_user(email):
    if 'role' not in session or session['role'] != 'admin':
        return jsonify({"error": "Acceso denegado"}), 403
    
    db = read_db("db.txt")
    if email in db:
        del db[email]
        write_db("db.txt", db)
        return redirect(url_for('read_record', message="Usuario eliminado correctamente"))
    
    return jsonify({"error": "Usuario no encontrado"}), 404

@app.route('/update_user/<email>', methods=['POST'])
def update_user(email):
    # Leer la base de datos de usuarios
    db = read_db("db.txt")

    username = request.form['username']
    dni = request.form['dni']
    dob = request.form['dob']
    nombre = request.form['nombre']
    apellido = request.form['apellido']
    errores = []

    if not validate_dob(dob):
        errores.append("Fecha de nacimiento inválida")
    if not validate_dni(dni):
        errores.append("DNI inválido")
    if not validate_user(username):
        errores.append("Usuario inválido")
    if not validate_name(nombre):
        errores.append("Nombre inválido")
    if not validate_name(apellido):
        errores.append("Apellido inválido")

    if errores:
        return render_template('edit_user.html',
                               user_data=db[email],
                               email=email,
                               error=errores)


    db[email]['username'] = normalize_input(username)
    db[email]['nombre'] = normalize_input(nombre)
    db[email]['apellido'] = normalize_input(apellido)
    db[email]['dni'] = dni
    db[email]['dob'] = normalize_input(dob)


    write_db("db.txt", db)
    

    # Redirigir al usuario a la página de records con un mensaje de éxito
    return redirect(url_for('read_record', message="Información actualizada correctamente"))

