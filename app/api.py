from datetime import datetime, timedelta
from flask import Flask
import time
from app.validation import *
from app.reading import *
from flask import request, jsonify, redirect, url_for, render_template, session, make_response, g
from app import app
from app.encryption import *
from functools import wraps


login_attempts = {}
MAX_ATTEMPTS = 3
BLOCK_TIME = 300  # 5 minutos en segundos
clave = get_random_bytes(16)
app.secret_key = 'your_secret_key'
# Configurar la expiración de sesión después de 5 minutos de inactividad
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)



def login_required(f):
    """ Decorador para verificar si el usuario tiene una sesión activa. """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:  # Verifica si el usuario está autenticado
            return redirect(url_for('api_login', error="Por favor, inicia sesión primero."))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def validar_sesion():
    rutas_permitidas = ['/api/login', '/api/users', '/logout', '/static', '/register']
    
    #  Usar `request.path.startswith()` para evitar errores con subrutas
    if any(request.path.startswith(ruta) for ruta in rutas_permitidas):
        return  

    if 'email' in session:
        session.permanent = True  
        session.modified = True  
    else:
        return redirect(url_for('api_login', error="Tu sesión ha expirado. Inicia sesión nuevamente."))

    g.darkmode = request.cookies.get('darkmode', 'light')


@app.context_processor
def inject_darkmode():
    return dict(darkmode=g.get('darkmode', 'light'))


@app.route('/api/users', methods=['GET', 'POST'])
def create_record():
    if request.method == 'GET':
        return render_template('register.html')  # Mostrar el formulario de registro

    data = request.form
    email = data.get('email')
    username = data.get('username')
    nombre = data.get('nombre')
    apellido = data.get('Apellidos')
    password = data.get('password')
    dni = data.get('dni')
    dob = data.get('dob')
    errores = []
    
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
    hashed_pwd, salt = hash_with_salt(normalize_input(password))
    dni_aes, nonce = encrypt_aes(str(dni), clave)
    dni_cifrado = [dni_aes, nonce, clave.hex()]  # Guardar el dni cifrado y el nonce
    
    db = read_db("db.txt")
    db[email] = {
        'nombre': normalize_input(nombre),
        'apellido': normalize_input(apellido),
        'username': normalize_input(username),
        'password': hashed_pwd,
        "password_salt": salt,
        "dni": dni_cifrado,
        'dob': normalize_input(dob),
        "role": "admin"
    }

    write_db("db.txt", db)
    return redirect("/login")


# Endpoint para el login
@app.route('/api/login', methods=['GET', 'POST'])
def api_login():
    if request.method == 'GET':
        return render_template('login.html')  # Mostrar la página de login

    # Si es POST, obtener los valores del formulario de forma segura
    email = normalize_input(request.form.get('email', ''))  # Si no existe, devuelve ''
    password = normalize_input(request.form.get('password', ''))

    if not email or not password:  # Validar que los campos no estén vacíos
        error = "Debe ingresar email y contraseña."
        return render_template('login.html', error=error)

    db = read_db("db.txt")
    if email not in db:
        error = "Credenciales inválidas"
        return render_template('login.html', error=error)

    # Verificar si el usuario está bloqueado
    if email in login_attempts and login_attempts[email]['blocked_until'] > time.time():
        block_time_remaining = int((login_attempts[email]['blocked_until'] - time.time()) / 60)
        error = f"Cuenta bloqueada. Intenta nuevamente en {block_time_remaining} minutos."
        return render_template('login.html', error=error)

    password_db = db[email].get("password", "")
    salt_db = db[email].get("password_salt", "")

    if compare_salt(password, password_db, salt_db):
        login_attempts[email] = {'attempts': 0, 'blocked_until': 0}

        session['email'] = email
        session['role'] = db[email].get('role', 'usuario')  # Si no tiene rol, asignar 'usuario'

        return redirect(url_for('customer_menu'))
    else:
        if email not in login_attempts:
            login_attempts[email] = {'attempts': 0, 'blocked_until': 0}

        login_attempts[email]['attempts'] += 1

        if login_attempts[email]['attempts'] >= MAX_ATTEMPTS:
            login_attempts[email]['blocked_until'] = time.time() + BLOCK_TIME
            error = f"Se han excedido los intentos permitidos. Cuenta bloqueada por {BLOCK_TIME // 60} minutos."
        else:
            remaining_attempts = MAX_ATTEMPTS - login_attempts[email]['attempts']
            error = f"Credenciales incorrectas. Tienes {remaining_attempts} intentos restantes."

        return render_template('login.html', error=error)




# Página principal del menú del cliente
@app.route('/customer_menu')
@login_required
def customer_menu():
    if 'email' not in session:
        # Redirigir a la página de inicio de sesión si el usuario no está autenticado
        error_msg = "Por favor, inicia sesión para acceder a esta página."
        return render_template('login.html', error=error_msg)

    email = session.get('email')
    db = read_db("db.txt")
    transactions = read_db("transaction.txt")
    current_balance = sum(float(t['balance']) for t in transactions.get(email, []))
    last_transactions = transactions.get(email, [])[-5:]
    message = request.args.get('message', '')
    error = request.args.get('error', 'false').lower() == 'true'
    return render_template('customer_menu.html',
                           message=message,
                           nombre=db.get(email)['nombre'],
                           balance=current_balance,
                           last_transactions=last_transactions,
                           error=error)


# Endpoint para leer un registro
@app.route('/records', methods=['GET'])
@login_required
def read_record():
    db = read_db("db.txt")
    message = request.args.get('message', '')
    user_email = session.get('email')  # Obtener el email del usuario autenticado
    user_role = session.get('role')  # Obtener el rol del usuario autenticado

    users_display = {}
    updated = False  # Para saber si necesitamos actualizar la base de datos

    for email, user in db.items():
        global clave # Clave global para desencriptar DNI
        try:
            #  Verificar si el DNI está encriptado y desencriptarlo
            dni_descifrado = ""
            if isinstance(user["dni"], list):  # Si es una lista, está encriptado
                if len(user["dni"]) == 2:  # Si solo tiene DNI cifrado y nonce, agregar clave
                    print(f"Agregando clave a {email}")
                    user["dni"].append(clave.hex())  # Agrega la clave global
                    updated = True  # Marcar que la base de datos debe actualizarse
                    
                dni_cifrado, nonce, clave = user["dni"]
                
                print(f"Procesando DNI de {email}:")
                print(f"DNI cifrado: {dni_cifrado}")
                print(f"Nonce: {nonce}")
                clave = bytes.fromhex(user["dni"][2])  # Obtener la clave del usuario
                dni_descifrado = decrypt_aes(dni_cifrado, nonce, clave)
                print(f"DNI desencriptado para {email}: {dni_descifrado}")
                
            else:
                dni_descifrado = user["dni"]

            #  Verificar si el usuario tiene rol, si no, asignarle "user"
            if "role" not in user or not user["role"]:
                print(f"Asignando rol 'user' a {email}")  # Debug
                user["role"] = "user"
                updated = True  # Marcar que hubo un cambio en la base de datos

            users_display[email] = {
                "nombre": user["nombre"],
                "apellido": user["apellido"],
                "username": user["username"],
                "dni": ofuscar_dni(dni_descifrado),
                "dob": user["dob"],
                "role": user["role"]  #  Ahora siempre tendrá un rol
            }
        
        except Exception as e:
            print(f"Error al manejar el DNI de {email}: {e}")
            users_display[email] = user.copy()
            users_display[email]["dni"] = "****"

    #  Si se asignaron nuevos roles, actualizar la base de datos
    if updated:
        write_db("db.txt", db)

    if user_role != "admin":
        users_display = {user_email: users_display[user_email]}  # Mostrar solo el usuario autenticado

    return render_template('records.html', users=users_display, role=user_role, message=message)



@app.route('/update_user/<email>', methods=['POST', 'GET'])
@login_required
def update_user(email):
    if 'email' not in session:
        return redirect(url_for('api_login', error="Debes iniciar sesión."))

    db = read_db("db.txt")

    if email not in db:
        return redirect(url_for('read_record', message="Usuario no encontrado."))

    user = db[email]

    # #  Verificar si el DNI está encriptado y desencriptarlo antes de mostrarlo
    # dni_descifrado = ""
    # if isinstance(user["dni"], list):  # Si es una lista, significa que está encriptado
    #     dni_cifrado, nonce = user["dni"]
    #     try:
    #         dni_descifrado = decrypt_aes(dni_cifrado, nonce, clave).strip()  # Desencriptar correctamente
    #     except Exception as e:
    #         print(f" Error al desencriptar el DNI de {email}: {e}")
    #         dni_descifrado = "ERROR"
    # else:
    #     dni_descifrado = user["dni"]  # Si no está encriptado, usarlo directamente

    # if request.method == 'GET':
    #     return render_template('edit_user.html', 
    #                            user_data=user, 
    #                            email=email, 
    #                            dni=dni_descifrado,  #  Pasamos el DNI ya desencriptado
    #                            darkmode=request.cookies.get('darkmode', 'light'))

    # Si es una solicitud POST (actualización de datos)
    username = request.form['username']
    dni = request.form['dni']
    dob = request.form['dob']
    nombre = request.form['nombre']
    apellido = request.form['apellido']
    darkmode = 'dark' if 'darkmode' in request.form else 'light'

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
                               error=errores, 
                               dni=dni,  #  Mostrar lo que el usuario ingresó
                               darkmode=darkmode)

    #  Volver a cifrar el DNI antes de guardarlo
    clave = bytes.fromhex(db[email]["dni"][2])  # Obtener la clave del usuario
    dni_cifrado, nonce = encrypt_aes(dni, clave)
    
    db[email]['username'] = normalize_input(username)
    db[email]['nombre'] = normalize_input(nombre)
    db[email]['apellido'] = normalize_input(apellido)
    db[email]['dni'] = [dni_cifrado, nonce, clave.hex()]  # Guardar el DNI cifrado
    db[email]['dob'] = normalize_input(dob)

    write_db("db.txt", db)

    # Guardar preferencia de modo oscuro en cookie
    resp = make_response(redirect(url_for('read_record', message="Información actualizada correctamente")))
    resp.set_cookie('darkmode', darkmode, max_age=60*60*24*30, httponly=True, secure=True, samesite='Lax')

    return resp

@app.route('/api/delete_user/<email>', methods=['GET'])
@login_required
def delete_user(email):
    """Elimina un usuario y cierra su sesión si es el usuario autenticado."""
    
    if session.get('role') == 'admin':  # Solo el admin puede eliminar usuarios
        db = read_db("db.txt")

        if email not in db:
            return redirect(url_for('read_record', message="Usuario no encontrado"))

        del db[email]  # Eliminar el usuario de la base de datos
        write_db("db.txt", db)

        # Si el usuario eliminado es el que está en sesión, cerramos su sesión
        if session.get('email') == email:
            session.clear()  # Eliminar sesión del usuario eliminado
            return redirect(url_for('api_login', error="Tu cuenta ha sido eliminada."))

        return redirect(url_for('read_record', message="Usuario eliminado"))
    
    else:
        return redirect(url_for('read_record', message="No autorizado"))

# Endpoint para depósito
@app.route('/api/deposit', methods=['POST'])
@login_required
def api_deposit():
    if 'email' not in session:
        # Redirigir a la página de inicio de sesión si el usuario no está autenticado
        error_msg = "Por favor, inicia sesión para acceder a esta página."
        return render_template('login.html', error=error_msg)

    deposit_balance = request.form['balance']
    deposit_email = session.get('email')

    db = read_db("db.txt")
    transactions = read_db("transaction.txt")

    # Verificamos si el usuario existe
    if deposit_email in db:
        # Guardamos la transacción
        transaction = {"balance": deposit_balance, "type": "Deposit", "timestamp": str(datetime.now())}

        # Verificamos si el usuario tiene transacciones previas
        if deposit_email in transactions:
            transactions[deposit_email].append(transaction)
        else:
            transactions[deposit_email] = [transaction]
        write_db("transaction.txt", transactions)

        return redirect(url_for('customer_menu', message="Depósito exitoso"))

    return redirect(url_for('customer_menu', message="Email no encontrado"))


# Endpoint para retiro
@app.route('/api/withdraw', methods=['POST'])
@login_required
def api_withdraw():
    email = session.get('email')
    amount = float(request.form['balance'])
    password = normalize_input(request.form['password'])

    db = read_db("db.txt")

    password_db = db.get(email)["password"]
    salt_db = db.get(email)["password_salt"]
    if not password:
        return redirect(url_for('customer_menu',
                                message="Debe ingresar una contraseña",
                                error=True))

    if compare_salt(password, password_db, salt_db):
        """
        if amount <= 0:
            return redirect(url_for('customer_menu',
                                    message="La cantidad a retirar debe ser positiva",
                                    error=True))

        transactions = read_db("transaction.txt")
        current_balance = sum(float(t['balance']) for t in transactions.get(email, []))

        if amount > current_balance:
            return redirect(url_for('customer_menu',
                                    message="Saldo insuficiente para retiro",
                                    error=True))
        """
        
        # Procesar el retiro si la contraseña es correcta
        transaction = {"balance": -amount, "type": "Withdrawal", "timestamp": str(datetime.now())}
        transactions = read_db("transaction.txt")
        
        if email in transactions:
            transactions[email].append(transaction)
        else:
            transactions[email] = [transaction]

        write_db("transaction.txt", transactions)

        return redirect(url_for('customer_menu',
                                message="Retiro exitoso",
                                error=False))

    else:
        error = f"Credenciales incorrectas."
        return render_template('withdraw.html', error=error)

@app.route('/logout')
def logout():
    """Elimina la sesión del usuario y redirige a la página de login."""
    session.clear()  # Borra todos los datos de sesión
    return redirect(url_for('login'))  # Redirigir al login