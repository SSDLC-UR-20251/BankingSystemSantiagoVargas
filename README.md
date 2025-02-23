# Lab1 - Secure Coding Practices for Input Validation, Authentication and Authorization

## 🎓 Universidad del Rosario - 2025 – 1

---

## 📖 Sección Teórica (1pt)
El objetivo de esta sección es evaluar la comprensión precisa de los conceptos teóricos cubiertos en clase. Las preguntas son de opción múltiple y siguen el modelo de examen del Certified Application Security Engineer y de DevSecOps Essentials.

1. **¿Cuál de los siguientes no es un tipo de autorización?** 
   - [x] 🔹 a) Managed Access Control  
   - [ ] 🔹 b) Mandatory Access Control  
   - [ ] 🔹 c) Discretionary Access Control  
   - [ ] 🔹 d) Role Based Access Control  

2. **¿Qué mecanismo de seguridad implementarías para restringir el acceso de los usuarios a recursos específicos dentro de una aplicación?**
   - [ ] 🔐 a) Autenticación  
   - [x] 🔐 b) Autorización  
   - [ ] 🔐 c) Delegación  
   - [ ] 🔐 d) Impersonación  

3. **Según las prácticas de autenticación y autorización segura en el desarrollo de aplicaciones, ¿con qué tipo de privilegios no se debe ejecutar una aplicación?**
   - [x] 🚫 a) Privilegios de cuenta de administrador  
   - [ ] 🚫 b) Privilegios de cuenta de usuario  
   - [ ] 🚫 c) Privilegios de cuenta de invitado  
   - [ ] 🚫 d) Privilegios de cuenta normal  

4. **¿Cuál de las siguientes técnicas de seguridad implica el proceso de convertir datos potencialmente peligrosos en formatos seguros que se pueden mostrar o almacenar de forma segura?**
   - [ ] 🛠️ a) Input Validation  
   - [ ] 🔐 b) Encryption and Hashing  
   - [x] 🔄 c) Output Encoding  
   - [ ] 🔑 d) Access Control  

5. **¿Cuál es el principio central de la práctica de seguridad "Secure by Default"?**
   - [ ] 🔒 a) Los sistemas deben estar diseñados para fallar en un estado seguro.  
   - [ ] 🏛️ b) Diseñar la seguridad en los niveles físico, identidad y acceso, perímetro, red, cómputo, aplicación y datos.  
   - [ ] 🔑 c) Requiere autenticación y autorización para cada acción.  
   - [x] 📜 d) Los requisitos de seguridad deben definirse al inicio del proceso de desarrollo de la aplicación.  

---

## 🛠️ Sección Práctica (4pt)

### **🔐 Implementación de Seguridad en Autenticación y Autorización**

Se deberá complementar el módulo de login de BankingSystem con control de intentos fallidos para mitigar ataques de fuerza bruta y una lógica de autorización basada en roles.

#### **1️⃣ Control de Intentos Fallidos en Autenticación (2pt)**

1. **Definir variables globales**: 
   - 📌 Definir variables para almacenar el número máximo de intentos permitidos.
   - 📌 Definir el tiempo de bloqueo (5 minutos por defecto).
   - 📌 Crear un diccionario para registrar el estado de los usuarios: `{ "usuario": { "intentos": 0, "tiempoBloqueo": 0 } }`

2. **Validar si el correo existe en la base de datos**:
   - ✅ Si el usuario existe y la contraseña es correcta, resetear su contador de intentos fallidos a cero.
   - ❌ Si la contraseña es incorrecta, incrementar el contador de intentos fallidos.

3. **Bloquear la cuenta si se exceden los intentos permitidos**:
   - 🚨 Si se superan los 3 intentos fallidos, actualizar el `tiempoBloqueo` en el diccionario, estableciéndolo al tiempo de bloqueo.

4. **Verificar si la cuenta está bloqueada**:
   - 🔎 Antes de procesar la autenticación, verificar si el usuario sigue en estado de bloqueo.
   - ⏳ Si el tiempo de bloqueo no ha terminado, mostrar un mensaje informando cuánto tiempo queda hasta el desbloqueo.

#### **2️⃣ Implementación de Control de Acceso Basado en Roles (1pt)**

1. **Añadir un campo de rol al registro del usuario**:
   - 📝 Modificar la base de datos y el formulario de registro para incluir el campo `rol`, que podrá tomar los valores `admin` o `user`.

2. **Modificar el proceso de autenticación**:
   - 🔄 Al iniciar sesión, almacenar el rol del usuario en la sesión, por ejemplo: `session['role'] = 'admin'` o `session['role'] = 'user'.

3. **Implementar la lógica de autorización**:
   - 🚦 Modificar la ruta `/records` para que solo los usuarios con rol `admin` puedan acceder a todos los registros de la base de datos.
   - 👤 Si el usuario tiene el rol `user`, solo podrá visualizar y actualizar su propio registro.
   - 🗑️ Implementar la lógica para la eliminación de usuarios:

      - Solo los usuarios con rol admin pueden eliminar otros usuarios.
      - Agregar un botón de eliminación en la vista HTML para la gestión de usuarios.
      - Implementar un endpoint que realice la eliminación del usuario seleccionado.

#### **3️⃣ Implementación Validación de Entradas (1pt)**

1. **Validación de Usuario**  
  - El **nombre de usuario** solo puede contener **caracteres alfabéticos y el punto (`.`)**.  
  - Ejemplo válido: `sara.palacios`.  

2. **Validación de Contraseña**  
  Según las **políticas de seguridad de la Universidad del Rosario**, una contraseña debe cumplir con:  
    - **Al menos una letra minúscula, una letra mayúscula y un número**.  
    - **Al menos un carácter especial requerido**: `# * @ $ % & - ! + = ?`.  
    - **Longitud mínima:** 8 caracteres.  
    - **Longitud máxima:** 35 caracteres.  

3. **Validación de Correo Electrónico**  
  - Se debe asegurar que el **dominio del correo electrónico** sea: `@urosario.edu.co`.  

4. **Validación de Fecha de Nacimiento**  
  - Solo se pueden registrar usuarios **mayores de 16 años**.  

5. **Validación de Documento de Identificación**  
  - Debe ser **numérico** y tener **máximo 10 dígitos**.  
  - Debe **iniciar con "1000000000"**.  
---

🚀 Cómo clonar BankingSystem y subirlo a un nuevo repositorio

Si necesitas trabajar con el código del repositorio BankingSystem y subirlo a un nuevo repositorio, sigue estos pasos:

Clonar el repositorio original:
```bash
git clone https://github.com/SSDLC-UR-20251/BankingSystem.git
cd BankingSystem
```
Eliminar la conexión con el repositorio original:

```bash
git remote remove origin
```

Copia la URL de tu repositorio.

Agregar el nuevo repositorio como remoto:

```bash
git remote add origin https://github.com/usuario/nuevo-repo.git
```
Subir el código al nuevo repositorio:
```bash
git push -u origin main
```
Si experimentas errores de autenticación al hacer git pull o git push, sigue estos pasos para autenticarte localmente:

 - Configurar almacenamiento de credenciales para HTTPS:
```bash

git config --global credential.helper store
git push -u origin main
```
Luego, introduce tus credenciales cuando se te soliciten. Estas se guardarán localmente para futuras conexiones.

- Autenticarse usando un token personal en HTTPS:
Si usas autenticación con token en GitHub, usa este formato al hacer git pull o git push:
```bash

git remote set-url origin https://<TOKEN>@github.com/usuario/nuevo-repo.git
```

Crear una nueva rama para tu implementación:
```bash
git checkout -b feature/nueva-funcionalidad
```
Agregar los cambios realizados:
```bash
git add .
```
Realizar un commit con un mensaje descriptivo:
```bash
git commit -m "Agrega nueva funcionalidad de autorización basada en roles"
```
Subir la rama al repositorio remoto:
```bash
git push origin feature/nueva-funcionalidad
```
Crear un PullRequest y agregar la URL a la entrega en e-aulas.
