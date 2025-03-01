from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


def hash_with_salt(texto, salt=None):
    # Generar un salt aleatorio si no se proporciona
    if salt is None:
        salt = get_random_bytes(32)
    
    # Crear un objeto de hash SHA-256
    hash_obj = SHA256.new()
    
    # Agregar la sal y el texto plano al hash
    hash_obj.update(salt + texto.encode())  # Concatenar salt + password antes de hashear
    
    # Calcular el hash final
    hash_result = hash_obj.digest()  # Devuelve el hash en bytes
    
    # Devolver el hash en hexadecimal y el salt en bytes
    return hash_result.hex(), salt.hex()

def decrypt_aes(texto_cifrado_str, nonce_str, clave):
    # Convertir el texto cifrado y el nonce de hexadecimal a bytes
    texto_cifrado = bytes.fromhex(texto_cifrado_str)
    nonce = bytes.fromhex(nonce_str)

    # Crear un objeto AES con la clave y el nonce proporcionados
    cipher = AES.new(clave, AES.MODE_EAX, nonce=nonce)

    # Descifrar el texto
    texto_descifrado = cipher.decrypt(texto_cifrado)

    # Convertir los bytes del texto descifrado a una cadena de texto
    return texto_descifrado.decode()


def encrypt_aes(texto, clave):
    # Convertir el texto a bytes
    texto_bytes = texto.encode()

    # Crear un objeto AES con la clave proporcionada
    cipher = AES.new(clave, AES.MODE_EAX)

    # Cifrar el texto
    nonce = cipher.nonce
    texto_cifrado, tag = cipher.encrypt_and_digest(texto_bytes)

    # Convertir el texto cifrado en bytes a una cadena de texto
    texto_cifrado_str = texto_cifrado.hex()

    # Devolver el texto cifrado y el nonce
    return texto_cifrado_str, nonce.hex()

if __name__ == '__main__':
    texto = "Hola Mundo"
    clave = get_random_bytes(16)
    texto_cifrado, nonce = encrypt_aes(texto, clave)
    print("Texto cifrado: " + texto_cifrado)
    print("Nonce: " + nonce)
    des = decrypt_aes(texto_cifrado, nonce, clave)
    print("Texto descifrado: " + des)