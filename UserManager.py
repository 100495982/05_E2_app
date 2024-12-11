import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from JSONManager import JSONManager
from SessionManager import UserSession
from guiManager import GUIManager
from PKIManager import PKIManager

#Hasheo de la contraseña usando SHA-256.
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def hash_username(username):
    return hashlib.sha256(username.encode()).hexdigest()

#Clase que se encarga de la autenticación de los usuarios.
class UserAuthenticator:

    #Resgistro de un nuevo usuario.
    @staticmethod
    def register():
        gui = GUIManager
        user_data = JSONManager.load_user_data()
        # username = input("Enter a username: ")
        gui.print_msg("Enter a username: ")
        username = input()
        if username in user_data:
            gui.print_msg("Username already exists.")
            return False

        gui.print_msg("Enter a password: ")
        password = input()
        hashed_password = hash_password(password)

        #Genera las claves (Publica y privada) para el usuario.
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()

        #Encripta la clave privada con la contraseña del usuario.
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        ).decode('utf-8')

        #Convierte la clave publica a un formato PEM y la guarda en el JSON.
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        csr_filename = PKIManager.generar_csr(username, private_key)
        PKIManager.emitir_certificado(csr_filename, username)

        #Guarda la información del usuario en el JSON.
        user_data[username] = {
            "password": hashed_password,
            "private_key": private_key_pem
        }
        #Guarda la clave publica en el JSON.
        JSONManager.save_user_data(user_data)
        JSONManager.save_public_key(username,
                                    public_key_pem)  

        #Mensaje de confirmación de que el registro ha ido bien.
        gui.print_msg(f"User {username} registered successfully. Please log in.", "bold")
        return True

    #Función para el login de un usuario.
    @staticmethod
    def login():
        gui = GUIManager
        user_data = JSONManager.load_user_data()
        gui.print_msg("Username: ")
        username = input()
        if username not in user_data:
            gui.print_msg("Username does not exist.")
            return None

        #Comprueba que la contraseña es correcta.
        gui.print_msg("Password: ")
        password = input()
        hashed_password = hash_password(password)

        if user_data[username]["password"] == hashed_password:
            gui.print_msg("Login successful.")
            return UserSession(username, password)
        else:
            gui.print_msg("Incorrect password.", "red")
            return None
