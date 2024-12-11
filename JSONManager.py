import json
import os


class JSONManager:
    """ Clase para la gestión de archivos JSON. """
    USER_DATA_FILE = "users.json"
    PUBLIC_KEY_FILE = "public_keys.json"

    # Método para cargar los datos de los usuarios desde users.json
    @staticmethod
    def load_user_data():
        if os.path.exists(JSONManager.USER_DATA_FILE):
            with open(JSONManager.USER_DATA_FILE, "r") as f:
                return json.load(f)
        return {}
    
    # Método para guardar los datos de los usuarios en users.json
    @staticmethod
    def save_user_data(user_data):
        with open(JSONManager.USER_DATA_FILE, "w") as f:
            json.dump(user_data, f, indent=4)

    # Método para guardar la clave pública de un usuario en public_keys.json
    @staticmethod
    def save_public_key(username, public_key_pem):
        if os.path.exists(JSONManager.PUBLIC_KEY_FILE):
            with open(JSONManager.PUBLIC_KEY_FILE, "r") as f:
                public_keys = json.load(f)
        else:
            public_keys = {}

        public_keys[username] = public_key_pem
        with open(JSONManager.PUBLIC_KEY_FILE, "w") as f:
            json.dump(public_keys, f, indent=4)

    # Método para cargar la clave pública de un usuario desde public_keys.json
    @staticmethod
    def load_public_key(username):
        if os.path.exists(JSONManager.PUBLIC_KEY_FILE):
            with open(JSONManager.PUBLIC_KEY_FILE, "r") as f:
                public_keys = json.load(f)
                return public_keys.get(username)
        return None

