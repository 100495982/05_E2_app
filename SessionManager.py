import base64
import json
import os

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509 import load_pem_x509_certificate

from JSONManager import JSONManager
from guiManager import GUIManager
from LogManager import LogManager

from datetime import datetime

signature_logger = LogManager.setup_logger('signatures.log')
certificate_logger = LogManager.setup_logger('certificates.log')


# Clase que se encarga de la gestion de la sesion de un usuario.
class UserSession:
    def __init__(self, username, password):
        self.username = username
        self.private_key, self.public_key = self.load_keys(password)
        print(f"Session started for {username}.")

    # Carga las claves del usuario.
    def load_keys(self, password):
        user_data = JSONManager.load_user_data()
        user_info = user_data.get(self.username)

        # Comprueba si el usuario existe.
        if not user_info:
            raise ValueError("User not found.")

        # Carga la clave publica del usuario.
        public_key_pem = JSONManager.load_public_key(self.username)
        if not public_key_pem:
            raise ValueError("Public key not found.")

        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )

        # Carga la clave privada del usuario.
        private_key_pem = user_info["private_key"]
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=password.encode(),
            backend=default_backend()
        )

        return private_key, public_key

    # Carga la clave publica de otro usuario.
    def load_public_key(self, other_username):
        public_key_pem = JSONManager.load_public_key(other_username)
        if not public_key_pem:
            raise ValueError(
                f"No public key found for user '{other_username}'. Please ensure they are registered correctly.")

        return serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )

    # Encripta un mensaje para otro usuario.
    def encrypt_message(self, receiver_username, message):
        receiver_public_key = self.load_public_key(receiver_username)

        # Generate shared secret
        shared_secret = self.private_key.exchange(ec.ECDH(), receiver_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_secret)

        payload_file = "payload.json"

        try:
            # Create payload.json if it doesn't exist
            if not os.path.exists(payload_file):
                with open(payload_file, "w") as f:
                    payload = {
                        "sender": self.username,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "message": message
                    }
                    json.dump(payload, f, indent=4)

            # Load payload
            with open(payload_file, "r") as f:
                payload_data = f.read()

            # Encrypt message
            chacha = ChaCha20Poly1305(derived_key)
            nonce = os.urandom(12)
            ciphertext = chacha.encrypt(nonce, payload_data.encode('utf-8'), None)

            # Sign the ciphertext
            signature = self.sign_message(ciphertext)

            # Attach sender's certificate
            with open(f"{self.username}_cert.pem", "rb") as cert_file:
                cert_data = cert_file.read()

            # Store encrypted message, nonce, signature, and certificate
            with open(f"messages_{receiver_username}.txt", "ab") as f:
                f.write(json.dumps({
                    "sender_public_key": self.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode('utf-8'),
                    "nonce": base64.b64encode(nonce).decode('utf-8'),
                    "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                    "signature": base64.b64encode(signature).decode('utf-8'),
                    "certificate": cert_data.decode('utf-8'),
                    "read_status": 0
                }).encode() + b"\n")
        except Exception as e:
            print(f"Error during encryption: {e}")
            raise  # Re-raise the exception after logging
        finally:
            # Ensure payload.json is securely deleted
            if os.path.exists(payload_file):
                os.remove(payload_file)

        # print("Message encrypted, signed, and stored successfully.")

    # Desencripta los mensajes recibidos.
    def decrypt_message(self):
        try:
            messages_file = f"messages_{self.username}.txt"
            # Read all messages into memory
            with open(messages_file, "r") as f:
                lines = f.readlines()

            updated_lines = []
            for line in lines:
                msg = json.loads(line)

                ciphertext = base64.b64decode(msg["ciphertext"])
                nonce = base64.b64decode(msg["nonce"])
                signature = base64.b64decode(msg["signature"])
                certificate = msg["certificate"]
                sender_public_key_pem = msg["sender_public_key"]

                # Load sender's certificate
                sender_cert = x509.load_pem_x509_certificate(
                    certificate.encode('utf-8'), backend=default_backend()
                )

                # Validate the certificate
                # print("Validating sender's certificate...")
                with open("root_cert.pem", "rb") as root_cert_file:
                    root_cert = x509.load_pem_x509_certificate(root_cert_file.read())
                if sender_cert.issuer != root_cert.subject:
                    print("Certificate validation failed: Issuer mismatch.")
                    updated_lines.append(line)  # Keep the original message unchanged
                    continue
                # print("Certificate validated successfully.")

                sender_public_key = sender_cert.public_key()

                try:
                    # Verify the signature
                    sender_public_key.verify(
                        signature,
                        ciphertext,
                        ec.ECDSA(hashes.SHA256())
                    )
                    # print("Signature verified successfully.")
                except InvalidSignature:
                    print(f"Invalid signature for message: {msg}")
                    updated_lines.append(line)  # Keep the original message unchanged
                    continue

                # Decrypt the message
                shared_secret = self.private_key.exchange(ec.ECDH(), sender_public_key)
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake data'
                ).derive(shared_secret)

                chacha = ChaCha20Poly1305(derived_key)
                plaintext_json = chacha.decrypt(nonce, ciphertext, None)
                payload = json.loads(plaintext_json.decode('utf-8'))
                print(f"New message from {payload['sender']} at {payload['timestamp']}:")
                print(f"Message: {payload['message']}")

                # Update read_status
                msg["read_status"] = 1
                updated_lines.append(json.dumps(msg).encode() + b"\n")  # Update the line

            # Write back updated lines to the file
            with open(messages_file, "wb") as f:
                f.writelines(updated_lines)

        except FileNotFoundError:
            print("No messages found.")

    # Finaliza la sesion del usuario.
    def end_session(self):
        self.private_key = None
        gui = GUIManager
        gui.print_msg(f"Session ended for {self.username}.", "red")

    # metodo para firmar mensajes
    def sign_message(self, message):
        signature = self.private_key.sign(
            message,  # Use consistent encoding
            ec.ECDSA(hashes.SHA256())
        )
        LogManager.log_signature_operation(
            logger=signature_logger,
            operation="Generated",
            algorithm="ECDSA with SHA-256",
            key_length=self.private_key.key_size,
            username=self.username
        )
        return signature

    # metodo para verificar firmas de mensajes
    def verify_signature(self, message, signature, sender_cert_path):
        # print(f"Verifying message: {message}")
        # print(f"Using signature: {base64.b64encode(signature).decode('utf-8')}")

        with open(sender_cert_path, "rb") as f:
            sender_cert = load_pem_x509_certificate(f.read())

        sender_public_key = sender_cert.public_key()
        try:
            sender_public_key.verify(
                signature,
                message.encode('utf-8'),  # Use consistent encoding
                ec.ECDSA(hashes.SHA256())
            )
            # print("Signature verified successfully.")
            LogManager.log_signature_operation(
                logger=signature_logger,
                operation="Verified",
                algorithm="ECDSA with SHA-256",
                key_length=sender_public_key.key_size,
                username=sender_cert.subject.rfc4514_string()
            )
        except InvalidSignature:
            print("Signature verification failed.")
            LogManager.log_signature_operation(
                logger=signature_logger,
                operation="Verification Failed",
                algorithm="ECDSA with SHA-256",
                key_length=sender_public_key.key_size,
                username=sender_cert.subject.rfc4514_string()
            )
            raise

    def notify_unread_messages(self):

        messages_file = f"messages_{self.username}.txt"

        try:
            with open(messages_file, "rb") as f:
                lines = f.readlines()

            unread_counts = {}
            for line in lines:
                msg = json.loads(line)
                if msg.get("read_status", 0) == 0:  # Check if the message is unread
                    sender_cert = msg["certificate"]
                    sender_cert_obj = x509.load_pem_x509_certificate(
                        sender_cert.encode("utf-8"), backend=default_backend()
                    )
                    sender_name = sender_cert_obj.subject.get_attributes_for_oid(
                        NameOID.COMMON_NAME
                    )[0].value
                    unread_counts[sender_name] = unread_counts.get(sender_name, 0) + 1

            if unread_counts:
                print("You have unread messages:")
                for sender, count in unread_counts.items():
                    print(f"- {sender}: {count} unread message(s)")
            else:
                print("No unread messages.")
        except FileNotFoundError:
            print("No messages found.")
