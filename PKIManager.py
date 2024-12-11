from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import CertificateBuilder, NameOID, \
    CertificateSigningRequestBuilder
from LogManager import LogManager
import cryptography.x509 as x509
import datetime

signature_logger = LogManager.setup_logger('signatures.log')
certificate_logger = LogManager.setup_logger('certificates.log')


class PKIManager:
    @staticmethod
    def crear_ca():
        # Generar clave privada de la CA
        ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        # Crear certificado autosignado
        ca_cert = (
            CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Root CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            ]))
            .issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Root CA"),
            ]))
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .sign(ca_key, hashes.SHA256())
        )

        # Guardar clave y certificado en archivos
        with open("root_key.pem", "wb") as f:
            f.write(ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open("root_cert.pem", "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

        # print("CA creada y guardada como root_key.pem y root_cert.pem.")

    @staticmethod
    def generar_csr(username, private_key):
        csr = (
            CertificateSigningRequestBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, username),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization"),
            ]))
            .sign(private_key, hashes.SHA256())
        )

        csr_filename = f"{username}_csr.pem"
        with open(csr_filename, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

        print(f"CSR generado para {username} en {csr_filename}.")
        return csr_filename

    @staticmethod
    def emitir_certificado(csr_filename, username):
        # Cargar la clave privada y certificado de la CA
        with open("root_key.pem", "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open("root_cert.pem", "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        # Cargar el CSR
        with open(csr_filename, "rb") as f:
            csr = x509.load_pem_x509_csr(f.read())

        # Crear el certificado del usuario
        user_cert = (
            CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .sign(ca_key, hashes.SHA256())
        )

        cert_filename = f"{username}_cert.pem"
        with open(cert_filename, "wb") as f:
            f.write(user_cert.public_bytes(serialization.Encoding.PEM))

        LogManager.log_certificate_operation(
            logger=certificate_logger,
            operation="Generated",
            algorithm="RSA with SHA-256",
            key_length=ca_key.key_size,
            subject=user_cert.subject.rfc4514_string(),
            issuer=ca_cert.subject.rfc4514_string()
        )

        # print(f"Certificado emitido para {username} en {cert_filename}.")

