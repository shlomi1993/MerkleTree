from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

# UNTESTED EXAMPLE!

##### Symmetric crypto #####

# key = (key1 || key2) where key1 is 128b MAC key and key2 is 128b encryption key.
# key is a symmetric key.
key = Fernet.generate_key()

# MAC with HMAC-SHA256:
cipher = Fernet(key)

# Encryption with AES-CBC 128b:
token = cipher.encrypt(b"Hello")

# Decryption:
plaintext = cipher.decrypt(token)



##### Asymmetric crypto #####

# Creating sk, with common exponent and common key size.
# Backend is the creation library. default_backend() is a common library.
private_key = rsa.generate_private_key(public_exponent = 65537,
        key_size = 2048,
        backend = default_backend()
    )

# Now we want to store the key in the storage so it will be available after system restart.
# Save sk to pramenter named pem with additional settings and security measures (like password).
pem = private_key.private_bytes(encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = alg
    )

# Write pem to sk.pem file.
with open("sk.pem", "wb") as f:
    f.write(pem)

# With the private key we can extract public key (pk).
public_key = private_key.public_key()

# Again, we can save the pk in a parameter pem with addtional settings like encoding, format
# and additional security measures.
pem = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Write pem to pk.pem file.
with open("pk.pem", "wb") as f:
    f.write(pem)

# Now we have private and public keys and we can use them for signing and verifying
# of for encryption and decryption.

# Create msg.
message = b"Hello world"

# Signing -- it is recommended to use padding and salt.
signature = private_key.sign(message,
        padding.PSS(mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
        hashes.SHA256()
    )

# Verifying -- with the same mgf (padding), salt and hash.
public_key.verify(signature, message,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# Failed verification throws exception.

# Encryption using pk.
ciphertext = public_key.encrypt(message,
        padding.OAEP(
            mgf = padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None)
        )

# Decryption using sk.
plaintext = private_key.decrypt(ciphertext,
        padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None)
        )



##### Certificate Creation #####

# Now we can create an x509 certificate

# Declare certificate structure.
subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IL"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Foo Inc."),
            x509.NameAttribute(NameOID.COMMON_NAME, "Foo CA"),
        ]
    )

# Using Certificate Builder -- Note the different fields.
certificateBuilder = (x509.CertificateBuilder()
        .serial_number(x509.random_serial_number())
        .issuer_name(subjest) # self-sign
        .not_valid_before(datetime.utcnow() + timedelta(days = 1))
        .not_valid_after(datetime.utcnow() + timedelta(days = 180))
        .subject_name(subject)
        .public_key(private_key.public_key())
        .add_extension(x509.BasicConstraints(ca = True, path_length = None), critical = True)
    )

# Creating the certificate (BUILD).
signature = certificateBuilder.sign(private_key, hashes.SHA256(), default_backend())

# Save certificate in the storage.
with open(filename, "wb") as cert:
    cert.write(signature.public_bytes(serialization.Encoding.PEM))
