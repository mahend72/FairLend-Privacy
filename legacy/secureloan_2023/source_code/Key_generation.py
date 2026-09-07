from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_rsa_key_pair():
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Commonly used value for public exponent
        key_size=2048,          # You can adjust the key size as needed
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize keys to bytes
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem, public_key_pem


# Step 0.1: Customer Key pair generation

private_key, public_key = generate_rsa_key_pair()
with open('Customer_private_key.pem', 'wb') as private_key_file:
    private_key_file.write(private_key)

with open('Customer_public_key.pem', 'wb') as public_key_file:
    public_key_file.write(public_key)

print("Customer key pair generated and saved as Customer_private_key.pem and Customer_public_key.pem.")

# Step 0.2: Bank Key pair generation

private_key, public_key = generate_rsa_key_pair()
with open('Bank_private_key.pem', 'wb') as private_key_file:
    private_key_file.write(private_key)

with open('Bank_public_key.pem', 'wb') as public_key_file:
    public_key_file.write(public_key)


print("Bank key pair generated and saved as Bank_private_key.pem and Bank_public_key.pem.")


# Step 0.3: Third party Key pair generation
private_key, public_key = generate_rsa_key_pair()
with open('Third_party_private_key.pem', 'wb') as private_key_file:
    private_key_file.write(private_key)

with open('Third_party_public_key.pem', 'wb') as public_key_file:
    public_key_file.write(public_key)


print("Third_party key pair generated and saved as Third_party_private_key.pem and Third_party_public_key.pem.")

# Step 0.4: CIBIL Key pair
private_key, public_key = generate_rsa_key_pair()
with open('CIBIL_private_key.pem', 'wb') as private_key_file:
    private_key_file.write(private_key)

with open('CIBIL_public_key.pem', 'wb') as public_key_file:
    public_key_file.write(public_key)


print("CIBIL key pair generated and saved as CIBIL_private_key.pem and CIBIL_public_key.pem.")
