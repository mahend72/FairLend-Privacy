pip install petlib

#Function: Non-interactive zero-knowledge proof of knowledge

import random
from petlib.ec import EcGroup
from petlib.bn import Bn

def NIZKP(PII):
    # Define the elliptic curve group
    group = EcGroup()

    name = PII["Name"]
    address = PII["Address"]
    dateofbirth = PII["DateOfBirth"]
    phonenumber = PII["PhoneNumber"]

    # Encode the Name as an integer using a hash function
    name_encode = Bn.from_num(int(hashlib.sha256(name.encode()).hexdigest()[:8], 16))
    address_encode = Bn.from_num(int(hashlib.sha256(address.encode()).hexdigest()[:8], 16))
    dateofbirth_encode = Bn.from_num(int(hashlib.sha256(dateofbirth.encode()).hexdigest()[:8], 16))
    phonenumber_encode = Bn.from_num(int(hashlib.sha256(phonenumber.encode()).hexdigest()[:8], 16))

    # Generate the user's public key
    name_public_key = name_encode * group.generator()
    address_public_key = address_encode * group.generator()
    dateofbirth_public_key = dateofbirth_encode * group.generator()
    phonenumber_public_key = phonenumber_encode * group.generator()

    # Commitment
    r = Bn.from_num(random.randint(1, 10000))
    commitment = r * group.generator()

    # Verifier generates a random challenge
    c = Bn.from_num(random.randint(1, 10000))

    # Prover computes the response
    name_response = r + c * name_encode
    address_response = r + c * address_encode
    dateofbirth_response = r + c * dateofbirth_encode
    phonenumber_response = r + c * phonenumber_encode

    # Verifier checks the equation
    if (
        commitment + c * name_public_key == name_response * group.generator()
        and commitment + c * address_public_key == address_response * group.generator()
        and commitment + c * dateofbirth_public_key == dateofbirth_response * group.generator()
        and commitment + c * phonenumber_public_key == phonenumber_response * group.generator()
    ):
        return 1
    else:
        return 0


# Call the NIZKP function
result = NIZKP(PII)
print(result)

# Function: Account Number
import random

def generate_account_number(name, address, gender, dateofbirth, phone_number):
    # Combine the input data to create a unique seed
    seed = str(name) + str(address) +str(gender)+ str(dateofbirth) + str(phone_number)

    # Set a fixed random seed for reproducibility (optional)
    random.seed(seed)

    # Generate a random number
    account_number = random.randint(1000000, 9999999)  # You can adjust the range as needed

    return account_number

# Function: Customer ID
import string
def generate_customer_id():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

#Account open: main

#packages and libraries
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Step: 2.1 Load the public key from a PEM file (request for Bank's public key)
with open('Bank_public_key.pem', 'rb') as key_file:
    Bank_public_key = serialization.load_pem_public_key(key_file.read())

# Step 2.2: Request to open account by encrypting and sending encrypted PII

# Encrypts PII details using Bank's public key
name = PII["Name"].encode('utf-8')
address = PII["Address"].encode('utf-8')
gender = PII["Gender"].encode('utf-8')
dateofbirth = PII["DateOfBirth"].encode('utf-8')
phonenumber = PII["PhoneNumber"].encode('utf-8')

enc_name = Bank_public_key.encrypt(name,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
enc_address = Bank_public_key.encrypt(address,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
enc_gender = Bank_public_key.encrypt(gender,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
enc_dateofbirth = Bank_public_key.encrypt(dateofbirth,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
enc_phonenumber = Bank_public_key.encrypt(phonenumber,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

print("Encrypted PII")
print("Name: ", enc_name)
print("Address: ", enc_address)
print("Gender: ", enc_gender)
print("Date of Birth: ", enc_dateofbirth)
print("Phone number: ", enc_phonenumber)


# Step 2.3: Bank decrypts encrypted information using his private key

with open('Bank_private_key.pem', 'rb') as key_file:
    Bank_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None  # You may need to provide a password if the key is password-protected
    )

dec_name = Bank_private_key.decrypt(enc_name,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
dec_address = Bank_private_key.decrypt(enc_address,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
dec_gender = Bank_private_key.decrypt(enc_gender,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
dec_dateofbirth = Bank_private_key.decrypt(enc_dateofbirth,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
dec_phonenumber = Bank_private_key.decrypt(enc_phonenumber,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

print("\nDecrypted PII")
print("Name: ", dec_name.decode('utf-8'))
print("Address: ", dec_address.decode('utf-8'))
print("Gender: ", dec_gender.decode('utf-8'))
print("Date of Birth: ", dec_dateofbirth.decode('utf-8'))
print("Phone number: ", dec_phonenumber.decode('utf-8'))


# Step 2.4: Customer Authentication Using ZKP
# Information in json formate
Decrypted_PII={
    "Name": dec_name.decode('utf-8'),
    "Address" : dec_address.decode('utf-8'),
    "Gender" : dec_gender.decode('utf-8'),
    "DateOfBirth" : dec_dateofbirth.decode('utf-8'),
    "PhoneNumber" : dec_phonenumber.decode('utf-8')
}

result = NIZKP(Decrypted_PII)

#Step 2.5: If verified,
#generate account details, (user id, account number),
#encrypt gender info Customer_pub_key
# and account details with Bank_pub_key
#and store them in their storage

#Generates customer
if result!=1:
  print("not valid")
else:
  # Extract Bank and Customer's Public keys
  with open('Customer_public_key.pem', 'rb') as key_file:
      Customer_public_key = serialization.load_pem_public_key(key_file.read())
  with open('Bank_public_key.pem', 'rb') as key_file:
      Bank_public_key = serialization.load_pem_public_key(key_file.read())

  #Encyrpt gender details with customer public key and rest with his public key and encrypted iformation in its storage
  enc_name = Customer_public_key.encrypt(
      Decrypted_PII["Name"].encode('utf-8'),  # Encode the string to bytes
      padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
  enc_address= Customer_public_key.encrypt(
      Decrypted_PII["Address"].encode('utf-8'),
      padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
  enc_name = Customer_public_key.encrypt(
      Decrypted_PII["DateOfBirth"].encode('utf-8'),
      padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
  enc_name = Customer_public_key.encrypt(
      Decrypted_PII["PhoneNumber"].encode('utf-8'),
      padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

  enc_name = Bank_public_key.encrypt(
      Decrypted_PII["Gender"].encode('utf-8'),
      padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

  # Generate account details
  account_num = generate_account_number(name, address, gender, dateofbirth, phonenumber)
  customer_id = generate_customer_id()
  print("Customer ID :", customer_id)
  print("Account Number :", account_num)


#Step 2.6: Bank encrypts account details using customer public key and sends it to customer
enc_account_num = Customer_public_key.encrypt(
    str(account_num).encode('utf-8'),  # Convert the integer to bytes and then encrypt
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

enc_customer_id = Customer_public_key.encrypt(
    str(customer_id).encode('utf-8'),  # Convert the integer to bytes and then encrypt
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

print("Encrypted Customer ID: ", enc_customer_id)
print("Encrypted Account Number: ", enc_account_num)

#Step 2.7: Customer decrypts the encrypted details with private key and save it.
with open('Customer_private_key.pem', 'rb') as key_file:
    Customer_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None)  # You may need to provide a password if the key is password-protected

dec_account_num = Customer_private_key.decrypt(
    enc_account_num,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None) )

dec_customer_id = Customer_private_key.decrypt(
    enc_customer_id,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None) )

print("Decrypted Customer ID: ", dec_customer_id.decode('utf-8'))
print("Decrypted Account Number: ", dec_account_num.decode('utf-8'))





