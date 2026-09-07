#Step 3.1: Customer request for CIBIL and Bank's public key to know his CIBIL score

with open('Bank_public_key.pem', 'rb') as key_file:
    Bank_public_key = serialization.load_pem_public_key(key_file.read())

with open('CIBIL_public_key.pem', 'rb') as key_file:
    CIBIL_public_key = serialization.load_pem_public_key(key_file.read())

#Step 3.2:  Customer encrypts FII and PII with CIBIL public key and request for CIBIL score
name = PII["Name"].encode('utf-8')
address = PII["Address"].encode('utf-8')
gender = PII["Gender"].encode('utf-8')
dateofbirth = PII["DateOfBirth"].encode('utf-8')
phonenumber = PII["PhoneNumber"].encode('utf-8')

employmentstatus=FI["EmploymentStatus"].encode('utf-8')
salary= FI["Salary"].encode('utf-8')
existingloan=FI["ExistingLoan"].encode('utf-8')
collateral=FI["Collateral"].encode('utf-8')

enc_name = CIBIL_public_key.encrypt(name,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
enc_address = CIBIL_public_key.encrypt(address,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
enc_gender = CIBIL_public_key.encrypt(gender,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
enc_dateofbirth = CIBIL_public_key.encrypt(dateofbirth,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
enc_phonenumber = CIBIL_public_key.encrypt(phonenumber,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

enc_employmentstatus = CIBIL_public_key.encrypt(employmentstatus,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
enc_salary = CIBIL_public_key.encrypt(salary,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
enc_existingloan = CIBIL_public_key.encrypt(existingloan,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
enc_collateral = CIBIL_public_key.encrypt(collateral,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

print("Encrypted personal identifiable information")
print("Name: ", enc_name)
print("Address: ", enc_address)
print("Gender: ", enc_gender)
print("Date of Birth: ", enc_dateofbirth)
print("Phone number: ", enc_phonenumber)

print("\nEncrypted financial information")
print("Employment status: ", enc_employmentstatus)
print("Salary", enc_salary)
print("Existing Loan: ", enc_existingloan)
print("Collateral: ", enc_collateral)


# Step 3.3: Bank decrypts encrypted information using his private key

with open('CIBIL_private_key.pem', 'rb') as key_file:
    CIBIL_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None  # You may need to provide a password if the key is password-protected
    )

dec_name = CIBIL_private_key.decrypt(enc_name,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
dec_address = CIBIL_private_key.decrypt(enc_address,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
dec_gender = CIBIL_private_key.decrypt(enc_gender,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
dec_dateofbirth = CIBIL_private_key.decrypt(enc_dateofbirth,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
dec_phonenumber = CIBIL_private_key.decrypt(enc_phonenumber,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

dec_employmentstatus = CIBIL_private_key.decrypt(enc_employmentstatus,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
dec_salary = CIBIL_private_key.decrypt(enc_salary,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
dec_existingloan = CIBIL_private_key.decrypt(enc_existingloan,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
dec_collateral = CIBIL_private_key.decrypt(enc_collateral,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

print("\nDecrypted personal identifiable information")
print("Name: ", dec_name.decode('utf-8'))
print("Address: ", dec_address.decode('utf-8'))
print("Gender: ", dec_gender.decode('utf-8'))
print("Date of Birth: ", dec_dateofbirth.decode('utf-8'))
print("Phone number: ", dec_phonenumber.decode('utf-8'))

print("\nDecrypted financial information")
print("Employment status: ", dec_employmentstatus.decode('utf-8'))
print("Salary", dec_salary.decode('utf-8'))
print("Existing Loan: ", dec_existingloan.decode('utf-8'))
print("Collateral: ", dec_collateral.decode('utf-8'))

#Step 3.3: Compute CIBIL Score
CIBIL_score = 550

#Step 3.4 CIBIL agency requests for Cus_pub_key
with open('Customer_public_key.pem', 'rb') as key_file:
    Customer_public_key = serialization.load_pem_public_key(key_file.read())


#Step 3.5: CIBIL agency encrypts score with Cus_pub_key
#Step 3.6: Sends encrypted score to customer
enc_score = CIBIL_public_key.encrypt(str(CIBIL_score).encode('utf-8'),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
print("\nEncrypted CIBIL score", enc_score)

# Step 3.7: Customer decrypts encrypted CIBIL score
dec_score = CIBIL_private_key.decrypt(enc_score,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
print("\nDecrypyted CIBIL score", dec_score.decode('utf-8'))


