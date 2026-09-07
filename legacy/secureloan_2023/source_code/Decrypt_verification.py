import ast
import base64
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def decrypt_and_verify(filename):
    with open(filename, "r") as file:
        data = file.read()
    #print(data)
    # Extracting the value of the "Account Number" field using ast.literal_eval
    try:
        account_number_str = data.split("Account Number:")[1].split("Account Type:")[0].strip()
        account_number = ast.literal_eval(account_number_str)
        customer_name_str = data.split("Customer Name:")[1].split("Customer ID:")[0].strip()
        customer_name = ast.literal_eval(customer_name_str)

    except (IndexError, ValueError, SyntaxError) as e:
        print(f"Error extracting account number: {e}")
        return None

    print(customer_name)
    # Decrypt the data using the private key
    decrypted_account = Customer_private_key.decrypt(account_number,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None,))
    print(decrypted_account)
    #decrypted_customer_name = Customer_private_key.decrypt(customer_name,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None,))

    # Extract the details
    details = decrypted_account.decode("utf-8").splitlines()

    print("\ndetails", details)
    # Verify the details using NIZKP
    if NIZKP(details):
        print("Details verified successfully!")
        # Sign the information with the private key
        signature = private_key.sign(
           details,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return signature
    else:
        print("Details verification failed.")
        return None, None

# Load private key
with open('Customer_private_key.pem', 'rb') as key_file:
    customer_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None  # You may need to provide a password if the key is password-protected
    )

# Example usage
filename = "loan_information.txt"
signature = decrypt_and_verify(filename)

if signature:
    #print("Details:", details)
    print("Signature:", base64.b64encode(signature).decode())
