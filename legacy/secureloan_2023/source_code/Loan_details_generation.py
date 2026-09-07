#Generate Loan details/documents

import random
import string

def generate_credit_limits():
    return random.randint(1000, 10000)

def generate_loan_details():
    loan_types = ['Home Loan', 'Car Loan', 'Personal Loan']
    return {
        'Loan Type': random.choice(loan_types),
        'Loan Amount': random.randint(5000, 50000),
        'Interest Rate': round(random.uniform(2, 10), 2),
        'Loan Duration (months)': random.randint(12, 60)
    }

# Generate information for an approved loan
account_number = enc_account_num
account_type = random.choice(['Savings', 'Checking'])
customer_name = enc_name  # Replace with actual customer name
customer_id = enc_customer_id
address = enc_address
gender= enc_gender
dateofbirth = enc_dateofbirth
phone_number = enc_phonenumber
cibil_score = enc_score
credit_limits = generate_credit_limits()
loan_details = generate_loan_details()



# Construct the generated information as a string
loan_information = f"""Persional Details:
Account Number: {account_number}
Account Type: {account_type}
Customer Name: {customer_name}
Customer ID: {customer_id}
Address: {address}
Phone Number: {phone_number}
CIBIL Score: {cibil_score}
Credit Limits: {credit_limits}

Loan Details:
Loan Type: {loan_details['Loan Type']}
Loan Amount: {loan_details['Loan Amount']}
Interest Rate: {loan_details['Interest Rate']}
Loan Duration (months): {loan_details['Loan Duration (months)']}
"""

# Write the information to a file
file_path = 'loan_information.txt'
with open(file_path, 'w') as file:
    file.write(loan_information)

print(f"Loan information has been written to {file_path}")
