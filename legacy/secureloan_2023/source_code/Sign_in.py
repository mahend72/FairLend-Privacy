import sqlite3
import hashlib

# Function to create a table for user credentials
def initialize_table():
    connection = sqlite3.connect("Secureloan.db")
    cursor = connection.cursor()

    # Create a table to store user credentials
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    connection.commit()
    connection.close()

initialize_table()

import sqlite3
import hashlib
from petlib.ec import EcGroup, Bn
import random

def Sign_In(username, name, address, dateofbirth, phonenumber):
    connection = sqlite3.connect("Secureloan.db")
    cursor = connection.cursor()

    # Check if the username already exists
    cursor.execute('''
        SELECT * FROM users
        WHERE username = ?
    ''', (username,))

    existing_user = cursor.fetchone()

    if existing_user:
        print("Username already exists. Please choose a different username.")
        connection.close()
        return

    # Call NIZKP function for verification
    PII = {"Name": name, "Address": address, "DateOfBirth": dateofbirth, "PhoneNumber": phonenumber}
    verification_result = NIZKP(PII)

    if verification_result:
        print("Persional details are verified")
        password = input("Enter your password: ")

        password_hash = hash_password(password)

        # Insert a sample user
        cursor.execute('''
            INSERT INTO users (username, password) VALUES (?, ?)
        ''', (username, password_hash))

        print("User registered successfully!")
    else:
        print("Verification failed. User not registered.")

    connection.commit()
    connection.close()

def hash_password(password):
    # Hash the password using SHA-256
    return hashlib.sha256(password.encode()).hexdigest()

# Example of how to call insert_user_details
username_input = input("Enter username: ")
name_input = input("Enter your name: ")
address_input = input("Enter your address: ")
dateofbirth_input = input("Enter your date of birth: ")
phonenumber_input = input("Enter your phone number: ")

Sign_In(username_input, name_input, address_input, dateofbirth_input, phonenumber_input)


