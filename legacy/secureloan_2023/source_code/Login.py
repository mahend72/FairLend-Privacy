#login
import sqlite3
import hashlib

def login(username, password):
    connection = sqlite3.connect("Secureloan.db")
    cursor = connection.cursor()

    # Check if the entered credentials match
    cursor.execute('''
        SELECT * FROM users
        WHERE username = ? AND password = ?
    ''', (username, hash_password(password)))

    user = cursor.fetchone()

    connection.close()

    if user:
        print("Login successful!")
    else:
        print("Invalid username or password. Please try again.")

def hash_password(password):
    # Hash the password using SHA-256
    return hashlib.sha256(password.encode()).hexdigest()

# Example of how to call the login function
username_input = input("Enter your username: ")
password_input = input("Enter your password: ")

login(username_input, password_input)
