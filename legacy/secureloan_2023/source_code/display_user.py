import sqlite3

def display_user_credentials():
    connection = sqlite3.connect("Secureloan.db")
    cursor = connection.cursor()

    # Fetch all user records
    cursor.execute('''
        SELECT * FROM users
    ''')

    users = cursor.fetchall()

    if not users:
        print("No users found.")
    else:
        print("List of Usernames and Password Hashes:")
        for user in users:
            print(f"Username: {user[1]}, Password Hash: {user[2]}")

    connection.close()
	
display_user_credentials()