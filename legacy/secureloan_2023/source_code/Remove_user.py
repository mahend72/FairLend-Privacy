import sqlite3

def remove_user(username):
    connection = sqlite3.connect("Secureloan.db")
    cursor = connection.cursor()

    # Check if the user exists
    cursor.execute('''
        SELECT * FROM users
        WHERE username = ?
    ''', (username,))

    user = cursor.fetchone()

    if user:
        # Remove the user
        cursor.execute('''
            DELETE FROM users
            WHERE username = ?
        ''', (username,))

        print(f"User '{username}' removed successfully.")
        connection.commit()
    else:
        print(f"User '{username}' not found.")

    connection.close()
	
username =input("Enter your username: ")
remove_user(username)
