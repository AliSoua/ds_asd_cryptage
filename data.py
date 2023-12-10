import sqlite3

conn = sqlite3.connect('data.db')
cursor = conn.cursor()


def check_email_existence(email):
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user WHERE email=?", (email,))
    result = cursor.fetchone()
    return bool(result) 

def add_user(email, password):
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO user (email, password) VALUES (?, ?)", (email, password))
    conn.commit()
    print("User added successfully.")

def check_credentials(email, password):
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user WHERE email=? AND password=?", (email, password))
    result = cursor.fetchone()
    return bool(result)



table_create_query = '''CREATE TABLE IF NOT EXISTS user 
                    (email TEXT , password TEXT )'''


conn.execute(table_create_query)
conn.close()