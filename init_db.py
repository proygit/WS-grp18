import sqlite3

connection = sqlite3.connect('database.db')
cur = connection.cursor()

cur.execute("""DROP TABLE IF EXISTS users;""")


cur.execute("""CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);""")


connection.commit()
connection.close()