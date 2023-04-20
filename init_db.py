import sqlite3

connection = sqlite3.connect('database.db')
cur = connection.cursor()

cur.execute("""DROP TABLE IF EXISTS users;""")


cur.execute("""CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);""")


cur.execute("""DROP TABLE IF EXISTS urls;""")

cur.execute("""CREATE TABLE urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    short_url TEXT NOT NULL,
    link TEXT NOT NULL
);""")

connection.commit()
connection.close()