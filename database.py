import mysql.connector

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Rj_young158",
    database="phishing_db"
)

cursor = db.cursor()
