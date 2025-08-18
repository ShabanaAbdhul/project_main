#pip install mysql-connector-python
import mysql.connector
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="admin",
    database="flask_notes_app"
)
cursor = db.cursor()