from flask import Flask, request, jsonify
import mysql.connector
import bcrypt
from datetime import datetime,timedelta
import jwt
from functools import wraps


app = Flask(__name__)

mydatabase = mysql.connector.connect(
    host = "localhost",
    user = "root",
    password = "Rahul73556"
)


mycursor = mydatabase.cursor()
mycursor.execute("create database if not exists app_test")
mydatabase.database = "app_test"

mycursor.execute("""
    CREATE TABLE IF NOT EXISTS app_test_table (
        user_id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
""")

mycursor.execute("""
    CREATE TABLE IF NOT EXISTS tasks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        due_date DATETIME,
        status ENUM('Todo', 'Inprogress', 'Done') DEFAULT 'Todo',
        user_id INT,
        FOREIGN KEY (user_id) REFERENCES app_test_table(user_id)
    )
""")

mycursor.execute("""
    CREATE TABLE IF NOT EXISTS task_members (
        id INT AUTO_INCREMENT PRIMARY KEY,
        task_id INT,
        user_email VARCHAR(255),
        FOREIGN KEY (task_id) REFERENCES tasks(id)
    )
""")

mydatabase.commit()


jwt_secret = "jwtsecretkey"



def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")

        if not token:
            return jsonify({"error": "Token is missing"}), 401

        try:
            token = token.split(" ")[1]
            data = jwt.decode(token, jwt_secret, algorithms=["HS256"])
            request.user_id = data["user_id"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception as e:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)

    return decorated




@app.route("/home")
@app.route("/")
def home():
    return jsonify({"message": "Welcome to the Home Page!"})

@app.route("/register",methods=["GET","POST"])
def register():
    data = request.get_json()
    Name = data.get("Name")
    Email = data.get("Email")
    Password = data.get("Password")
    ConfirmPassword = data.get("ConfirmPassword")
    
    if not Name and not Email and not Password and not ConfirmPassword:
        return jsonify({"Error":"All field all not filled."})
    
    if Password!=ConfirmPassword:
        return jsonify({"Error":"Passowrd and Confirm Password does not match"})
    
    mycursor.execute("select count(*) from app_test_table where Email = %s",(Email,))
    result = mycursor.fetchone()
    if result[0] != 0:
        return jsonify({"Message":"This Email id is already Registered."})
    
    else:
        try:
            hashed_password = bcrypt.hashpw(Password.encode("utf-8"),bcrypt.gensalt())
            mycursor.execute("insert into app_test_table(Name,Email,Password) values(%s,%s,%s)",(Name,Email,hashed_password))
            mydatabase.commit()
            return jsonify({"Message":"Registered Successfully."})
            
        except Exception as e:
            return jsonify({"Message":f"{e}"})



@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("Email")
    password = data.get("Password")

    if not email or not password:
        return jsonify({"error": "Email and Password are required"}), 400

    try:
        mycursor.execute("SELECT * FROM app_test_table WHERE Email = %s", (email,))
        user = mycursor.fetchone()
        print(user)

        if not user:
            return jsonify({"error": "Email not found"}), 404

        user_id, name, db_email, db_password = user
        print(name)

        if bcrypt.checkpw(password.encode("utf-8"), db_password.encode("utf-8")):

            payload = {
                "user_id":user_id,
                "email": db_email,
                "exp": datetime.utcnow() + timedelta(hours=24)
            }
            token = jwt.encode(payload, jwt_secret, algorithm="HS256")

            response = jsonify({
                "message": "Logged in successfully!",
                "token": token,
                "Name": name,
                "Email": email
            })

            response.headers["Authorization"] = f"Bearer {token}"

            return response, 200
        else:
            return jsonify({"error": "Incorrect password"}), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/create_task", methods=["POST"])
@token_required
def create_task():
    data = request.get_json()

    title = data.get("title")
    description = data.get("description")
    due_date = data.get("due_date")
    user_id = request.user_id

    if not title or not due_date:
        return jsonify({"error": "Title and Due date are required"}), 400

    try:
        mycursor.execute(
            """
            INSERT INTO tasks (title, description, due_date, user_id)
            VALUES (%s, %s, %s, %s)
            """,
            (title, description, due_date, user_id)
        )
        mydatabase.commit()

        return jsonify({"message": "Task created successfully"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/get_tasks", methods=["GET"])
@token_required
def get_tasks():
    user_id = request.user_id
    print(user_id)

    try:
        mycursor.execute("SELECT * FROM tasks WHERE user_id = %s", (user_id,))
        tasks = mycursor.fetchall()

        result = []
        for task in tasks:
            result.append({
                "id": task[0],
                "title": task[1],
                "description": task[2],
                "due_date": task[3],
                "status": task[4]
            })

        return jsonify({"tasks": result}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/update_task", methods=["PUT"])
@token_required
def update_task():
    data = request.get_json()

    task_id = data.get("id")
    title = data.get("title")
    description = data.get("description")
    due_date = data.get("due_date")
    status = data.get("status")
    user_id = request.user_id
    if not task_id:
        return jsonify({"error":"Please provide id number also."}),400
    try:
        mycursor.execute(
            """
            UPDATE tasks 
            SET title = %s, description = %s, due_date = %s, status = %s
            WHERE id = %s AND user_id = %s
            """,
            (title, description, due_date, status, task_id, user_id)
        )
        mydatabase.commit()

        return jsonify({"message": "Task updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/delete_task", methods=["DELETE"])
@token_required
def delete_task():
    data = request.get_json()
    task_id = data.get("id")

    if not task_id:
        return jsonify({"error": "Task ID is required"}), 400

    try:
        mycursor.execute("DELETE FROM tasks WHERE id = %s", (task_id,))
        mydatabase.commit()

        return jsonify({"message": "Task deleted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/add_member", methods=["POST"])
@token_required
def add_member():
    data = request.get_json()
    task_id = data.get("task_id")
    user_email = data.get("user_email")

    if not task_id or not user_email:
        return jsonify({"error": "Task ID and User Email are required"}), 400

    try:
        mycursor.execute(
            "INSERT INTO task_members (task_id, user_email) VALUES (%s, %s)",
            (task_id, user_email)
        )
        mydatabase.commit()

        return jsonify({"message": "Member added successfully"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/get_members", methods=["GET"])
@token_required
def get_members():
    task_id = request.args.get("task_id")

    if not task_id:
        return jsonify({"error": "Task ID is required"}), 400

    try:
        mycursor.execute(
            "SELECT user_email FROM task_members WHERE task_id = %s",
            (task_id,)
        )
        members = [row[0] for row in mycursor.fetchall()]

        return jsonify({"members": members}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/update_status", methods=["PUT"])
@token_required
def update_status():
    data = request.get_json()
    task_id = data.get("id")
    status = data.get("status")

    valid_statuses = ["Todo", "Inprogress", "Done"]

    if status not in valid_statuses:
        return jsonify({"error": "Invalid status"}), 400

    try:
        mycursor.execute(
            "UPDATE tasks SET status = %s WHERE id = %s",
            (status, task_id)
        )
        mydatabase.commit()

        return jsonify({"message": "Task status updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500




if __name__ == '__main__':
    app.run(debug=True)
