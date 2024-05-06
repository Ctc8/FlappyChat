from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, LoginManager, UserMixin, login_required, current_user, logout_user

from werkzeug.security import generate_password_hash
import random
from flask_socketio import join_room, leave_room, send, SocketIO
from string import ascii_uppercase


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///db.sqlite3"
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

app.config["SECRET_KEY"] = "1234"
socketio = SocketIO(app)

rooms = {}

class User(UserMixin, db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(30), unique=True) 
  password = db.Column(db.String(30))  

def generate_unique_code(length):
    while True:
        code =""
        for _ in range(length):
            code += random.choice(ascii_uppercase)

        if code not in rooms:
            break
    return code

@app.route("/")
def index():
    return render_template('login.html')

# @app.route('/home', methods=['GET', 'POST'])
# def home():
#     user_name = session.get('username')  # Retrieve the username from the session
#     # if request.method == 'POST':
#     #     # Your POST handling code...
#     return render_template('home.html', user=user_name)

# Signup
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return render_template("signup.html", error="Please enter a username and password!")

        user = User.query.filter_by(username=username).first()

        if user:
            return render_template("signup.html", error="Username already exists!")

        # new_user = User(username=username, password=generate_password_hash(password))
        new_user = User(username=username, password=(password))
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("signup.html")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#Login
@app.route('/login', methods=['GET', 'POST'])
def login():
  error = None
  if request.method == 'POST':
    username = request.form.get('username')
    password = request.form.get('password')

    user = User.query.filter_by(username=username).first()    

    if user and user.password == password:  
      login_user(user)
      session['username'] = username  # Store the username in the session
      return redirect(url_for('chat'))

    error = 'Invalid username or password'

    signup_url = url_for('signup')
  return render_template('login.html', error=error)


@app.route("/chat",methods=["POST","GET"])
def chat():
    if request.method == "POST":
        name = session.get('username')  # Get the name from the session
        code = request.form.get("code")
        join = request.form.get("join",False)
        create = request.form.get("create",False)

        if not name:
            return redirect(url_for('login'))  # Redirect to login if there's no name in the session
        
        if join != False and not code:
            return render_template("home.html",error="Please enter a room code!",code=code,name=name)
        
        room = code
        if create != False:
            room = generate_unique_code(4)
            rooms[room] = {"members":0,"messages": []}
        elif code not in rooms:
            return render_template("home.html",error="Room does not exist!",code=code,name=name)

        session["room"] = room
        session["name"] = name
        return redirect(url_for("room"))
    
    room_list = list(rooms.keys())  # Retrieve the list of room codes
    return render_template("home.html", rooms=room_list)


@app.route("/room")
def room():
    room = session.get("room")
    if room is None or session.get("name") is None or room not in rooms:
        return redirect(url_for("chat"))
    
    return render_template("room.html",code=room,messages=rooms[room]["messages"])

@socketio.on("message")
def message(data):
    room = session.get("room")
    if room not in rooms:
        return 
    
    content = {
        "name": session.get("name"),
        "message": data["data"]
    }
    send(content, to=room)
    rooms[room]["messages"].append(content)
    print(f"{session.get('name')} said: {data['data']}")

@socketio.on("connect")
def connect(auth):
    room = session.get("room")
    name = session.get("name")
    if not room or not name:
        return
    if room not in rooms:
        leave_room(room)
        return
    
    join_room(room)
    send({"name":name,"message":"has entered the room"},to=room)
    rooms[room]["members"] += 1
    print(f"{name} joined room {room}")

@socketio.on("disconnect")
def disconnect():
    room = session.get("room")
    name = session.get("name")
    leave_room(room)

    if room in rooms:
        rooms[room]["members"] -= 1
        if rooms[room]["members"] <= 0:
            del rooms[room]
    
    send({"type": "leave", "name": name, "message": "has left the room"}, to=room)
    print(f"{name} has left the room {room}")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    socketio.run(app,debug=True)
