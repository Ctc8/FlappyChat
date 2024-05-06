from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, LoginManager, UserMixin, login_required, current_user, logout_user
from flask_cors import CORS
from werkzeug.security import generate_password_hash
import random
from flask_socketio import SocketIO, send, emit, join_room, leave_room
from string import ascii_uppercase

from sqlalchemy.orm import relationship

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///db.sqlite3"
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

app.config["SECRET_KEY"] = "1234"
socketio = SocketIO(app, cors_allowed_origins="*")


class User(UserMixin, db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(30), unique=True) 
  password = db.Column(db.String(30))  

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    sender = relationship('User', foreign_keys=[sender_id])
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver = relationship('User', foreign_keys=[receiver_id])
    content = db.Column(db.String(500))
    

@app.route("/home", methods=["POST", "GET"])
@login_required
def home():
    if request.method == "POST":
        receiver_username = request.form.get("username")
        receiver = User.query.filter_by(username=receiver_username).first()
        if not receiver:
            flash("User does not exist!")
            return redirect(url_for('home'))
        return redirect(url_for('chat', receiver_id=receiver.id))
    return render_template("home.html", user=current_user.username)



@app.route('/chat/<receiver_id>', methods=['GET', 'POST'])
def chat(receiver_id):
    room = sorted([current_user.id, int(receiver_id)])
    room_name = f'{room[0]}_{room[1]}'

    if request.method == 'POST':
        
        message_content = request.form.get('message')
        new_message = Message(content=message_content, sender_id=current_user.id, receiver_id=receiver_id)
        db.session.add(new_message)
        db.session.commit()

        socketio.emit('new_message', {'content': message_content, 'sender_id': current_user.id}, room=room_name)

        return redirect(url_for('chat', receiver_id=receiver_id))

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == receiver_id)) |
        ((Message.sender_id == receiver_id) & (Message.receiver_id == current_user.id))
    ).all()
    return render_template('chat.html', messages=messages, user=current_user.username, broadcast=True)

@app.route("/")
def index():
    return render_template('login.html')

@socketio.on('join_room')
def handle_join_room(data):
    join_room(data['room'])

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

        return redirect(url_for("home"))

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
      session['username'] = username  
      return redirect(url_for('home'))

    error = 'Invalid username or password'

  signup_url = url_for('signup')
  return render_template('login.html', error=error, signup_url=signup_url)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    socketio.run(app,debug=True)