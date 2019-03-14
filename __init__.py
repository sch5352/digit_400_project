from flask import Flask, render_template, url_for, flash, redirect, request, session
from wtforms import Form, BooleanField, TextField, PasswordField, validators
from passlib.hash import sha256_crypt
from pymysql import escape_string as thwart
from functools import wraps
import gc
import os, sys; sys.path.append(os.path.dirname(os.path.realpath(__file__)))
from content import Content

from db_connect import connection 



app = Flask(__name__)

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash("Please login.")
            return redirect(url_for('login'))


APP_CONTENT = Content()



@app.route("/", methods=["GET", "POST"])
def index():
    error = ""
    try:
        c, conn = connection()
        if request.method == "POST":
            
            data = c.execute("SELECT * FROM users WHERE username = ('{0}')".format(thwart(request.form['username'])))
            
            data = c.fetchone()[2]
        
            if sha256_crypt.verify(request.form["password"],data):
                session['logged_in'] = True
                session['username'] = request.form['username']
                
                flash("You are now logged in " +session['username']+"!")
                return redirect(url_for("dashboard"))
            else:
                error = "Invalid credentials, try again."
    
        return render_template("main.html", error = error)
    
    except Exception as e:
        flash(e) #remove for production
        error = "Invalid credentials, try again."
    return render_template("main.html", error = error)
    
    

@login_required
@app.route("/dashboard/")
def dashboard():
    try:
        return render_template("dashboard.html", APP_CONTENT = APP_CONTENT)
    except Exception as e:
        return render_template("500.html", error = e)

    
@app.route("/login/", methods=["GET", "POST"])
def login():
    error = ""
    try:
        c, conn = connection()
        if request.method == "POST":
            
            data = c.execute("SELECT * FROM users WHERE username = ('{0}')".format(thwart(request.form['username'])))
            
            data = c.fetchone()[2]
        
            if sha256_crypt.verify(request.form["password"],data):
                session['logged_in'] = True
                session['username'] = request.form['username']
                
                flash("You are now logged in " +session['username']+"!")
                return redirect(url_for("dashboard"))
            else:
                error = "Invalid credentials, try again."
    
        return render_template("login.html", error = error)
    
    except Exception as e:
        flash(e) #remove for production
        error = "Invalid credentials, try again."
    return render_template("login.html", error = error)
    
@login_required    
@app.route("/logout/")
def logout():
    session.clear()
    flash("You have been logged out!")
    gc.collect()
    return redirect(url_for("index"))
    
    
    
class RegistrationForm(Form): #like nursery for functions
    username = TextField("Username", [validators.Length(min=4, max=20)])
    email = TextField("Email Address", [validators.Length(min=6, max=50)])
    password = PasswordField("New Password", [validators.Required(),
                                             validators.EqualTo('confirm', message="Passwords must match")])
    
    confirm = PasswordField("Repeat Password")
    accept_tos = BooleanField("I accept the Terms of Service and Privacy Notice", [validators.Required()])

    
    
@app.route('/register/', methods=["GET","POST"])
def register_page():
    #c, conn = connection() #if it runs, it will post a string
    try:
        form = RegistrationForm(request.form)
        if request.method == "POST" and form.validate():
            username = form.username.data
            email = form.email.data
            password = sha256_crypt.encrypt((str(form.password.data))) 
            
            c, conn = connection() #if it runs, it will post a string
            
            x = c.execute("SELECT * FROM users WHERE username = ('{0}')".format((thwart(username))))
            
            if int(x) > 0:
                flash("That username is already taken, please choose another.")
                return render_template("register.html", form = form)
            else:
                c.execute("INSERT INTO users (username,password,email,tracking) VALUES ('{0}','{1}','{2}','{3}')".format(thwart(username),thwart(password),thwart(email),thwart("/dashboard/")))
                
                
                conn.commit()
                flash("Thanks for registering "+username+"!")
                conn.close()
                gc.collect()
                
                session['logged_in'] = True
                session['username'] = username
            
                return redirect(url_for('dashboard'))
        return render_template("register.html", form = form)
                
    except Exception as e:
        return(str(e)) #remember to remove for debugging only
    
    
##Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template ("404.html")

@app.errorhandler(405)
def methods_not_allowed(e):
    return render_template("405.html")

@app.errorhandler(500)
def server_error(e):
    return render_template ("500.html", error = e)



if __name__=="__main__":
    app.run(debug=True) #This should be turned off/False for production
