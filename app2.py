import os
import psycopg2
from datetime import datetime
from flask import Flask, render_template, url_for, flash, redirect, request, jsonify
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, Form
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String, Text, Binary, Column, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, backref
from flask_admin import Admin 
from flask_admin.contrib.sqla import ModelView
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
bootstrap = Bootstrap(app)


if os.environ.get('DATABASE_URL') is None:
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
    
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']

app.config['SECRET_KEY'] = 'd41d8cd98f00b204e9800998ecf8427e'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


# --- Forms

class DoctorSignupForm(FlaskForm):
    firstname = StringField('Firstname', validators=[DataRequired(), Length(min=4, max=20)])
    lastname = StringField('Lastname', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')



# --- Models

class User(UserMixin, db.Model) :
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(20), unique = True, nullable = False)
    password = db.Column(db.String(60), nullable=False)
    registered_on = db.Column(db.DateTime)
    is_doctor = db.Column(db.Boolean(), default=False)

    def __init__(self, id, email, password, is_doctor):
        self.email = email
        self.password = password
        self.registered_on = datetime.utcnow()
        self.is_doctor = is_doctor


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Doctor(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname  = db.Column(db.String(20), nullable = False)
    lastname  = db.Column(db.String(20), nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = relationship("User", backref=backref("doctor_id", uselist=False))

    def __init__(self, id, firstname, lastname, user_id):
        self.firstname = firstname
        self.lastname = lastname
        self.user_id = user_id


class Patient(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname  = db.Column(db.String(20), nullable = False)
    lastname  = db.Column(db.String(20), nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'), nullable=True)


    user = relationship("User", backref=backref("user_id", uselist=False))
    doctor = relationship("Doctor", backref=backref("doctor", uselist=False))

    def __init__(self, id, firstname, lastname, user_id, doctor_id):
        self.firstname = firstname
        self.lastname = lastname
        self.user_id = user_id
        self.doctor_id = doctor_id



class Checkup(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    made_on = db.Column(db.DateTime, nullable = False)
    hours_slept =  db.Column(db.Integer, nullable = False)
    humeur = db.Column(db.Integer, nullable = False)
    anxiety = db.Column(db.Integer, nullable = False)
    irritability = db.Column(db.Integer, nullable = False)
    suicidal_tendencies = db.Column(db.Integer, nullable = False)
    psychotics = db.Column(db.Integer, nullable = False)
    strange_ideas = db.Column(db.Integer, nullable = False)
    dangerous_comportment = db.Column(db.Integer, nullable = False)
    alcool = db.Column(db.Integer, nullable = False)
    drogues = db.Column(db.Integer, nullable = False)
    pills = db.Column(db.Integer, nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


    user = relationship("User", backref=backref("checkup_user_id", uselist=False))

    def __init__(self, id, made_on, hours_slept, humeur, anxiety, irritability, suicidal_tendencies, psychotics, strange_ideas, dangerous_comportment, alcool, drogues, pills, user_id):
        self.made_on = datetime.utcnow()
        self.hours_slept = hours_slept
        self.humeur = humeur
        self.anxiety = anxiety
        self.irritability = irritability
        self.suicidal_tendencies = suicidal_tendencies
        self.psychotics = psychotics
        self.strange_ideas = strange_ideas
        self.dangerous_comportment = dangerous_comportment
        self.alcool = alcool
        self.drogues = drogues
        self.pills = pills
        self.user_id = user_id

    

# ---- Routes
@app.route('/')
@app.route('/accueil')
def accueil():
    return render_template('accueil.html')


# login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)

                is_doctor = User.is_doctor

                if is_doctor == 1 :

                    return redirect(url_for('medicdashboard'))
                
                return redirect(url_for('userdashboard'))

            else :
                flash('FAIL')

    return render_template('login.html', form=form)


# inscirption
@app.route('/doctorsignup', methods=['GET', 'POST'])
def doctorsignup():
    form = DoctorSignupForm()
    
    if form.validate_on_submit():

        hashed_password = generate_password_hash(form.password.data, method='sha256')

        new_user = User(id, email = form.email.data, password = hashed_password, is_doctor = True)
        db.session.add(new_user)
        db.session.commit()

        user = User.query.filter_by(email=form.email.data).first()
        login_user(user)

        new_doctor = Doctor(id, firstname = form.firstname.data, lastname = form.lastname.data, user_id = current_user.id) 
        db.session.add(new_doctor)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('doctorsignup.html', form=form)


@app.route('/patientsignup', methods=['GET', 'POST'])
def patientsignup():
    form = DoctorSignupForm()
    
    if form.validate_on_submit():

        hashed_password = generate_password_hash(form.password.data, method='sha256')

        new_user = User(id, email = form.email.data, password = hashed_password, is_doctor = False)
        db.session.add(new_user)
        db.session.commit()

        user = User.query.filter_by(email=form.email.data).first()
        login_user(user)

        new_patient = Patient(id, firstname = form.firstname.data, lastname = form.lastname.data, user_id = current_user.id, doctor_id = None) 
        db.session.add(new_patient)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('patientsignup.html', form=form)


# dashboard pour medecin
"""@app.route('/medicdashboard')
@login_required
def medicdashboard():
    return '<h1> MEDIC DASHBOARD </h1>'"""


# checkup pour patients
@app.route('/checkup')
@login_required
def checkup():
    return render_template('checkup.html')


#send checkup
@app.route('/post_checkup', methods=['POST'])
@login_required

def post_checkup():

    if request.method  == 'POST':

        hours_slept = request.form['hours_slept']
        humeur = request.form['mood']
        anxiety = request.form['anxiety']
        irritability = request.form['irritability']
        suicidal_tendencies = request.form['suicidal_tendencies']
        psychotics = request.form['psychotics']
        strange_ideas = request.form['strange_ideas']
        dangerous_comportment = request.form['dangerous_comportment']
        alcool = request.form['alcool']
        drogues = request.form['drogues']
        pills = request.form['pills']
        user_id = current_user.id

        new_checkup = Checkup(id, made_on = datetime.now, hours_slept = request.form['hours_slept'], humeur = request.form['mood'], anxiety = request.form['anxiety'], irritability = request.form['irritability'], suicidal_tendencies = request.form['suicidal_tendencies'], psychotics = request.form['psychotics'], strange_ideas = request.form['strange_ideas'], dangerous_comportment = request.form['dangerous_comportment'], alcool = request.form['alcool'], drogues = request.form['drogues'], pills = request.form['pills'], user_id = current_user.id)
        db.session.add(new_checkup)
        db.session.commit()

        return redirect(url_for('accueil'))


@app.route('/userdashboard')
@login_required
def userdashboard():

    usr_che = Checkup.query.filter_by(user_id = current_user.id).all()
    return render_template('data.html', usr = usr_che)

# deco
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('accueil'))


if __name__ == '__main__' :
    app.run(debug=True)
