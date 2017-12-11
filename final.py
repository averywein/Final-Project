import os
from flask_login import UserMixin, login_required, LoginManager, login_user, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, session, redirect, url_for, flash
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import Required, Length, Regexp, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy

from flask_migrate import Migrate, MigrateCommand

from flask_mail import Mail, Message
from threading import Thread
from werkzeug import secure_filename

import tweepy
import requests

Google_Maps_Key = "AIzaSyD8CbMh0oA4aa7-CNbEw1jEfPWJRV5MHTg"

auth = tweepy.OAuthHandler("dPHhI8kGXbWv3zZcWGlQD1Ebx", "QomDeBs0IlKRP5MPTdiUwBx1mBV8Ynl74NDowuj3OyQp4XFGQe")
auth.set_access_token("791353066612224000-8X2ZLy6ZXe0Hcs0Yet5Rw0jYCi3i96e", "FtJzRNSTabKedppBg7P25loeF08emDPXFf3dNRwlY3dd6")

api = tweepy.API(auth)

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'hardtoguessstringfromsi364(thisisnotsupersecure)'

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://localhost/averywfinalproject1"
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587 
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "averywein2@gmail.com"
app.config['MAIL_PASSWORD'] = "carefree"
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') 
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_SUBJECT_PREFIX'] = '[Songs App]'
app.config['MAIL_SENDER'] = 'Admin <averywein2@gmail.com>' 
app.config['ADMIN'] = "averywein2@gmail.com"

manager = Manager(app)
db = SQLAlchemy(app) 
migrate = Migrate(app, db) 
manager.add_command('db', MigrateCommand) 
mail = Mail(app) 
login_manager = LoginManager()
login_manager.init_app(app) 
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'

def make_shell_context():
    return dict(app=app, db=db, Tweet=Tweet, User=User, Hashtag=Hashtag)

manager.add_command("shell", Shell(make_context=make_shell_context))

def send_email(app, msg):
    with app.app_context():
        mail.send(msg)

def send_new_email(to, subject, template, **kwargs):
    msg = Message(app.config['MAIL_SUBJECT_PREFIX'] + ' ' + subject,
                  sender=app.config['MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    thr = Thread(target=send_email, args=[app, msg]) 
    thr.start()
    return thr 

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True) 
    email = db.Column(db.String(64), unique=True)
    password_hash = db.Column(db.String(200))

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
class Hashtag(db.Model):
    __tablename__ = 'hashtags'
    id = db.Column(db.Integer, primary_key=True) 
    text = db.Column(db.String) 
    location_id = db.Column(db.Integer, db.ForeignKey('locations.id'))

class Location(db.Model):
    __tablename__ = 'locations'
    id = db.Column(db.Integer, primary_key=True)
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    name = db.Column(db.String(64), unique=True)

class User_Searches(db.Model):
    __tablename__ = 'searches'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    hashtag_id = db.Column(db.Integer, db.ForeignKey('hashtags.id'))


def getTweets(hashtag, location_name, user):
    coordinates = requests.get("https://maps.googleapis.com/maps/api/geocode/json", params = {'address' : location_name, "key" : Google_Maps_Key}).json()["results"][0]["geometry"]["location"]
    location=get_or_create_location(coordinates, location_name)
    new_hashtag = get_or_create_hashtag(hashtag, location.id)
    new_search=get_or_create_search(user.id, new_hashtag.id)
    return api.search(hashtag, geocode="{},{},15mi".format(coordinates["lat"], coordinates['lng']))

def get_or_create_search(user_id, hashtag_id):
    search = db.session.query(User_Searches).filter_by(user_id=user_id, hashtag_id=hashtag_id).first()
    if search:
        return search
    else:
        search = User_Searches(user_id=user_id, hashtag_id=hashtag_id)
        db.session.add(search)
        db.session.commit()
        return search

def get_or_create_hashtag(text, loc_id):
    hashtag = db.session.query(Hashtag).filter_by(text=text, location_id=loc_id).first()
    if hashtag:
        return hashtag
    else:
        hashtag = Hashtag(text=text, location_id=loc_id)
        db.session.add(hashtag)
        db.session.commit()
        return hashtag

def get_or_create_location(coord_dict, location_name):
    loc = db.session.query(Location).filter_by(name=location_name).first()
    if loc:
        return loc
    else:
        loc = Location(name=location_name, lat=coord_dict["lat"], lng=coord_dict['lng'])
        db.session.add(loc)
        db.session.commit()
        return loc

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

class RegistrationForm(FlaskForm):
    email = StringField('Email:', validators=[Required(),Length(1,64),Email()])
    password = PasswordField('Password:',validators=[Required(),EqualTo('password2',message="Passwords must match")])
    password2 = PasswordField("Confirm Password:",validators=[Required()])
    submit = SubmitField('Register User')

    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1,64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

@app.route('/login',methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return(redirect("/"))
        flash('Invalid username or password.')
    return render_template('login.html',form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('index'))

@app.route('/register',methods=["GET","POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You can now log in!')
        return redirect(url_for('login'))
    return render_template('register.html',form=form)


class HashtagSearch(FlaskForm):
    hashtag = StringField("What is your hashtag?", validators=[Required()])
    location = StringField("What is your desired location?",validators=[Required()])
    submit = SubmitField('Submit')

@app.route('/')
@login_required
def index():
    form = HashtagSearch()
    return render_template('index.html', form=form)

@app.route('/tweets', methods=["POST"])
@login_required
def tweet_results():
    form = HashtagSearch()
    if form.validate_on_submit():
        send_new_email(current_user.email, "Tweets for Hashtag", "mail/hashtagResults", list_tweets=getTweets(form.hashtag.data,form.location.data, current_user), hashtag=form.hashtag.data,location=form.location.data)
        return render_template("tweets.html", list_tweets=getTweets(form.hashtag.data,form.location.data, current_user), hashtag=form.hashtag.data,location=form.location.data)

@app.route('/hashtag/<ht>/location/<location>', methods=["GET"])
@login_required
def hashtag_loc(ht, location):
    return render_template("tweets.html", list_tweets=getTweets(ht, location, current_user), hashtag=ht,location=location)


@app.route('/history', methods=["GET"])
@login_required
def history():
    return render_template("history.html", list_of_searches=db.session.query(User_Searches, Hashtag, Location).filter(User_Searches.user_id==current_user.id).join(Hashtag).join(Location).all())


if __name__ == '__main__':
    db.create_all()
    manager.run()