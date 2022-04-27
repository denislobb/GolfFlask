from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask import current_app
from flask_login import UserMixin, AnonymousUserMixin
from . import db, login_manager

# import app


event_course = db.Table('event_course',
                        db.Column('event_id', db.Integer, db.ForeignKey('events.id')),
                        db.Column('course_id', db.Integer, db.ForeignKey('courses.id'))
                        )

user_event = db.Table('user_event',
                               db.Column('user_id', db.Integer, db.ForeignKey('users.id')),
                               db.Column('event_id', db.Integer, db.ForeignKey('events.id'))
                               )


class Permission:
    FOLLOW = 1  # Follow users
    COMMENT = 2  # Comment on posts made by others
    WRITE = 4  # Write articles
    MODERATE = 8  # Moderate comments made by others
    ADMIN = 16  # Administration Access


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

    @staticmethod
    def insert_roles():
        roles = {
                'User': [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE],
                'Moderator': [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE,
                              Permission.MODERATE],
                'Administrator': [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE,
                                  Permission.MODERATE, Permission.ADMIN]
        }
        default_role = 'User'
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permissions()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default = (role.name == default_role)
            db.session.add(role)
        db.session.commit()

    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm

    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm

    def reset_permissions(self):
        self.permissions = 0

    def has_permission(self, perm):
        return self.permissions & perm == perm

    def __repr__(self):
        return f'<Role {self.name}'


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    golflink = db.Column(db.Integer, unique=True, index=True)
    handicap = db.Column(db.Float)
    handicap_updated = db.Column(db.DateTime(), default=datetime.utcnow)
    mobile = db.Column(db.String(12))
    date_of_birth = db.Column(db.DateTime())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    events = db.relationship('Event',
                             secondary=user_event,
                             backref=db.backref('users', lazy='dynamic'),
                             lazy='dynamic')

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['GOLFER_ADMIN']:
                self.role = Role.query.filter_by(name='Administrator').first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'confirm': self.id},
                       salt=current_app.config['SECURITY_PASSWORD_SALT'])

    def confirm(self, token, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token,
                           salt=current_app.config['SECURITY_PASSWORD_SALT'],
                           max_age=expiration)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    def generate_reset_token(self):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'reset': self.id},
                       salt=current_app.config['SECURITY_PASSWORD_SALT'])

    @staticmethod
    def reset_password(token, new_password, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token,
                           salt=current_app.config['SECURITY_PASSWORD_SALT'],
                           max_age=expiration)
        except:
            return False
        user = User.query.get(data.get('reset'))
        if user is None:
            return False
        user.password = new_password
        db.session.add(user)
        return True

    def generate_email_change_token(self, new_email, ):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'change_email': self.id, 'new_email': new_email},
                       salt=current_app.config['SECURITY_PASSWORD_SALT'])

    def change_email(self, token, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token,
                           salt=current_app.config['SECURITY_PASSWORD_SALT'],
                           max_age=expiration)
        except:
            return False
        if data.get('change_email') != self.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email = new_email
        db.session.add(self)
        return True

    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)

    def is_administrator(self):
        return self.can(Permission.ADMIN)

    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return f'<User {self.username}'


class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False


login_manager.anonymous_user = AnonymousUser


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    event_name = db.Column(db.String(64), index=True)
    date = db.Column(db.DateTime, index=True, default=datetime.now)
    start_time = db.Column(db.DateTime, default=datetime.now)
    scoring_format = db.Column(db.String(64), default="Stroke")
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'))

    def __repr__(self):
        return f"<Event(event_name={self.event_name}, event_date={self.date}, scoring_format={self.scoring_format}"


class Course(db.Model):
    __tablename__ = 'courses'
    id = db.Column(db.Integer, primary_key=True)
    course_name = db.Column(db.String(64), unique=True, index=True)
    tee_box = db.Column(db.String(64))
    slope_rating = db.Column(db.Integer)
    scratch_rating = db.Column(db.Integer)
    course_par = db.Column(db.Integer)
    holes = db.relationship('Hole', backref='course', lazy='dynamic')
    events = db.relationship('Event',
                             secondary=event_course,
                             backref=db.backref('course', lazy='dynamic'),
                             lazy='dynamic')

    def __repr__(self):
        return f"<Course(course_name={self.course_name}, tee-box={self.tee_box}, slope_rating={self.slope_rating}"


class Hole(db.Model):
    __tablename__ = 'holes'
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False, index=True)
    hole_number = db.Column(db.Integer, nullable=False, index=True)
    length = db.Column(db.Integer, nullable=False)
    par = db.Column(db.Integer, nullable=False)
    hcap_index = db.Column(db.Integer, nullable=False)
    match_index = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"<Hole(hole_number={self.hole_number}, " \
               f"length={self.length}, par={self.par}, hcap_index={self.hcap_index}"


