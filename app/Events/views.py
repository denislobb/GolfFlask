from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from . import event
from .. import db
from ..models import User


@event.before_app_request
def before_request():
    if current_user.is_authenticated \
            and current_user.role_id == 3:
        return


@event.route('event/create')
def event_create()
    form = LoginFo