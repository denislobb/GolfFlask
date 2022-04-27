from flask import Blueprint

event = Blueprint('auth', __name__)

from . import views