from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, DateField, IntegerRangeField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo, NumberRange, AnyOf
from wtforms import ValidationError
from ..models import User, Event
from datetime import datetime, date


class EventForm(FlaskForm):
    today = date.today

    event_name = StringField('Name of Event', validators=[DataRequired()])

    event_date = DateField('Day of Event', default=today)

    event_start_time = StringField('Start Time of Event', validators=[DataRequired()])

    scoring_format = StringField('Type of Event',
                             validators=[DataRequired(), AnyOf(['Stroke', 'Stableford', 'Par'])])

    event_course = StringField('Which course?', validators=[DataRequired()])

    event_tee = StringField('Event tees',
                            validators=[DataRequired(), AnyOf(['black', 'blue', 'white', 'red', 'gold'])])

    course_slope_rating = IntegerRangeField('Slope rating?',
                                            validators=[DataRequired(), NumberRange(min=1, max=150)])

    course_scratch_rating = IntegerRangeField('Scratch rating',
                                              validators=[DataRequired(), NumberRange(min=65, max=75)])

    course_par_rating = IntegerRangeField('Course par', validators=[DataRequired()])

    submit = SubmitField('Register Event')

    def validate_on_submit(self):
        result = super(EventForm, self).validate()
        if self.event_name < date.today:
            return False
        else:
            return result

