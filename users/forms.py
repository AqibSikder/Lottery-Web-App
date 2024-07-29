#IMPORTS
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, Length, ValidationError, EqualTo
import re

# INPUT VALIDATION - first name and last name character check
def character_check(form, field):
    excluded_chars = "*?!'^+%&/()=}][{$#@<>"

    for char in field.data:
        if char in excluded_chars:
            raise ValidationError(f"Character {char} is not allowed.")


# INPUT VALIDATION - Password validation check
def validate_pass(form, field):
    p = re.compile("(?=.*\d)(?=.*\W)(?=.*[A-Z])(?=.*[a-z])")
    if not p.match(field.data):
        raise ValidationError(f"Must contain at least 1 lower case and upper case letter,1 digit and 1 special character")


# INPUT VALIDATION - Phone digits format check
def validate_phone(form, field):
    p = re.compile("(^\d{4})(?=-)(?=.*\d{3})(?=-)(?=.*\d{4})")
    if not p.match(field.data):
        raise ValidationError(f"Must be digits of the form: XXXX-XXX-XXXX (including the dashes)")

# Rendering of the registration form and validators
class RegisterForm(FlaskForm):
    email = StringField(validators=[DataRequired(), Email()])
    firstname = StringField(validators=[DataRequired(), character_check])
    lastname = StringField(validators=[DataRequired(), character_check])
    phone = StringField(validators=[DataRequired(), validate_phone])
    password = PasswordField(validators=[DataRequired(), Length(min=6, max=12), validate_pass])
    confirm_password = PasswordField(validators=[DataRequired(), EqualTo('password', message="Both password fields must be equal!")])
    submit = SubmitField()

# Rendering of the login form and validators
class LoginForm(FlaskForm):
    recaptcha = RecaptchaField()
    email = StringField(validators=[DataRequired(), Email()])
    password = PasswordField(validators=[DataRequired()])
    submit = SubmitField()
