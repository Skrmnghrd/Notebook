
import sqlite3 
from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
#from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, SelectField
from passlib.hash import sha256_crypt
from functools import wraps
from string import maketrans
from flask import Flask, render_template
from flask.ext.wtf import Form, widgets, SelectMultipleField
"""app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        data = (request.form.getlist('hello'))

      	if request.form.get('match-with-pairs'):
      		var1 = 'awdawdawd'
    		return render_template('checkbox.html', data=data,var1=var1)
    return render_template('checkbox.html', data=data)
"""

SECRET_KEY = 'development'

app = Flask(__name__)
app.config.from_object(__name__)

class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()


class SimpleForm(Form):
    string_of_files = ['one\r\ntwo\r\nthree\r\n']
    list_of_files = string_of_files[0].split()
    # create a list of value/description tuples
    files = [(x, x) for x in list_of_files]
    example = MultiCheckboxField('Label', choices=files)

@app.route('/',methods=['post','get'])
def hello_world():
    form = SimpleForm()
    if form.validate_on_submit():
        print form.example.data
    else:
        print form.errors
    return render_template('example.html',form=form)

app.run(port=1214, debug=True)