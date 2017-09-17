#!/usr/bin/python
import sqlite3 
<<<<<<< HEAD
from flask import Flask, render_template, flash, redirect, url_for, session, request, logging, jsonify
=======
from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
>>>>>>> 840c399edd6dec43958d3a4d5cf7fd0e419ce125
#from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, SelectField
from passlib.hash import sha256_crypt
from functools import wraps
from string import maketrans
<<<<<<< HEAD
import netmiko
import base64
#cgi.escape sucks
=======

>>>>>>> 840c399edd6dec43958d3a4d5cf7fd0e419ce125
app = Flask(__name__)

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'password'
app.config['MYSQL_DB'] = 'cheatsheet'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# init MYSQL
mysql = MySQL(app)
db_name = 'test.db'
<<<<<<< HEAD

banned_characters = ['%','<','"','\'','--+', '--', '=','<script>','</script']
=======
>>>>>>> 840c399edd6dec43958d3a4d5cf7fd0e419ce125
#sqliteshitandstuff
def interact_with_db(db_name, query):
    con = sqlite3.connect(db_name)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute(str(query))
    rows = cur.fetchall()
    cur.close
    return rows


# Index
@app.route('/')
def index():
    return render_template('home.html')

# About
@app.route('/about')
def about():
    return render_template('about.html')


# Articles
@app.route('/articles')
def articles():
<<<<<<< HEAD
   articles = interact_with_db(db_name, "SELECT * FROM commands order by id desc")
=======
   articles = interact_with_db(db_name, "SELECT * FROM commands")
>>>>>>> 840c399edd6dec43958d3a4d5cf7fd0e419ce125
   return render_template('articles.html', articles=articles)
#Single Article
@app.route('/article/<string:id>/')
def article(id):
    con = sqlite3.connect(db_name)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute('SELECT * FROM commands WHERE id=?', ([id]))
    result = cur.fetchall()
    cur.close
    return render_template('article.html', result=result)

# Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    #query to test if username exists, then warning else go :D 
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        
        con = sqlite3.connect(db_name)
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        cur.execute("SELECT * FROM users WHERE username=?", ([username]))
        exist = cur.fetchone()
        #print exist
        if exist is None:
            cur.execute("INSERT INTO users(name, username, password) VALUES(?, ?, ?)", (name, username, password,))
            con.commit()
            cur.close
            flash('You are now registered and can log in', 'success')
            return redirect(url_for('login'))
        else:
            flash ('User already exists, Please try a different username', 'danger')
            return render_template('register.html', form=form)

           
    return render_template('register.html', form=form)

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        con = sqlite3.connect(db_name)
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']
        result = cur.execute("SELECT * FROM users WHERE username=?", ([username]))
        exist = cur.fetchone()

        if exist is None:
            error = 'Username not found'
            return render_template('login.html', error=error)
        else:
            password = exist['password']

            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in,You can now edit articles', 'danger')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            # Close connection
            cur.close()
    return render_template('login.html')

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    # Create cursor
    con = sqlite3.connect(db_name)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
<<<<<<< HEAD
    result = cur.execute("SELECT * FROM commands ORDER BY id DESC")
=======
    result = cur.execute("SELECT * FROM commands")
>>>>>>> 840c399edd6dec43958d3a4d5cf7fd0e419ce125

    articles = cur.fetchall()

    if result > 0:
        return render_template('dashboard.html', articles=articles)
    else:
        msg = 'No Articles Found'
        return render_template('dashboard.html', msg=msg)
    # Close connection
    cur.close()

# Article Form Class
class ArticleForm(Form):
<<<<<<< HEAD
    commands = TextAreaField('Commands: ', [validators.Length(min=0)])
    explaination = TextAreaField('Explaination: ', [validators.Length(min=0)])
    notes = TextAreaField('Notes: ', [validators.Length(min=0)])
    topic_name = TextAreaField('Topic Name: ', [validators.Length(min=1, max=2000)])
=======
    commands = TextAreaField('Commands: ', [validators.Length(min=1, max=2000)])
    explaination = TextAreaField('Explaination: ', [validators.Length(min=10)])
    notes = TextAreaField('Notes: ', [validators.Length(min=10)])
    topic_name = StringField('Commands: ', [validators.Length(min=1, max=2000)])
>>>>>>> 840c399edd6dec43958d3a4d5cf7fd0e419ce125
    tags = TextAreaField('Tags: (Are used for searching please separate with spaces) ', [validators.Length(min=1, max=2000)])
# Add Article
@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():

        commands = form.commands.data
        explaination = form.explaination.data
        notes = form.notes.data
        topic_name = form.topic_name.data
        tags = form.tags.data
        # Create Cursor
        con = sqlite3.connect(db_name)
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        #topic_name, tags
        # Execute
        cur.execute("INSERT INTO commands(commands, explaination, notes, topic_name, tags) VALUES(?, ?, ?, ?, ?)", (commands, explaination, notes, topic_name, tags,))
        #session['username']))
        # Commit to DB
        con.commit()
        #Close connection
        cur.close()

        flash('Article Created', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_article.html', form=form)


# Edit Article
@app.route('/edit_article/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_article(id):
    # Create cursor
    con = sqlite3.connect(db_name)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    # Get article by id
    result = cur.execute("SELECT * FROM commands WHERE id =?", ([id]))
    article = cur.fetchone()
    cur.close()
    # Get form
    form = ArticleForm(request.form)

    # Populate article form fields
    form.commands.data = article['commands']
    form.explaination.data = article['explaination']
    form.notes.data = article['notes']
    form.topic_name.data = article['topic_name']
    form.tags.data = article['tags']

    if request.method == 'POST' and form.validate():
        commands = request.form['commands']
        explaination = request.form['explaination']
        notes = request.form['notes']
        topic_name = request.form['topic_name']
        tags = request.form['tags']

        # Create Cursor
        con = sqlite3.connect(db_name)
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        app.logger.info(topic_name)
        with con:
            cur.execute("UPDATE commands SET commands=?, explaination=?, notes=?, topic_name=?, tags=? WHERE id=?", (commands, explaination, notes, topic_name, tags, id))
        # Commit to DB
            con.commit()
        #Close connection
        cur.close()

        flash('Article Updated', 'success')

        return redirect(url_for('dashboard'))

    return render_template('edit_article.html', form=form)

# Delete Article
@app.route('/delete_article/<string:id>', methods=['POST'])
@is_logged_in
def delete_article(id):
    # Create cursor
    con = sqlite3.connect(db_name)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    with con:
        cur.execute("DELETE FROM commands WHERE id = ?", ([id]))
        con.commit()

    cur.close()

<<<<<<< HEAD
    flash("Article Deleted", 'danger')
=======
    flash('Article Deleted', 'success')
>>>>>>> 840c399edd6dec43958d3a4d5cf7fd0e419ce125

    return redirect(url_for('dashboard'))

def grouped_bits_to_decimals(pass_a_list_here, presentable=False):
    intab = ','
    outtab = '.'
    transtab = maketrans(intab, outtab)
    ibalik_ako = [] #return this :D
    for octets in pass_a_list_here:
        ibalik_ako.append(int(octets, 2))
    if presentable == False:
        return ibalik_ako
    else:
        return '.'.join(str(x) for x in ibalik_ako) #translates commas into dots
def bit_grouper (pass_a_list_here):
    return_me_outside = []
    for i in range(0, len(pass_a_list_here), 8):
        appendme2 = (str(pass_a_list_here[i]), str(pass_a_list_here[i + 1]), str(pass_a_list_here[i + 2]), str(pass_a_list_here[i + 3]), str(pass_a_list_here[i + 4]), str(pass_a_list_here[i + 5]), str(pass_a_list_here[i + 6]), str(pass_a_list_here[i + 7]))
        appendme = ''.join(appendme2)
        return_me_outside.append(appendme)
    return return_me_outside #amo ni ang ip nga grouped ang octets
def and_the_two_binary(list_one, list_two):
    #this takes up the args 
    #[['0', '1', '1', '0', '0', '1', '0', '1'], ['1', '0', '1', '1', '0', '0', '0', '0'], ['1', '1', '0', '0', '1', '1', '0', '0'], ['0', '0', '0', '1', '0', '1', '0', '0']]
    ang_na_end_na_nga_result = []
    for numbers_in_list1, numbers_in_list2 in zip(list_one, list_two):
        for host_bits, subnet_bits  in zip(numbers_in_list1, numbers_in_list2): #THIS IS ONLY THE 1st OCTET PLEASE DO NOT FORGET HEHEHE
            if int(host_bits) and int(subnet_bits) == 1:
                ang_na_end_na_nga_result.append(1)
            else:
                ang_na_end_na_nga_result.append(0)
    return ang_na_end_na_nga_result
def subnet_and_broadcast_ip_finder(HOST_IP, SUBNET_MASK):
    host_ip = str(HOST_IP) #input from you sir, or user
    subnet_mask = str(SUBNET_MASK) #same
    host_ip_in_list = host_ip.split(".") 
    # ['10', '255', '79', '96']
    subnet_mask_in_list = subnet_mask.split(".")
    #['255', '255', '255', '224']
    host_ip_in_binary = []
    #['00001010', '11111111', '01001111', '01100000']
    subnet_mask_in_binary = []
    separated_host_ip_in_binary = []
    #[['0', '0', '0', '0', '1', '0', '1', '0'], ['1', '1', '1', '1', '1', '1', '1', '1'], ['0', '1', '0', '0', '1', '1', '1', '1'], ['0', '1', '1', '0', '0', '0', '0', '0']]
    separated_subnet_mask_in_binary = [] 
    #this is for buli-an and purposes
    #[['1', '1', '1', '1', '1', '1', '1', '1'], ['1', '1', '1', '1', '1', '1', '1', '1'], ['1', '1', '1', '1', '1', '1', '1', '1'], ['1', '1', '1', '0', '0', '0', '0', '0']]
    logicaly_and_the_binary_and_mask = []
    subnet_ip_mask = [] #this is from converted binray from mask['124','161','77',1]
    logical_OR_the_binray_and_mask = [] #this is useless
    inverted_separated_subnet_mask = []
    #[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1]
    grouped_inverted_separated_subnet_mask = []
    separated_inverted_separated_subnet_mask = []
    separated_broadcast_ip_address_in_binary = [] #this is the answer
    for ips in host_ip_in_list:
        host_ip_in_binary.append(bin(int(ips))[2:].zfill(8))
    for ips in subnet_mask_in_list:
        subnet_mask_in_binary.append(bin(int(ips))[2:].zfill(8))
    for ips in host_ip_in_binary:
        appendme =  [items for items in ips]
        separated_host_ip_in_binary.append(appendme) #separets ip into a list of list :D 
    for ips in subnet_mask_in_binary:
        appendme = [items for items in ips]
        separated_subnet_mask_in_binary.append(appendme)
    #now iterate on the items on the two dimensional list :)
    for numbers_in_host, numbers_in_subnet in zip(separated_host_ip_in_binary, separated_subnet_mask_in_binary):
        for host_bits, subnet_bits  in zip(numbers_in_host, numbers_in_subnet): #THIS IS ONLY THE 1st OCTET PLEASE DO NOT FORGET HEHEHE
            if int(host_bits) and int(subnet_bits) == 1:
                logicaly_and_the_binary_and_mask.append(1)
            else:
                logicaly_and_the_binary_and_mask.append(0)
                #end of AND binary
        #INVERSE THE MASK FIRST YOU DUMB ASS 
        for host_bits, subnet_bits  in zip(numbers_in_host, numbers_in_subnet): #THIS IS ONLY THE 1st OCTET PLEASE DO NOT FORGET HEHEHE
            if int(host_bits) or int(subnet_bits) == 1:
                logical_OR_the_binray_and_mask.append(1)
            else:
                logical_OR_the_binray_and_mask.append(0)
    a = 0
    #subnet_ip_mask should be the output for number four (4)
    grouped_logicaly_and_the_binary_and_mask = bit_grouper(logicaly_and_the_binary_and_mask)
    #print grouped_logicaly_and_the_binary_and_mask
    for octet in grouped_logicaly_and_the_binary_and_mask:
        subnet_ip_mask.append(int(octet, 2))
    #print subnet_ip_mask
    for octet in separated_subnet_mask_in_binary:
        for bits in octet:
            if int(bits) == 1:
                inverted_separated_subnet_mask.append(0)
            else:
                inverted_separated_subnet_mask.append(1)
             #this returns a list. thats why. wtf
    grouped_inverted_separated_subnet_mask = bit_grouper(inverted_separated_subnet_mask)
    for ips in grouped_inverted_separated_subnet_mask:
        appendme =  [items for items in ips]
        separated_inverted_separated_subnet_mask.append(appendme)
    for numbers_in_host, numbers_in_inverted_subnet in zip(separated_host_ip_in_binary, separated_inverted_separated_subnet_mask):
        for host_bits, subnet_bits  in zip(numbers_in_host, numbers_in_inverted_subnet): #THIS IS ONLY THE 1st OCTET PLEASE DO NOT FORGET HEHEHE
            if int(host_bits) or int(subnet_bits) == 1:
                separated_broadcast_ip_address_in_binary.append(1)
            else:
                separated_broadcast_ip_address_in_binary.append(0)
    grouped_separated_broadcast_ip_address_in_binary = bit_grouper(separated_broadcast_ip_address_in_binary)
    broadcast_ip_address_in_ip_form = grouped_bits_to_decimals(grouped_separated_broadcast_ip_address_in_binary, presentable=True)
    host_ip_and_subnet_AND_result = and_the_two_binary(separated_host_ip_in_binary, separated_inverted_separated_subnet_mask)
    grouped_host_ip_and_subnet_AND_result = bit_grouper(host_ip_and_subnet_AND_result)
    inverse_mask =  grouped_bits_to_decimals(grouped_host_ip_and_subnet_AND_result, presentable=True)
    printable_subnet_ip_mask_in_ip_form =   grouped_bits_to_decimals(grouped_logicaly_and_the_binary_and_mask, presentable=True)
    print "[$] The subnet_ip_mask is :=> %s" % (printable_subnet_ip_mask_in_ip_form)
    print "--------------------------------------"
    print "[$] The Broadcast IP address is :=> %s " % (broadcast_ip_address_in_ip_form)
    print "--------------------------------------"
    print "[$] The Inverse_mask IP address is :=> %s" % (inverse_mask)
    print "--------------------------------------"
    print grouped_host_ip_and_subnet_AND_result
    return (printable_subnet_ip_mask_in_ip_form, broadcast_ip_address_in_ip_form, inverse_mask)
    #next up the division of ip and incrementals :D c
def from_slash_to_subnet(TINAMAD, presentable=False):
    first_prefix_bits =  (1,2,3,4,5,6,7,8) #fist octet
    second_prefix_bits = (9,10,11,12,13,14,15,16) #second octet
    third_prefix_bits = (17,18,19,20,21,22,23,24) #third octet 
    fourth_prefix_bits = (25,26,27,28,29,30,31,32)
    subnet_mask = [128,192,224,240,248,252,254,255]
    resulting_subnet = []
    tinamad = TINAMAD
    number = int(tinamad)
    lists_of_preifx = ((first_prefix_bits),(second_prefix_bits),(third_prefix_bits),(fourth_prefix_bits))
    for prefixes in lists_of_preifx:
        if number in prefixes:
            octetlocation = lists_of_preifx.index(prefixes) + 1  #plus one para tarong hahaha
            #print "It is located on the %dth octet " % octetlocation
            narrowed_prefixes = lists_of_preifx[lists_of_preifx.index(prefixes)]#$
            for items in  narrowed_prefixes: #narrowed input
                if number == items:
                    result = narrowed_prefixes.index(number)
                    #print subnet_mask[result]
                    if octetlocation == 1:
                        resulting_subnet.append(subnet_mask[result])
                        while  len(resulting_subnet) < 4:
                            resulting_subnet.append(0)
                    else:
                        octetlocation -= 1
                        for i in range(octetlocation):
                            two_five_five_lol_wtf = 255
                            resulting_subnet.append(255)
                        resulting_subnet.append(subnet_mask[result])
                        while  len(resulting_subnet) < 4:
                            resulting_subnet.append(0)
                    #print resulting_subnet #this shows a list. we need an ip for easy copy pasting
                    presentablesubnet = '.'.join(str(x) for x in resulting_subnet)
                    print "[$] {0} This is the subnet mask: ".format (str(presentablesubnet))
                    print "[$] {0} Is the octet location: ".format (str(octetlocation))
                    if presentable == False:
                        return resulting_subnet
                    else:
                        return '.'.join(str(x) for x in resulting_subnet)



def subnet_divider(Given_ip, Class_type,Dividend):
    binray_values =(128,64,32,16,8,4,2,1)
    class_c = ["11111111","11111111","11111111"]
    class_b = ["11111111","11111111"]
    class_a = ["11111111"]
    grouped_final_subnet_mask_in_binary = []
    class_type = Class_type#raw_input(str(#raw_input(str("[?] Please enter ip class. E.g(A,B,C,D (ALL CAPS)) : "))))
    given_ip = Given_ip#raw_input(str("[?] Please enter the ip: "))
    #reverse_subnet = raw_input(str("[!] Pls enter the reverse mask (32,23,17): "))
    dividend = Dividend #raw_input(str("[?] Break this on how many networks?: "))
    #subnet_mask = from_slash_to_subnet(reverse_subnet, presentable=True)
    given_ip_in_list = given_ip.split(".")
    #subnet_mask_in_list = subnet_mask.split(".")
    #print given_ip_in_list
    #print subnet_mask_in_list
    dividend_on_binary =  (bin(int(dividend))[2:].zfill(8)) #binary ka 20 == 00 01 01 00
    untouched_separated_dividend_on_binary = list(dividend_on_binary)
    separated_dividend_on_binary = list(dividend_on_binary) 
    # ['0', '0', '0', '1', '0', '1', '0', '0']
    #print separated_dividend_on_binary
    for i in range(len(separated_dividend_on_binary)):
        if int(separated_dividend_on_binary[0]) == 1:
            break
        separated_dividend_on_binary.pop(0)
    #after this function seperaed_dividend_on_binary will be significant btis
    significant_bits = separated_dividend_on_binary
    last_octet_of_mask = []
    for things in range(len(significant_bits)): #append those 1's on the last subnet mask
        last_octet_of_mask.append(1)
    while len(last_octet_of_mask) != 8:
        last_octet_of_mask.append(0)
    grouped_last_octet_of_mask = bit_grouper(last_octet_of_mask)
    if class_type == "C": 
        for octet in class_c:
            grouped_final_subnet_mask_in_binary.append(octet)
        for octetagain in grouped_last_octet_of_mask:
            grouped_final_subnet_mask_in_binary.append(octetagain)

    elif class_type == "B":
        for octet in class_b:
            grouped_final_subnet_mask_in_binary.append(octet)
        for octetagain in grouped_last_octet_of_mask:
            grouped_final_subnet_mask_in_binary.append(octetagain)
        grouped_final_subnet_mask_in_binary.append('00000000')      
    elif class_type == "A":#append('00000000')  
        for octet in class_a:
            grouped_final_subnet_mask_in_binary.append(octet) #append only the last 
        for octetagain in grouped_last_octet_of_mask: 
            grouped_final_subnet_mask_in_binary.append(octetagain)
        grouped_final_subnet_mask_in_binary.append('00000000')
        grouped_final_subnet_mask_in_binary.append('00000000')  
        #DPUTA SALA NI TANAN DALI LG GUID HA. SALA NI SA. bcs
        """

        class c is sometimes 255.255.255.somthing right?
        soo kugn mag 11111111 11111111 11111111 ang preset. okay lg kung may 0 sa
        soo class b should be 11111111 xxxxxxxx 0000000 0000000 lg.
        whilst class A should be xxxxxxx 00000000 00000000 0000000 dba? or somehting. test later  after work
        """
            
    final_subnet_mask = grouped_bits_to_decimals(grouped_final_subnet_mask_in_binary, presentable=True)
    determine_the_biggest_on_this_list_plus_1 = []
    for iterator, bits in enumerate(last_octet_of_mask):
        if bits == 1:
            determine_the_biggest_on_this_list_plus_1.append(iterator)
    test =  max(determine_the_biggest_on_this_list_plus_1)

    incremental_value = binray_values[test] #get the incremental value
    print  incremental_value
    var = 0 #first
    inc = incremental_value
    last = inc
    
    ip2 = given_ip_in_list[:3]
    print ip2
    ip = '.'.join(ip2)+ '.' #formats the ip to 209.50.1.x wher x is awdawdawdwa
    zero = 0
    print "[!] Incremental by {0}".format(str(inc))
    setofip = []
    while var < 256:
        usable_start = var+1
        usable_last = last-1
        if var == 0:
            setofip.append("{0}{1} |---| {0}{3} <==[upto]==> {0}{4}".format (ip, var, inc, usable_start, usable_last))
        else:   
            setofip.append("{0}{1} |---| {0}{2} <==[upto]==> {0}{3}".format (ip, var, usable_start, usable_last))
        var += inc
        last += inc 
    return setofip

class hadinputsomething(Form):
    host_ip = StringField('Host IP', [validators.Length(min=1, max=15)])
    subnet = StringField('Subnet', [validators.Length(min=4, max=25)])
@app.route('/subnetbroadcastfinder', methods=['GET', 'POST'])
def subnetbroadcastfinder():
     form = hadinputsomething(request.form)   
     if request.method == 'POST':
        # Get Form Fields
        host_ip = form.host_ip.data#request.form['host_ip']
        subnet = form.subnet.data#request.form['subnet']
        if len(subnet) < 3: # kung /24 or something ang ip
            subnet = from_slash_to_subnet(subnet, presentable=True)
            subnetandipbroadcastfinder = subnet_and_broadcast_ip_finder(str(host_ip), str(subnet))
            network = subnetandipbroadcastfinder[0]
            broadcast = subnetandipbroadcastfinder[1]
            inverse_mask = subnetandipbroadcastfinder[2]
<<<<<<< HEAD
            return render_template('subnet.html',  network=network,broadcast=broadcast, inverse_mask=inverse_mask,  subnet=subnet, form=form )
=======
            return render_template('subnet.html',  network=network,broadcast=broadcast, inverse_mask=inverse_mask,  form=form )
>>>>>>> 840c399edd6dec43958d3a4d5cf7fd0e419ce125
        else:
            subnetandipbroadcastfinder = subnet_and_broadcast_ip_finder(str(host_ip), str(subnet))
            network = subnetandipbroadcastfinder[0]
            broadcast = subnetandipbroadcastfinder[1]
            inverse_mask = subnetandipbroadcastfinder[2]
<<<<<<< HEAD
            return render_template('subnet.html',  network=network,broadcast=broadcast, inverse_mask=inverse_mask,   form=form )
=======
            return render_template('subnet.html',  network=network,broadcast=broadcast, inverse_mask=inverse_mask,  form=form )
>>>>>>> 840c399edd6dec43958d3a4d5cf7fd0e419ce125
     else:
        return render_template('subnet.html', form=form)

class FORM_ipdivider(Form):
    choice = ["C","B","A"]
    Given_ip = StringField( 'Host IP', [validators.Length(min=1, max=15)] )
    Dividend  = StringField( 'Dividend', [validators.Length(min=4, max=25)] )
    IP_class = SelectField( 'IP Classes', choices=(('C', 'Class C'), ('B', 'Class B'), ('A', 'Class A')))
    network_or_host = SelectField( 'Network? or Host?', choices=(('NETWORK', 'Find How Many Networks'), ('HOST', 'Find How Many Hosts'), ))
@app.route('/ipdivider', methods=['GET', 'POST'])
def ipdivider():#subnet divider 
    form = FORM_ipdivider(request.form)
    if request.method == 'POST':
        given_ip = form.Given_ip.data
        dividend = form.Dividend.data#request.form['host_ip']
        ip_class = form.IP_class.data
        network_or_host = form.network_or_host.data
        range_of_ips = subnet_divider(given_ip, ip_class, dividend)
        return render_template('ipdivider.html', form=form, given_ip=given_ip, dividend=dividend,ip_class=ip_class,network_or_host=network_or_host, range_of_ips=range_of_ips )
    else:
        return render_template('ipdivider.html', form=form)
<<<<<<< HEAD

"""
END OF IP THINGS
END OF IP THINGS

END OF IP THINGS
END OF IP THINGS

END OF IP THINGS
END OF IP THINGS

END OF IP THINGS
END OF IP THINGS

END OF IP THINGS
END OF IP THINGS

END OF IP THINGS
END OF IP THINGS

END OF IP THINGS
END OF IP THINGS

END OF IP THINGS
END OF IP THINGS

END OF IP THINGS
END OF IP THINGS


"""

#ad
@app.route('/_add_numbers')
def add_numbers():
    a = request.args.get('a', type=str)
    con = sqlite3.connect(db_name)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("select * from commands where tags like ?", ("%"+a+"%",))
    result = cur.fetchall()
    print result
    return jsonify(result=result)
    #AJAX pa more
class FORM_search_topic(Form):
    searchquery = StringField('Enter Something',[validators.Length(min=3, max=25)])

@app.route('/search', methods=['GET', 'POST'])
def search_topic():
    form = FORM_search_topic(request.form)
    searchquery = form.searchquery.data
    if request.method == "POST" and form.validate():
        for things in banned_characters:
            if things in searchquery:
                flash ('Wag si acqoue bess,', 'danger')
                return render_template('search.html', form=form) #cut
        #if input does not contain malicious shits
        #execute and connect to db
        con = sqlite3.connect(db_name)
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute('SELECT id, topic_name from commands where tags like ?', ("%" + searchquery + "%", ))
        topic_names = cur.fetchall()
        return render_template('search.html', topic_names=topic_names, form=form, searchquery=searchquery)
    else:
        return render_template('search.html', form=form)


"""
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS
START OF NETMIKO THINGS

"""

def encoder(phrase):
    pass
def decoder(letters):
    return_me = letters
    for i in range(10):
        return_me = base64.b64decode(return_me)
    return return_me
laptop = {
	'device_type': 'linux',
	'ip': 'localhost',
	'username': 'skrm',
	'password': decoder('Vm0wd2VHUXhUWGROVldSWVYwZDRWRll3Wkc5V1ZsbDNXa1JTVjJKR2JETlhhMk0xWVd4S2MxZHFRbFZXYlUweFZtcEdZV1JIVmtWUmJIQk9UVEJLU1ZacVNqUlpWMDE1VTJ0V1ZXSkhVbkJWYlhSM1UxWmtWMWRzV214U2JWSkpWbTEwVjFWdFNrZFhiR2hhWWtkU2RsWkdXbUZqTVdSMFVteGtUbFp1UWxoV1JscFhWakpHU0ZadVJsSldSM001'),
	'port' : 22
	
}
cellphone = {
    'device_type': 'linux',
    'ip' : 'localhost',
    'username': 'root',
    'password': decoder('Vm0wd2VHUXhUWGROVldSWVYwZDRWRll3Wkc5V1ZsbDNXa1JTVjJKR2JETlhhMk0xWVd4S2MxZHFRbFZXYlUweFZtcEdZV1JIVmtWUmJIQk9UVEJLU1ZacVNqUlpWMDE1VTJ0V1ZXSkhVbkJWYlhSM1UxWmtWMWRzV214U2JWSkpWbTEwVjFWdFNrZFhiR2hhWWtkU2RsWkdXbUZqTVdSMFVteGtUbFp1UWxoV1JscFhWakpHU0ZadVJsSldSM001'),
    'port' : 2222
}

@app.route('/interactive')
def interactive():
	try:
		return render_template('interactive.html')
	except Exception as e:
		return (str(e))

"""
@app.route('/_background_process')
def background_process():
	lang = request.args.get('proglang')

    if str(lang).lower() == 'python':
        return jsonify(result='YOU ARE WISE! AHHA LOL')
    else:
        return jsonify(result="balimbing pota")
"""

@app.route('/background_process')
def background_process():
    a = request.args.get('proglang')
    lang2 = request.args.get('secondlang')
    con = sqlite3.connect(db_name)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("select * from commands where tags like ?", ("%"+a+"%",))
    article = cur.fetchall()
    if str(a).lower() == 'python':
        return jsonify(result=article, sec_res=a)
    else:
        return jsonify(result=a, sec_res='shet')


if __name__ == '__main__':
    connect_to_cp = netmiko.ConnectHandler(**laptop)
    print connect_to_cp.find_prompt()
    print connect_to_cp.send_command_timing('ls')
    print laptop
    print cellphone
=======
if __name__ == '__main__':
>>>>>>> 840c399edd6dec43958d3a4d5cf7fd0e419ce125
    app.secret_key='thequickbrownfoxjumpedoverthelazydog'
    app.run(port=8000, host="0.0.0.0", debug=True)
