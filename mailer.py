#!/usr/bin/python2.7
import smtplib
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import multiprocessing



"""

#use this function to generate a b64 encoded string for your password 
def encoder(your_raw_password):
	a = your_raw_password
	for i in range(10):
		a = base64.b64encode(a)
	return a
"""
def decoder(hehe):
    a = hehe
    for i in range(10):
        a = base64.b64decode(a)
    return a

def send_backup():    
	msg = MIMEMultipart()

	msg['From'] = 'someone@gmail.com'
	msg['To'] = 'someone@gmail.com'
	msg['Subject'] = 'Test Backup Of Database Sent through email'

	body = "I hoope this works. Cause we are gonna need to backup the whole database"

	msg.attach(MIMEText(body, 'plain'))

	filename = "test.db"
	attachment = open("test.db", "rb")

	part = MIMEBase('application', 'octet-stream')
	part2 = MIMEBase('application', 'octet-stream')
	part.set_payload( (attachment).read() )
	encoders.encode_base64(part)

	part2.set_payload( (attachment).read() )
	encoders.encode_base64(part2)

	part.add_header('Content-Disposition', "attachment; filename= %s" % filename)

	msg.attach(part)
	msg.attach(part2)


	server = smtplib.SMTP('smtp.gmail.com', 587)
	server.starttls()
	server.login("someone@somemail.com", decoder("your encoded password here") )
	 
	text = msg.as_string()
	#msg = "YOUR TEST MESSAGE IF PYTHON IS WORKING PROPERLY MESSAGE!"
	server.sendmail("sender@sender.com", "reciever@reciever.com", text)
	server.quit()

