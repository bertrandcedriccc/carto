#!/usr/bin/env python
# -*- encoding: utf-8 -*-
import os,sys
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import encoders
from email.mime.base import MIMEBase
#https://realpython.com/python-send-email/#adding-attachments-using-the-email-package

def envoi_notification(outil,domaine):
	print("envoi de l'email")
	msg = MIMEMultipart()
	msg['From'] = 'Cartoz'
	msg['To'] = 'notification_cyberveille@lepouvoirclapratique.com'
	msg['Subject'] = "notification alerte " + outil + " sur " + domaine
	message = "L'outil " + outil + " a fini d'etre execute sur le domaine " + domaine + "\n" 
	msg.attach(MIMEText(message,"plain"))
	#print message
	
	text = msg.as_string()

	try:
		mailserver = smtplib.SMTP('ssl0.ovh.net', 587)
		mailserver.ehlo()
		mailserver.starttls()
		mailserver.ehlo()
		mailserver.login('notification_cyberveille@lepouvoirclapratique.com', 'oqyLzUHJW2cxnH6m6x9s')
		#mailserver.sendmail('notification_cyberveille@lepouvoirclapratique.com', 'notification_cyberveille@lepouvoirclapratique.com', msg.as_string())
		mailserver.sendmail('notification_cyberveille@lepouvoirclapratique.com', 'notification_cyberveille@lepouvoirclapratique.com', text)
		mailserver.quit()
		print("notification envoyee")
	except:
		print(("Oops!",sys.exc_info()[0],"occured."))