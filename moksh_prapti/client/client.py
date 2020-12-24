import smtplib
import sys
import smime

def sendsmime(from_addr, to_addrs, subject, msg, from_cert, smtpd='localhost'):
	message = [
		'To: "shubham" <'+to_addrs+'>',
		'From: "Ashish" <'+from_addr+'>',
		'Subject: '+subject,
		'',
		msg
	]
	
	with open(from_cert, 'rb') as pem:
		msg=smime.encrypt('\n'.join(message), pem.read())
	
	print("to send: ")
	print(msg)

	smtp = smtplib.SMTP()
	smtp.connect(smtpd)
	smtp.sendmail(from_addr, to_addrs, msg)
	smtp.quit()

sendsmime("patelashish769@mail.com","shubhamsoni@mail.com",'Sub','i love a just world but unfortunately it cant be created.','./client/signer.pem',smtpd='localhost:1130')
