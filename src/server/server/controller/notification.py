import smtplib, ssl
import pandas as pd
import plyer


port = 587  
smtp_server = "smtp.gmail.com"
sender_email = ""
receiver_email = ""
password = ""


def notify_email():
    message = """\
    Subject: Hi there

    This message is sent from Python."""

    context = ssl.create_default_context()

    try:
        server = smtplib.SMTP(smtp_server, port)
        server.ehlo() 
        server.starttls(context=context)
        server.ehlo() 
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message)
    except Exception as e:
        print(e)
    finally:
        server.quit()


def notify_desktop(title,message):
    


if __name__== "__main__":
    pass

