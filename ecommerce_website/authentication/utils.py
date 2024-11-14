from django.conf import settings
from django.core.mail import send_mail
import random

# This view generate random 6 digit otp
def generate_otp():
    return str(random.randint(100000, 999999))


# Send OTP email to the user
def send_otp_to_users(title, message, email):
    sender = settings.EMAIL_HOST_USER
    send_mail(
        title,
        message,
        sender,
        [email],
        fail_silently=False,
    )