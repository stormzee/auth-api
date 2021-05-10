from django.core.mail import send_mail
from django.conf import settings

class utils_func():
    
    def send_email(self, data):
        send_mail(
            subject = data['subject'],
            message = data['message'],
            from_email = data['From'],
            recipient_list  = (data['To'],),
            fail_silently = False
            # auth_user = settings.EMAIL_HOST_USER,
            # auth_password = settings.EMAIL_HOST_PASSWORD,

        )