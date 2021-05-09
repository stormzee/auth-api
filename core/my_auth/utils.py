from django.core.mail import send_mail


class utils_func():
    
    def send_email(self, data):
        send_mail(
            subject = data['subject'],
            message = data['message'],
            from_email = data['From'],
            recipient_list  = [data['To']]
        )