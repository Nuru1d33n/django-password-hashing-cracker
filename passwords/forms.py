from django import forms

class PasswordForm(forms.Form):
    password_list = forms.CharField(max_length=4444)
    password_file = forms.FileField(required=False)
    password_text_area = forms.Textarea()