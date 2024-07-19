from django import forms

class PasswordForm(forms.Form):
    CHOICES = [
        ('input', 'Enter password manually'),
        ('textarea', 'Enter passwords in textarea'),
        ('file', 'Upload a file')
    ]

    choice = forms.ChoiceField(choices=CHOICES, widget=forms.RadioSelect)
    password_input = forms.CharField(max_length=4444, required=False)
    password_text_area = forms.CharField(widget=forms.Textarea, required=False)
    password_file = forms.FileField(required=False)

class HashForm(forms.Form):
    HASH_CHOICES = [
        ('md5', 'MD5'),
        ('sha1', 'SHA-1'),
        ('sha224', 'SHA-224'),
        ('sha256', 'SHA-256'),
        ('sha384', 'SHA-384'),
        ('sha512', 'SHA-512'),
        ('sha3_256', 'SHA-3-256')
    ]

    hash_type = forms.ChoiceField(choices=HASH_CHOICES)
    password = forms.CharField(max_length=4444)


class HashCheckForm(forms.Form):
    hash_value = forms.CharField(max_length=128)


class HashIdentifyForm(forms.Form):
    hash_value = forms.CharField(max_length=128)
from django import forms

class IdentifyHashForm(forms.Form):
    hash_value = forms.CharField(label='Enter the hash', max_length=128)

