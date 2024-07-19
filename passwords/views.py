import hashlib
from django.shortcuts import render
from passwords.forms import PasswordForm, HashForm
from passwords.models import (
    Password, MD5Password, SHA1Password, SHA224Password,
    SHA256Password, SHA384Password, SHA512Password, SHA3256Password
)
from passwords.utils import identify_hash_type



HASH_TYPES = {
    'md5': 32,
    'sha1': 40,
    'sha224': 56,
    'sha256': 64,
    'sha384': 96,
    'sha512': 128,
    'sha3_256': 64,
}

def get_hash_type(hash_value):
    hash_length = len(hash_value)
    for hash_type, length in HASH_TYPES.items():
        if hash_length == length:
            return hash_type
    return None


def home(request):
    passwords = []
    hash_type_result = None

    if request.method == 'POST':
        form = PasswordForm(request.POST, request.FILES)
        hash_form = HashForm(request.POST)
        hash_check_form = HashCheckForm(request.POST)

        if form.is_valid():
            choice = form.cleaned_data['choice']
            password_input = form.cleaned_data['password_input']
            password_text_area = form.cleaned_data['password_text_area']
            password_file = request.FILES.get('password_file')

            def save_password(password):
                if not Password.objects.filter(value=password).exists():
                    Password.objects.create(value=password)
                    passwords.append(password)

            if choice == 'input' and password_input:
                save_password(password_input)

            if choice == 'textarea' and password_text_area:
                for line in password_text_area.splitlines():
                    save_password(line.strip())

            if choice == 'file' and password_file:
                for line in password_file:
                    save_password(line.decode().strip())

        if hash_form.is_valid():
            hash_type = hash_form.cleaned_data['hash_type']
            print(hash_type)
            password = hash_form.cleaned_data['password']

            def save_hashed_password(model, hashed_value):
                if not model.objects.filter(value=hashed_value).exists():
                    model.objects.create(value=hashed_value)

            hashed_password = None
            if hash_type == 'md5':
                hashed_password = hashlib.md5(password.encode()).hexdigest()
                save_hashed_password(MD5Password, hashed_password)

            elif hash_type == 'sha1':
                hashed_password = hashlib.sha1(password.encode()).hexdigest()
                save_hashed_password(SHA1Password, hashed_password)

            elif hash_type == 'sha224':
                hashed_password = hashlib.sha224(password.encode()).hexdigest()
                save_hashed_password(SHA224Password, hashed_password)

            elif hash_type == 'sha256':
                hashed_password = hashlib.sha256(password.encode()).hexdigest()
                save_hashed_password(SHA256Password, hashed_password)

            elif hash_type == 'sha384':
                hashed_password = hashlib.sha384(password.encode()).hexdigest()
                save_hashed_password(SHA384Password, hashed_password)

            elif hash_type == 'sha512':
                hashed_password = hashlib.sha512(password.encode()).hexdigest()
                save_hashed_password(SHA512Password, hashed_password)

            elif hash_type == 'sha3_256':
                hashed_password = hashlib.sha3_256(password.encode()).hexdigest()
                save_hashed_password(SHA3256Password, hashed_password)

    else:
        form = PasswordForm()
        hash_form = HashForm()

    context = {
        'form': form,
        'hash_form': hash_form,
        'passwords': passwords,
    }
    return render(request, 'home/index.html', context)


import hashlib
from django.shortcuts import render, redirect
from passwords.models import (
    Password, MD5Password, SHA1Password, SHA224Password,
    SHA256Password, SHA384Password, SHA512Password, SHA3256Password
)

def convert_passwords(request):
    if request.method == 'POST':
        # Get all passwords from the Password table
        passwords = Password.objects.all()
        
        def save_hashed_password(model, hashed_value):
            if not model.objects.filter(value=hashed_value).exists():
                model.objects.create(value=hashed_value)
        
        # Iterate over each password and save hashed versions
        for password in passwords:
            pwd_value = password.value
            
            # MD5
            md5_hashed = hashlib.md5(pwd_value.encode()).hexdigest()
            save_hashed_password(MD5Password, md5_hashed)

            # SHA1
            sha1_hashed = hashlib.sha1(pwd_value.encode()).hexdigest()
            save_hashed_password(SHA1Password, sha1_hashed)

            # SHA224
            sha224_hashed = hashlib.sha224(pwd_value.encode()).hexdigest()
            save_hashed_password(SHA224Password, sha224_hashed)

            # SHA256
            sha256_hashed = hashlib.sha256(pwd_value.encode()).hexdigest()
            save_hashed_password(SHA256Password, sha256_hashed)

            # SHA384
            sha384_hashed = hashlib.sha384(pwd_value.encode()).hexdigest()
            save_hashed_password(SHA384Password, sha384_hashed)

            # SHA512
            sha512_hashed = hashlib.sha512(pwd_value.encode()).hexdigest()
            save_hashed_password(SHA512Password, sha512_hashed)

            # SHA3-256
            sha3_256_hashed = hashlib.sha3_256(pwd_value.encode()).hexdigest()
            save_hashed_password(SHA3256Password, sha3_256_hashed)
        
        return redirect('home')

    return render(request, 'home/convert.html')



# import hashlib
# from django.shortcuts import render
# from .forms import HashIdentifyForm

# def identify_hash(request):
#     hash_type = None
#     hash_value = None

#     if request.method == 'POST':
#         form = HashIdentifyForm(request.POST)
#         if form.is_valid():
#             hash_value = form.cleaned_data['hash_value']
#             known_password = 'knownpassword'
            
#             hash_algorithms = {
#                 'md5': hashlib.md5(known_password.encode()).hexdigest(),
#                 'sha1': hashlib.sha1(known_password.encode()).hexdigest(),
#                 'sha224': hashlib.sha224(known_password.encode()).hexdigest(),
#                 'sha256': hashlib.sha256(known_password.encode()).hexdigest(),
#                 'sha384': hashlib.sha384(known_password.encode()).hexdigest(),
#                 'sha512': hashlib.sha512(known_password.encode()).hexdigest(),
#                 'sha3_256': hashlib.sha3_256(known_password.encode()).hexdigest()
#             }

#             for algo, hashed in hash_algorithms.items():
#                 if hash_value == hashed:
#                     hash_type = algo
#                     break

#     else:
#         form = HashIdentifyForm()

#     context = {
#         'form': form,
#         'hash_type': hash_type,
#         'hash_value': hash_value
#     }
#     return render(request, 'home/identify_hash.html', context)


import hashlib
from django.shortcuts import render
from passwords.forms import IdentifyHashForm
from passwords.models import (MD5Password, SHA1Password, SHA224Password, SHA256Password,
                              SHA384Password, SHA512Password, SHA3256Password)

def identify_hash(request):
    hash_value = None
    hash_type = None
    actual_password = None

    if request.method == 'POST':
        form = IdentifyHashForm(request.POST)

        if form.is_valid():
            hash_value = form.cleaned_data['hash_value']
            hash_length = len(hash_value)

            def get_password_from_hash(hash_model):
                try:
                    hash_record = hash_model.objects.get(value=hash_value)
                    return hash_record.original_password.value
                except hash_model.DoesNotExist:
                    return None

            if hash_length == 32:
                hash_type = 'MD5'
                actual_password = get_password_from_hash(MD5Password)

            elif hash_length == 40:
                hash_type = 'SHA-1'
                actual_password = get_password_from_hash(SHA1Password)

            elif hash_length == 56:
                hash_type = 'SHA-224'
                actual_password = get_password_from_hash(SHA224Password)

            elif hash_length == 64:
                if hash_value.startswith('sha3_'):
                    hash_type = 'SHA-3-256'
                    actual_password = get_password_from_hash(SHA3256Password)
                else:
                    hash_type = 'SHA-256'
                    actual_password = get_password_from_hash(SHA256Password)

            elif hash_length == 96:
                hash_type = 'SHA-384'
                actual_password = get_password_from_hash(SHA384Password)

            elif hash_length == 128:
                hash_type = 'SHA-512'
                actual_password = get_password_from_hash(SHA512Password)

    else:
        form = IdentifyHashForm()

    context = {
        'form': form,
        'hash_type': hash_type,
        'actual_password': actual_password,
        'hash_value': hash_value,
    }
    return render(request, 'home/identify_hash.html', context)


def identify_hash_type(hash_value):
    hash_length = len(hash_value)
    
    if hash_length == 32:
        return 'MD5'
    elif hash_length == 40:
        return 'SHA1'
    elif hash_length == 56:
        return 'SHA224'
    elif hash_length == 64:
        return 'SHA256'
    elif hash_length == 96:
        return 'SHA384'
    elif hash_length == 128:
        return 'SHA512'
    elif hash_length == 64 and all(c in '0123456789abcdefABCDEF' for c in hash_value):
        return 'SHA3-256'
    else:
        return 'Unknown hash type'


