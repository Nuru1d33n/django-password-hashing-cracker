import hashlib
from django.shortcuts import render, redirect
from passwords.forms import PasswordForm, HashForm, HashCheckForm, IdentifyHashForm
from passwords.models import (
    Password, MD5Password, SHA1Password, SHA224Password,
    SHA256Password, SHA384Password, SHA512Password, SHA3256Password
)

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
    error_message = None

    if request.method == 'POST':
        form = PasswordForm(request.POST, request.FILES)
        hash_form = HashForm(request.POST)

        if form.is_valid():
            choice = form.cleaned_data['choice']
            password_input = form.cleaned_data['password_input']
            password_text_area = form.cleaned_data['password_text_area']
            password_file = request.FILES.get('password_file')

            def save_password(password):
                # Check if password exists in Password table
                if Password.objects.filter(value=password).exists():
                    nonlocal error_message
                    error_message = f"The password '{password}' already exists."
                else:
                    # Save password to Password table if it does not exist
                    password_instance = Password.objects.create(value=password)
                    passwords.append(password)
                    # Hash the password and save it in various hash type tables
                    hash_and_save(password, password_instance)

            def hash_and_save(password, password_instance):
                hash_functions = {
                    'md5': hashlib.md5,
                    'sha1': hashlib.sha1,
                    'sha224': hashlib.sha224,
                    'sha256': hashlib.sha256,
                    'sha384': hashlib.sha384,
                    'sha512': hashlib.sha512,
                    'sha3_256': hashlib.sha3_256,
                }

                for hash_type, hash_func in hash_functions.items():
                    hashed_password = hash_func(password.encode()).hexdigest()
                    save_hashed_password(hash_type, hashed_password, password_instance)

            def save_hashed_password(hash_type, hashed_value, original_password):
                models = {
                    'md5': MD5Password,
                    'sha1': SHA1Password,
                    'sha224': SHA224Password,
                    'sha256': SHA256Password,
                    'sha384': SHA384Password,
                    'sha512': SHA512Password,
                    'sha3_256': SHA3256Password,
                }
                model = models.get(hash_type)
                if model:
                    if not model.objects.filter(value=hashed_value).exists():
                        model.objects.create(value=hashed_value, original_password=original_password)

            if choice == 'input' and password_input:
                save_password(password_input)

            if choice == 'textarea' and password_text_area:
                for line in password_text_area.splitlines():
                    save_password(line.strip())

            if choice == 'file' and password_file:
                for line in password_file:
                    save_password(line.decode().strip())

        if hash_form.is_valid():
            # Handle hash form if needed
            pass

    else:
        form = PasswordForm()
        hash_form = HashForm()

    context = {
        'form': form,
        'hash_form': hash_form,
        'passwords': passwords,
        'error_message': error_message,
    }
    return render(request, 'home/index.html', context)

def convert_passwords(request):
    if request.method == 'POST':
        passwords = Password.objects.all()
        
        def save_hashed_password(model, hashed_value, original_password):
            if not model.objects.filter(value=hashed_value).exists():
                model.objects.create(value=hashed_value, original_password=original_password)
        
        for password in passwords:
            pwd_value = password.value
            
            md5_hashed = hashlib.md5(pwd_value.encode()).hexdigest()
            save_hashed_password(MD5Password, md5_hashed, password)

            sha1_hashed = hashlib.sha1(pwd_value.encode()).hexdigest()
            save_hashed_password(SHA1Password, sha1_hashed, password)

            sha224_hashed = hashlib.sha224(pwd_value.encode()).hexdigest()
            save_hashed_password(SHA224Password, sha224_hashed, password)

            sha256_hashed = hashlib.sha256(pwd_value.encode()).hexdigest()
            save_hashed_password(SHA256Password, sha256_hashed, password)

            sha384_hashed = hashlib.sha384(pwd_value.encode()).hexdigest()
            save_hashed_password(SHA384Password, sha384_hashed, password)

            sha512_hashed = hashlib.sha512(pwd_value.encode()).hexdigest()
            save_hashed_password(SHA512Password, sha512_hashed, password)

            sha3_256_hashed = hashlib.sha3_256(pwd_value.encode()).hexdigest()
            save_hashed_password(SHA3256Password, sha3_256_hashed, password)
        
        return redirect('home')

    return render(request, 'home/convert.html')

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
