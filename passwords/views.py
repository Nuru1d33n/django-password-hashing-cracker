from django.shortcuts import render
from passwords.forms import PasswordForm

# Create your views here.
def home(request):
    if request.method == 'POST':
        form = PasswordForm(request.POST)
        print(form)
    context = {
        'form': form,
    }
    return render(request, 'home/index.html', context)
