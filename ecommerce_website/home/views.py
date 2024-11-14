from django.shortcuts import render
from django.contrib.auth.decorators import login_required

# Create your views here.
@login_required(login_url="/")
def home(request):
    user = request.user
    return render(request, "home.html", {"user": user})