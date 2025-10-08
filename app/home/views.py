from django.shortcuts import render,redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.cache import never_cache
import random
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.contrib.auth.hashers import make_password
from django.contrib.auth.decorators import login_required

@login_required(login_url="login")
def home(request):
    # Pass a flag to template whether user is superuser
    context = {
        'is_superuser': request.user.is_superuser
    }
    return render(request, "home.html", context)


# login === name and password
# --------------------------------

def login_view(request):
    message=None
    if request.POST:
        name=request.POST['name']
        password=request.POST['password']
        user=authenticate(username=name,password=password)
        if user is not None:
            login(request,user)
            return redirect ('home')
        else:
                messages.info(request,"invalid credentials")
                return redirect('login')
    else:
        return render(request, 'login.html')


# login === email and password
# --------------------------------------------------------

# def login_view(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         password = request.POST.get('password')

#         try:
#             user_obj = User.objects.get(email=email)
#             user = authenticate(request, username=user_obj.username, password=password)
#         except User.DoesNotExist:
#             user = None

#         if user is not None:
#             login(request, user)
#             return redirect('home')
#         else:
#             return render(request, 'login.html', {'error': 'Invalid email or password'})
    
#     return render(request, 'login.html')



def logout_view(request):
    logout(request)
    return redirect ('/')
   
    return render(request,"logout.html")




def signup(request):  

    if request.method=="POST":
        name=request.POST['name']
        email=request.POST['email']
        password=request.POST['password']
        password2=request.POST['confirm_password']


        if password==password2:

            if User.objects.filter(username=name).exists():
                messages.info(request, "Username already taken")
                return redirect('signup')
            
            elif User.objects.filter(email=email).exists():
                    messages.info(request, "Email already registered")
                    return redirect('signup')
        
            else:
                user=User.objects.create_user(username=name,email=email,password=password)
                user.save();
                return redirect('login')
            
        else:
             messages.info(request, "password not matching")
             return redirect('signup')

    else:
        
    
        return render(request,'signup.html')



# -------------forgot password-------------


def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get("email")
        try:
            user = User.objects.get(email=email)  # check if user exists
            otp = random.randint(1000, 9999)  # generate 4-digit OTP
            request.session["reset_email"] = email
            request.session["reset_otp"] = str(otp)

            # send email
            send_mail(
                "Your Password Reset OTP",
                f"Your OTP for password reset is {otp}.",
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )

            messages.success(request, "OTP has been sent to your email.")
            return redirect("otp")

        except User.DoesNotExist:
            messages.error(request, "Email not found.")

    return render(request,"forgot_password.html")



def otp(request):
    if request.method == "POST":
        otp = (
            request.POST.get("otp1", "") +
            request.POST.get("otp2", "") +
            request.POST.get("otp3", "") +
            request.POST.get("otp4", "")
        )
        if otp == request.session.get("reset_otp"):
            return redirect("reset_password")
        else:
            messages.error(request, "Invalid OTP. Try again.")
    return render(request,"otp.html")


def reset_password(request):

    if request.method == "POST":
        password = request.POST.get("pwd")
        confirm_password = request.POST.get("confirm_password")
        
        if password == confirm_password:
            email = request.session.get("reset_email")
            user = User.objects.get(email=email)
            user.set_password(password)
            user.save()

            # clear session
            request.session.flush()

            messages.success(request, "Password reset successful. Please login.")
            return redirect("login")
        else:
            messages.error(request, "Passwords do not match.")

    return render(request,"reset_password.html")


@login_required(login_url="login")
def member(request):
     user=User.objects.all()   
     return render(request,"adminn.html",{'user':user})

@login_required(login_url="login")
def add(request):
   
    return render(request,"add.html",)

@login_required(login_url="login")
def addrec(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")

        # check if username or email already exists
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return redirect("add")

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return redirect("add")

        # create new user
        user = User.objects.create(
            username=username,
            email=email,
            password=make_password(password)  # hash the password
        )

        messages.success(request, f"New member '{username}' added successfully!")
        return redirect("member")  # redirect to admin's member list

    return render(request, "add.html")

@login_required(login_url="login")
def delete(request,id):
    user = get_object_or_404(User, id=id)
    user.delete()
    return redirect("member")


@login_required(login_url="login")
def update(request, id):
    user = get_object_or_404(User, id=id)

    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")

        if User.objects.exclude(id=user.id).filter(username=username).exists():
            messages.error(request, "Username already exists. Please choose another.")
            return redirect('update', id=id)

        user.username = username
        user.email = email

        if password:
            user.password = make_password(password)

        user.save()
        messages.success(request, "User updated successfully!")
        return redirect("member")

    return render(request, "update.html", {"user": user})

