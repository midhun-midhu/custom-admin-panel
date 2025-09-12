from django.urls import path, re_path
from . import views

urlpatterns = [ 
    path('',views.home, name='home'),
    path('login/',views.login_view, name='login'),
    path('logout/',views.logout_view, name='logout'),
    path('signup/',views.signup, name='signup'),

    path('forgot_password/',views.forgot_password, name='forgot_password'),
    path('otp/',views.otp, name='otp'),
    path('reset_password/',views.reset_password, name='reset_password'),
    
    path('member/',views.member, name='member'),
    path('add/',views.add, name='add'),
    path('addrec/',views.addrec, name='addrec'),
    path('delete/<int:id>/',views.delete, name='delete'),
    path('update/<int:id>/',views.update, name='update'),
    

]