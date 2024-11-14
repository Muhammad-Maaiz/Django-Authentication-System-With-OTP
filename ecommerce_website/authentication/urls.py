from django.urls import path
from authentication import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('verify-otp/', views.verify_otp_view, name='verify_otp'),
    path('forget_password/', views.forget_password_view, name='forget_password'),
    path('verify_reset_otp/', views.verify_reset_otp_view, name='verify_reset_otp'),
    path('change_password/', views.change_password_view, name='change_password'),
    path('logout/', views.logout_view, name='logout'),
    # path('send-email/', views.send_email, name='send_email'),
]
