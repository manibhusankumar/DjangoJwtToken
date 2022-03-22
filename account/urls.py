
from django.urls import path
from account import views

urlpatterns = [
    path('register/',views.UserRegistrationView.as_view(), name='registration'),
    path('login/',views.UserLoginView.as_view(), name='login'),
    path('userprofile/',views.UserProfileView.as_view(), name='user_profile'),
    path('user-change-password/',views.UserChangePasswordView.as_view(), name='user_change_password'),
    path('send-reset-password-email/', views.SendPasswordResetEmailView.as_view(), name='send_reset_password'),
    path('reset-password/<uid>/<token>/', views.UserPasswordResetView.as_view(), name='reset_password'),

]