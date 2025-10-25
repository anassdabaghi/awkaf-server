"""
URL configuration for backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from api.views import AdminLoginRequestOTP, AdminVerifyOTP, CreateUserView,AdminRegisterView, UserLoginRequestOTP,AdminLoginView, UserVerifyOTP,VerifyEmailView,UpdateDeleteUserView,LogoutView
from api.views import CookieTokenRefreshView

from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.conf import settings
from django.conf.urls.static import static



urlpatterns = [
    path("admin/", admin.site.urls),
    path("apif/user/register/", CreateUserView.as_view(), name="register"),
    path("apif/token/", UserLoginRequestOTP.as_view(), name="user_login"),   
    path("apif/token/refresh/", CookieTokenRefreshView.as_view(), name="refresh"),
    path("apif/token/verify/", UserVerifyOTP.as_view(), name="user_verify_otp"),
    path("apif-auth/", include("rest_framework.urls")),
    path("apif/", include("api.urls")), 
    path('apif/user/update/', UpdateDeleteUserView.as_view(), name='user-update'),
    path('apif/admin/register/', AdminRegisterView.as_view(), name='admin-register'),
    path("apif/admin/login/", AdminLoginRequestOTP.as_view(), name="admin_login"),
    path("apif/admin/verify/", AdminVerifyOTP.as_view(), name="admin_verify_otp"),
    path("apif/user/verify-email/<uidb64>/<token>/", VerifyEmailView.as_view(), name="verify-email"),  # ✅ Email verification endpoint
    path("apif/logout/", LogoutView.as_view(), name="logout"),  # Single logout endpoint for all users
    
    
     
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

