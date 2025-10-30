from django.shortcuts import render
from django.contrib.auth.models import User
from rest_framework import generics
from .serializer import UserSerializer, InputFieldSerializer, BulkUpdateInputFieldSerializer,ZakatHistorySerializer
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from django.db.models.functions import TruncDate
from django.db.models import Count
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework import status
from rest_framework import exceptions
from .models import InputField,ZakatHistory
from datetime import datetime
from django.shortcuts import get_object_or_404
from django.db import connection
from django.conf import settings
from rest_framework import generics, permissions
from .models import WaqfProject,Employee
from .serializer import WaqfProjectSerializer
from .permissions import IsStaffUser  # Custom permission
from django.core.mail import send_mail
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth.tokens import default_token_generator
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import random
from django.contrib.auth import authenticate, login
from django.http import JsonResponse
from .models import OTPCode

from django.utils.timezone import now 
from datetime import timedelta
from rest_framework.decorators import api_view, permission_classes
#from rest_framework.request import Request
from django.core.cache import cache
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from rest_framework import generics
from rest_framework.pagination import PageNumberPagination
from api.models import User
from api.serializer import UserSerializer
from api.permissions import IsStaffUser
from .models import CompanyType, CompanyField
from .serializer import CompanyTypeSerializer
from rest_framework.decorators import api_view
from django.shortcuts import get_object_or_404
from django.db.utils import IntegrityError
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.core.cache import cache
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.utils.timezone import now
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from .serializer import (
    
    CompanyTypeSerializer
    
)




from rest_framework import generics, permissions
from django.contrib.auth.models import User
from .serializer import UserSerializer

class CreateUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]

    def get_serializer_context(self):
        return {"request": self.request}  # ✅ pass request to serializer via context

    def perform_create(self, serializer):
        print("Incoming Data:", self.request.data)
        serializer.save()  # ✅ no request here

from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator

from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator


import threading
from django.core.mail import send_mail

def send_otp_email_async(user):
    def task():
        send_otp_email(user)
    threading.Thread(target=task).start()

class UserLoginRequestOTP(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        # First, check if the user exists
        user = User.objects.filter(username=username).first()
        
        if not user:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the user's email is verified (active account)
        if not user.is_active:
            return Response({"error": "Email not verified. Please verify your email."}, status=status.HTTP_403_FORBIDDEN)

        # Authenticate after checking if the user is active
        user = authenticate(username=username, password=password)
        if not user:
            return Response({"error": "Invalid password"}, status=status.HTTP_400_BAD_REQUEST)
        # Send OTP email
        # if not user.is_active:
        #     send_otp_email(user)  # Send OTP email
        #     return Response({"message": "OTP sent to your email. Enter OTP to proceed."})
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)
        response = Response({"message": "Authentification successful." ,
                            "access": access_token,
                            "refresh": refresh_token
                            }, status=status.HTTP_200_OK)

        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=False,         # Set to False only in local dev (True in production with HTTPS)
            samesite="Lax",     # Allows cross-site requests (for frontend/backend on different domains)
            max_age=5 * 60       # Match your access token lifetime (in seconds)
        )

        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=False,
            samesite="Lax",
            max_age=24 * 60 * 60  # 1 day
        )

        return response

class UserVerifyOTP(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        otp = request.data.get("otp")

        # ✅ Check if user exists
        user = User.objects.filter(username=username).first()
        if not user:
            return Response({"error": "Invalid username"}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Check if OTP exists
        otp_obj = OTPCode.objects.filter(user=user).first()
        if not otp_obj:
            return Response({"error": "Invalid or expired OTP"}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Check expiration
        if (now() - otp_obj.created_at) > timedelta(minutes=5):
            otp_obj.delete()
            return Response({"error": "OTP has expired. Request a new one."}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Check match
        if otp_obj.otp != otp:
            return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Activate and clean up
        user.is_active = True
        user.save()
        otp_obj.delete()

        # ✅ Generate tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        # ✅ Build response
        response = Response({"message": "OTP verified successfully",
                            "access": access_token,
                            "refresh": refresh_token
                            }, status=status.HTTP_200_OK)

        # ✅ Store tokens in secure HTTP-only cookies
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=False,         # Set to False only in local dev (True in production with HTTPS)
            samesite="Lax",     # Allows cross-site requests (for frontend/backend on different domains)
            max_age=5 * 60       # Match your access token lifetime (in seconds)
        )

        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=False,
            samesite="Lax",
            max_age=24 * 60 * 60  # 1 day
        )

        return response

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status
from .serializer import UserSerializer

class AdminRegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data
        data["is_staff"] = True  # Mark this user as admin

        serializer = UserSerializer(data=data, context={"request": request})  # ✅ Pass request
        if serializer.is_valid():
            serializer.save()  # Email is sent inside serializer
            return Response({"message": "Admin account created. Please verify your email."}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class AdminLoginRequestOTP(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        secret_key = request.data.get("secret_key")

        # First, check if the user exists
        user = User.objects.filter(username=username).first()
        
        if not user or not user.is_staff:
            return Response({"error": "Invalid admin credentials"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the user's email is verified (active account)
        if not user.is_active:
            return Response({"error": "User is not verified. Please verify your email first."}, status=status.HTTP_403_FORBIDDEN)

        # Authenticate after checking if the user is active
        user = authenticate(username=username, password=password)
        if not user:
            return Response({"error": "Invalid password"}, status=status.HTTP_400_BAD_REQUEST)

        # Verify the secret key
        if secret_key != settings.ADMIN_SECRET_KEY:
            return Response({"error": "Invalid secret key"}, status=status.HTTP_403_FORBIDDEN)

        send_otp_email(user)  # Send OTP email
        return Response({"message": "OTP sent to your email. Enter OTP to proceed."})
class AdminVerifyOTP(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        otp = request.data.get("otp")

        # 1️⃣ Check if admin exists
        user = User.objects.filter(username=username, is_staff=True).first()
        if not user:
            return Response({"error": "Invalid username"}, status=status.HTTP_400_BAD_REQUEST)

        # 2️⃣ Check if OTP exists for the admin
        otp_obj = OTPCode.objects.filter(user=user).first()
        if not otp_obj:
            return Response({"error": "Invalid or expired OTP"}, status=status.HTTP_400_BAD_REQUEST)

        # 3️⃣ Check expiration (5 minutes)
        if (now() - otp_obj.created_at) > timedelta(minutes=5):
            otp_obj.delete()
            return Response({"error": "OTP has expired. Request a new one."}, status=status.HTTP_400_BAD_REQUEST)

        # 4️⃣ Check OTP match
        if otp_obj.otp != otp:
            return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

        # 5️⃣ Activate admin & delete OTP
        user.is_active = True
        user.save()
        otp_obj.delete()

        # 6️⃣ Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        # 7️⃣ Create response
        response = Response({"message": "OTP verified successfully!"}, status=status.HTTP_200_OK)

        # 8️⃣ Store tokens in HttpOnly cookies
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=False,  # only secure in production
            samesite="Lax",
            max_age=60 * 5  # 5 minutes
        )
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=False,
            samesite="Lax",
            max_age=60 * 60 * 24 * 7  # 7 days
        )

        return response
        
# views.py

from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .serializer import UserSerializer

User = get_user_model()

class UpdateDeleteUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self):
        # Always operate on the authenticated user
        return self.request.user

    def put(self, request, *args, **kwargs):
        # Full update: all writable fields should be provided
        return self.update_user(request, partial=False)

    def patch(self, request, *args, **kwargs):
        # Partial update: only provided fields will change
        return self.update_user(request, partial=True)

    def update_user(self, request, partial):
        user = self.get_object()
        serializer = UserSerializer(
            user,
            data=request.data,
            partial=partial,
            context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def delete(self, request, *args, **kwargs):
        user = self.get_object()
        user.delete()
        return Response({"message": "Account deleted successfully."}, status=204)




class AdminRegisterView(APIView):
    permission_classes = [AllowAny]  # Allow unauthenticated users to register

    def post(self, request):
        # Get data from the request
        data = request.data

        # Explicitly set is_staff to True for admin creation
        data["is_staff"] = True  # Always make is_staff True for admins

        # Use the UserSerializer to validate and create the admin user
        serializer = UserSerializer(data=data)
        if serializer.is_valid():
            user = serializer.save()  # Admin user is created with is_staff=True
            return Response({"message": "Admin user created successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AdminLoginView(TokenObtainPairView):
    """
    Admin login view that uses JWT to authenticate admins.
    Admins must provide a secret key along with their credentials.
    """

    def post(self, request, *args, **kwargs):
        username = request.data.get("username")
        secret_key = request.data.get("secret_key")  # Get secret key from frontend

        try:
            user = User.objects.get(username=username)

            # Check if the user is an admin
            if not user.is_staff:
                raise PermissionDenied("Only admins can log in via this endpoint.")

            # Verify the secret key
            if secret_key != settings.ADMIN_SECRET_KEY:
                return Response({"error": "Invalid secret key"}, status=status.HTTP_403_FORBIDDEN)

        except User.DoesNotExist:
            return Response({"error": "Invalid username or password"}, status=status.HTTP_401_UNAUTHORIZED)

        # Proceed with JWT token generation
        return super().post(request, *args, **kwargs)


class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        username = request.data.get("username")
        user = User.objects.filter(username=username).first()
        
        if user and not user.is_active:
            return Response({"error": "Email not verified. Please verify your email before logging in."}, status=status.HTTP_403_FORBIDDEN)
        
        return super().post(request, *args, **kwargs)



class InputFieldListCreate(APIView):
    permission_classes = [IsAuthenticated]  # Only authenticated users can access this view

    def post(self, request):
        # Check if the request data is a single object (dict) or a list
        if isinstance(request.data, dict):
            serializer = InputFieldSerializer(data=request.data)  # Single object creation
        elif isinstance(request.data, list):
            serializer = InputFieldSerializer(data=request.data, many=True)  # Bulk creation
        else:
            return Response({"error": "Invalid data format"}, status=status.HTTP_400_BAD_REQUEST)

        if serializer.is_valid():
            serializer.save()  # ✅ Ensure many=True serializer is saved properly
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BulkInputFieldUpdate(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        """Handles full updates (replacing all fields)."""
        return self.update_fields(request, partial=False)

    def patch(self, request):
        """Handles partial updates (modifying only specified fields)."""
        return self.update_fields(request, partial=True)

    def update_fields(self, request, partial):
        data = request.data

        # Convert single update request into a list
        if isinstance(data, dict):
            data = [data]

        instance_ids = [item.get("id") for item in data if "id" in item]
        if not instance_ids:
            return Response({"error": "No valid IDs provided for update"}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch instances from the database
        instances = {instance.id: instance for instance in InputField.objects.filter(id__in=instance_ids)}

        if len(instances) != len(instance_ids):
            return Response({"error": "Some IDs do not exist in the database"}, status=status.HTTP_400_BAD_REQUEST)

        updated_instances = []
        errors = {}

        # Apply updates manually
        for item in data:
            instance = instances.get(item["id"])
            serializer = BulkUpdateInputFieldSerializer(instance, data=item, partial=partial)

            if serializer.is_valid():
                updated_instance = serializer.save()
                updated_instances.append(updated_instance)
            else:
                errors[item["id"]] = serializer.errors

        if errors:
            return Response({"errors": errors}, status=status.HTTP_400_BAD_REQUEST)

        # Serialize the updated instances
        serialized_data = BulkUpdateInputFieldSerializer(updated_instances, many=True).data

        return Response({"message": "Successfully updated", "data": serialized_data}, status=status.HTTP_200_OK)



class BulkInputFieldDelete(APIView):
    permission_classes = [IsAuthenticated]  # Only authenticated users can access this view

    def delete(self, request):
        data = request.data

        # Handle single delete (convert single ID to list)
        if isinstance(data, dict) and "id" in data:
            data = {"ids": [data["id"]]}

        instance_ids = data.get('ids', [])

        if not instance_ids:
            return Response({"error": "No IDs provided"}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure the requested IDs exist
        deleted_count, _ = InputField.objects.filter(id__in=instance_ids).delete()

        if deleted_count == 0:
            return Response({"error": "No valid IDs found"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "InputFields deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
    
from django.db import connection


class AdminDeleteUserView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, user_id):
        if not request.user.is_staff:
            raise PermissionDenied("Only admins can delete users.")
        
        user = get_object_or_404(User, id=user_id)
        
        if user.is_staff:
            return Response({"error": "You cannot delete another admin."}, status=status.HTTP_403_FORBIDDEN)
        
        user.delete()

        # ✅ Clear the cached non-staff users list after deletion
        cache.delete("non_staff_users_list")

        return Response({"message": "User deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

    
class WaqfProjectListCreateView(generics.ListCreateAPIView):
    queryset = WaqfProject.objects.all().order_by('-created_at')  # Order by newest first
    serializer_class = WaqfProjectSerializer
    permission_classes = [IsStaffUser]  # Only staff users can add

# Retrieve, Update & Delete View (Only Staff Users can modify)
class WaqfProjectDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = WaqfProject.objects.all()
    serializer_class = WaqfProjectSerializer
    permission_classes = [IsStaffUser]  # Only staff users can edit/delete

# Read-Only List View (Anyone can access)
class WaqfProjectReadOnlyListView(generics.ListAPIView):
    queryset = WaqfProject.objects.all().order_by('-created_at')  # Order by newest first
    serializer_class = WaqfProjectSerializer
    permission_classes = [AllowAny]  # Public access

# Read-Only Detail View (Anyone can access)
class WaqfProjectReadOnlyDetailView(generics.RetrieveAPIView):
    queryset = WaqfProject.objects.all()
    serializer_class = WaqfProjectSerializer
    permission_classes = [AllowAny]  # Public access



from django.core.mail import send_mail
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

@csrf_exempt  # Bypass CSRF protection for testing
def send_contact_email(request):
    if request.method == "POST":
        try:
            # Decode the JSON body
            data = json.loads(request.body.decode("utf-8"))

            first_name = data.get("first_name")
            last_name = data.get("last_name")
            sender_email = data.get("sender_email")
            phone = data.get("phone")
            message = data.get("message")

            # Debugging: Print values to check if they are received
            print("Received Data:")
            print(f"First Name: {first_name}")
            print(f"Last Name: {last_name}")
            print(f"Email: {sender_email}")
            print(f"Phone: {phone}")
            print(f"Message: {message}")

            if not all([first_name, last_name, sender_email, message]):
                return JsonResponse({"error": "All fields are required"}, status=400)

            subject = f"New Message from {first_name} {last_name}"
            full_message = f"""
            First Name: {first_name}
            Last Name: {last_name}
            Email: {sender_email}
            Phone: {phone}

            Message:
            {message}
            """
            receiver_email = "amine.dizo123@gmail.com" 

            send_mail(subject, full_message, sender_email, [receiver_email])

            return JsonResponse({"success": "Email sent successfully"}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format"}, status=400)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request"}, status=400)
from django.shortcuts import render
from django.shortcuts import render
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView

class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)

            if default_token_generator.check_token(user, token):
                user.is_active = True
                user.save()
                return render(request, "verify_success.html")  # ✅ styled success page
            else:
                return render(request, "verify_failed.html")   # ✅ styled fail page

        except (User.DoesNotExist, ValueError, TypeError):
            return render(request, "verify_failed.html")    
class RequestPasswordResetView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        try:
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_link = f"http://{request.get_host()}/apif/user/reset-password/{uid}/{token}/"

            subject = "Reset Your Password"
            from_email = "noreply@yourdomain.com"
            to_email = [email]

            context = {
                "user": user,
                "reset_link": reset_link,
            }

            html_content = render_to_string("reset_password_email.html", context)
            text_content = f"Click the link to reset your password: {reset_link}"

            msg = EmailMultiAlternatives(subject, text_content, from_email, to_email)
            msg.attach_alternative(html_content, "text/html")
            msg.send()

            return Response({"message": "Password reset email sent!"})

        except User.DoesNotExist as error:
            print(f"❌ No user found with email: {email} - {error}")
            return Response({"error": "لا يوجد مستخدم بهذا البريد الإلكتروني"}, status=status.HTTP_400_BAD_REQUEST)



# views.py

from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model
from django.core.mail import send_mail

from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework.renderers import JSONRenderer, TemplateHTMLRenderer

User = get_user_model()

class ResetPasswordView(APIView):
    permission_classes = [AllowAny]
    renderer_classes = [JSONRenderer, TemplateHTMLRenderer]
    template_name = "reset_password_form.html"

    def get(self, request, uidb64, token):
        print("📩 [GET] Password reset link opened!")
        print(f"🔹 UIDB64: {uidb64}")
        print(f"🔹 Token: {token}")

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            print(f"🧠 Decoded UID: {uid}")
            user = User.objects.get(pk=uid)
            print(f"🧍 User found → ID: {user.id}, Email: {user.email}")
        except Exception as e:
            print(f"❌ Error decoding UID or fetching user: {e}")
            return Response(
                {"error": "Invalid link."},
                status=status.HTTP_400_BAD_REQUEST,
                template_name=self.template_name
            )

        if not default_token_generator.check_token(user, token):
            print(f"⚠️ Token invalid or expired for user ID {user.id}")
            return Response(
                {"error": "Token invalid or expired."},
                status=status.HTTP_400_BAD_REQUEST,
                template_name=self.template_name
            )

        print(f"✅ Token valid for user ID {user.id}")
        return Response(
            {"uidb64": uidb64, "token": token},
            template_name=self.template_name
        )

    def post(self, request, uidb64, token):
        print("📩 [POST] Password reset submission received!")
        print(f"🔹 UIDB64: {uidb64}")
        print(f"🔹 Token: {token}")

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            print(f"🧠 Decoded UID: {uid}")
            user = User.objects.get(pk=uid)
            print(f"🧍 User found → ID: {user.id}, Email: {user.email}")
        except Exception as e:
            print(f"❌ Error decoding UID or fetching user: {e}")
            return Response(
                {"error": "Invalid link."},
                status=status.HTTP_400_BAD_REQUEST,
                template_name=self.template_name
            )

        if not default_token_generator.check_token(user, token):
            print(f"⚠️ Token invalid or expired for user ID {user.id}")
            return Response(
                {"error": "Token invalid or expired."},
                status=status.HTTP_400_BAD_REQUEST,
                template_name=self.template_name
            )

        new_password = request.data.get("password") or request.POST.get("password")
        if not new_password:
            print(f"⚠️ Empty password field for user ID {user.id}")
            return Response(
                {"error": "Password cannot be empty."},
                status=status.HTTP_400_BAD_REQUEST,
                template_name=self.template_name
            )

        print(f"🔑 Setting new password for user ID {user.id}")
        user.set_password(new_password)
        user.save()
        print(f"💾 Password updated successfully for user ID {user.id}")

        try:
            send_mail(
                "Your password was changed",
                "Your password has been successfully reset.",
                "noreply@yourdomain.com",
                [user.email],
                fail_silently=False,
            )
            print(f"📬 Confirmation email sent to {user.email}")
        except Exception as e:
            print(f"🚫 Failed to send confirmation email: {e}")

        print(f"🎉 Password reset complete for user ID {user.id}")
        return Response(
            {"success": "Your password has been reset!"},
            template_name=self.template_name
        )

from django.shortcuts import render
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.views import View

from django.shortcuts import render
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.views import View

class ResetPasswordHTMLView(View):
    def get(self, request, uidb64, token):
        # Just show the form with the uidb64 and token as hidden fields
        return render(request, "reset_password_form.html", {"uidb64": uidb64, "token": token})

    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)

            # Validate the token
            if not default_token_generator.check_token(user, token):
                return render(request, "reset_password_form.html", {
                    "error": "Invalid or expired link."
                })

            password = request.POST.get("password")
            if not password:
                return render(request, "reset_password_form.html", {
                    "error": "Password cannot be empty.",
                })

            # Set and save the new password
            user.set_password(password)
            user.save()

            # Optional: Send confirmation email
            send_mail(
                subject="Your password was changed",
                message="Your password has been successfully reset.",
                from_email="noreply@yourdomain.com",
                recipient_list=[user.email],
                fail_silently=False,
            )

            return render(request, "reset_password_form.html", {
                "success": "Your password has been reset successfully!"
            })

        except Exception as e:
            return render(request, "reset_password_form.html", {
                "error": "Something went wrong. Please try again.",
            })

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Prefer refresh token from httpOnly cookie
            refresh_token = request.COOKIES.get("refresh_token")

            # Fallback: allow body token for backwards compatibility
            if not refresh_token:
                refresh_token = request.data.get("refresh_token")

            # Prepare response and clear cookies regardless
            response = Response({"message": "Successfully logged out"}, status=status.HTTP_200_OK)
            response.delete_cookie("access_token", path="/")
            response.delete_cookie("refresh_token", path="/")

            # If we have a refresh token, try to blacklist it
            if refresh_token:
                try:
                    token = RefreshToken(refresh_token)
                    token.blacklist()
                except Exception:
                    # Ignore blacklist errors to ensure logout always succeeds
                    pass

            return response
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

# ✅ Custom Pagination Class

class ArrayPagination(PageNumberPagination):
    """ ✅ Returns only the list of users instead of an object """
    page_size = 10
    page_size_query_param = "page_size"
    max_page_size = 50

    def get_paginated_response(self, data):
        return Response(data)  # ✅ Only return the array (not an object)

# ✅ Admin Non-Staff User List View
class AdminNonStaffUserListView(generics.ListAPIView):
    """ ✅ Allows only staff users to see non-staff users with optional pagination """

    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = None  # Default: No pagination
    CACHE_KEY = "non_staff_users_list"

    def get_queryset(self):
        """ ✅ Fetch non-staff users """
        return User.objects.filter(is_staff=False).only("id", "username", "email", "date_joined")

    def list(self, request, *args, **kwargs):
        """ ✅ Return paginated or full user list based on request """
        queryset = self.get_queryset()

        # ✅ Serialize data
        serializer = self.get_serializer(queryset, many=True)
        serialized_data = serializer.data

        # ✅ Apply pagination if requested
        if "page" in request.GET and "page_size" in request.GET:
            paginator = ArrayPagination()
            paginated_data = paginator.paginate_queryset(serialized_data, request, view=self)
            return paginator.get_paginated_response(paginated_data)

        # ✅ Default: Return all users (no pagination)
        return Response(serialized_data)

    
def send_otp_email(user):
    otp = str(random.randint(100000, 999999))  # Generate a 6-digit OTP

    # Try to update existing OTP or create a new one
    otp_obj, created = OTPCode.objects.update_or_create(
        user=user, defaults={"otp": otp, "created_at": now()}
    )

    # 🔥 Debugging: Print to console/logs
    print(f"OTP for {user.username}: {otp}, Stored: {created}")

    # Check if OTP was successfully saved
    saved_otp = OTPCode.objects.filter(user=user).first()
    if not saved_otp:
        print("❌ ERROR: OTP not saved in the database!")

    # Send OTP email
    send_mail(
        subject="Your OTP Code",
        message=f"Your OTP code is {otp}. It expires in 10 minutes.",
        from_email="your@email.com",  # Change this to your sender email
        recipient_list=[user.email],
        fail_silently=False,
    )
def verify_otp(request):
    if request.method == "POST":
        data = json.loads(request.body)
        username = data.get("username")
        otp = data.get("otp")

        user = User.objects.filter(username=username).first()
        otp_obj = OTPCode.objects.filter(user=user).first()

        if not user or not otp_obj:
            return JsonResponse({"error": "Invalid username or OTP"}, status=400)

        if otp_obj.otp == otp:
            otp_obj.delete()  # Delete OTP after successful verification

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            return JsonResponse({
                "access_token": access_token,
                "refresh_token": str(refresh),
            })

        return JsonResponse({"error": "Invalid or expired OTP"}, status=400)
    
@api_view(['POST'])
@permission_classes([IsAuthenticated])  # Ensure only authenticated users can access
def create_table(request):
    user = request.user
    if not user.is_staff:  # Only admins can create tables
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    data = request.data
    type_value = data.get('type', '').strip()  # Get 'type' value and remove extra spaces
    attributes = data.get('attributes', [])

    if not type_value or not attributes:
        return JsonResponse({'error': 'Invalid data'}, status=400)

    table_name = f"type de {type_value}"  # Format the table name with spaces
    table_name = f"`{table_name}`"  # Wrap it in backticks for MySQL compatibility

    # Prevent 'id' from being passed in attributes
    for attr in attributes:
        if attr['name'].lower() == 'id':
            return JsonResponse({'error': "You cannot define 'id' as a custom attribute."}, status=400)

    # Build SQL query for table creation
    columns_sql = ", ".join([f"`{attr['name']}` {attr['type']}" for attr in attributes])
    sql_query = f"CREATE TABLE {table_name} (`id` INT AUTO_INCREMENT PRIMARY KEY, {columns_sql});"

    try:
        with connection.cursor() as cursor:
            cursor.execute(sql_query)
        return JsonResponse({'message': f'Table {table_name} created successfully'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    


@api_view(['GET'])
@permission_classes([IsAuthenticated])  # Require authentication
def get_table_data(request, table_name):
    user = request.user
    if not user.is_staff:  # Check if the user is an admin
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    table_name = f"type de {table_name}"  # Format the table name
    table_name = f"`{table_name}`"  # Wrap in backticks for MySQL compatibility

    try:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM {table_name};")
            columns = [col[0] for col in cursor.description]  # Get column names
            rows = cursor.fetchall()  # Fetch all rows

        data = [dict(zip(columns, row)) for row in rows]
        return JsonResponse({'table_name': table_name, 'data': data})
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def rename_table(request):
    user = request.user
    if not user.is_staff:  
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    data = request.data
    old_name = f"type de {data.get('old_name', '').strip()}"
    new_name = f"type de {data.get('new_name', '').strip()}"

    try:
        with connection.cursor() as cursor:
            cursor.execute(f"ALTER TABLE `{old_name}` RENAME TO `{new_name}`;")
        return JsonResponse({'message': f'Table renamed to {new_name} successfully'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)








@api_view(['POST'])
@permission_classes([IsAuthenticated])
def modify_table(request):
    user = request.user
    if not user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    data = request.data
    table_name = f"type de {data.get('table_name', '').strip()}"
    add_columns = data.get('add_columns', [])
    remove_columns = data.get('remove_columns', [])

    # 🚨 Prevent deletion of the 'id' column
    if "id" in remove_columns:
        return JsonResponse({'error': "Cannot delete primary key column 'id'."}, status=400)

    alter_queries = []

    # Adding new columns
    for col in add_columns:
        alter_queries.append(f"ADD COLUMN `{col['name']}` {col['type']}")

    # Removing columns (excluding 'id')
    for col in remove_columns:
        alter_queries.append(f"DROP COLUMN `{col}`")

    if not alter_queries:
        return JsonResponse({'error': 'No modifications specified'}, status=400)

    alter_sql = f"ALTER TABLE `{table_name}` " + ", ".join(alter_queries) + ";"

    try:
        with connection.cursor() as cursor:
            cursor.execute(alter_sql)
        return JsonResponse({'message': f'Table {table_name} modified successfully'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    
    
    
    
    
    
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_table(request, table_name):
    user = request.user
    if not user.is_staff:  
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    full_table_name = f"type de {table_name}"

    try:
        with connection.cursor() as cursor:
            cursor.execute(f"DROP TABLE `{full_table_name}`;")
        return JsonResponse({'message': f'Table {full_table_name} deleted successfully'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    
from rest_framework import generics
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .models import WaqfProject
from .serializer import WaqfProjectSerializer


class WaqfProjectListView(generics.ListAPIView):
    """ ✅ Returns all Waqf projects (paginated or full list) as an array """

    serializer_class = WaqfProjectSerializer
    permission_classes = [AllowAny]
    pagination_class = None  # Default: No pagination unless requested

    def get_queryset(self):
        """ ✅ Fetch all Waqf projects with selected fields """
        return WaqfProject.objects.all().only(
            "id", "name", "domain", "objectives", "partners", "image", "created_at", "updated_at"
        )

    def list(self, request, *args, **kwargs):
        """ ✅ Return paginated or full list based on request """
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        serialized_data = serializer.data

        # ✅ Apply pagination if requested
        if "page" in request.GET and "page_size" in request.GET:
            paginator = ArrayPagination()
            paginated_data = paginator.paginate_queryset(serialized_data, request, view=self)
            return paginator.get_paginated_response(paginated_data)

        return Response(serialized_data)



from django.shortcuts import get_object_or_404
from sympy import sympify, symbols # type: ignore
from .models import CompanyType, CompanyField

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view
from .models import CompanyType, CompanyField
from .serializer import CompanyTypeSerializer

import json
import re
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.db.utils import IntegrityError
from sympy import symbols, sympify
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import CompanyType, CompanyField


 


import re
import json
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import CompanyType, CompanyField
from django.db.utils import IntegrityError

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.db import IntegrityError
from django.shortcuts import get_object_or_404
from sympy import sympify, symbols
import json
import re

class CompanyTypeCreateView(APIView):
    permission_classes = [IsAuthenticated]  # ⚠️ Facultatif si tu veux auth

    def post(self, request, *args, **kwargs):
        serializer = CompanyTypeSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            company_type = serializer.save()
            return Response(CompanyTypeSerializer(company_type, context={'request': request}).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ZakatCalculationView(APIView):
    def post(self, request, *args, **kwargs):
        data = request.data
        company_type_id = data.get('company_type_id')
        user_inputs = data.get('user_inputs', {})
        moon = float(data.get('moon', 1))
        nissab = float(data.get('nissab', 0))

        if not company_type_id or not isinstance(user_inputs, dict):
            return Response({'error': 'Invalid data'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            zakat_base, zakat_result = self.calculate_zakat_logic(company_type_id, user_inputs, moon, nissab)
            return Response({
                "zakat_base": zakat_base,
                "zakat_result": zakat_result
            }, status=status.HTTP_200_OK)
        except ValueError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': f"Unexpected error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def calculate_zakat_logic(self, company_type_id, user_inputs, moon, nissab):
        company_type = get_object_or_404(CompanyType, id=company_type_id)

        # ← only the bottom-level fields (no children) are real inputs
        leaf_fields = CompanyField.objects.filter(
            company_type=company_type,
            children__isnull=True
        )

        # normalize keys
        user_inputs = {
            re.sub(r'\s+', '_', k.strip()): v
            for k, v in user_inputs.items()
        }

        # required = exactly those leaf names
        required = { f.name for f in leaf_fields }
        labels   = { f.name: f.label for f in leaf_fields }

        missing = required - set(user_inputs.keys())
        if missing:
            raise ValueError(
                "Missing required fields: " +
                ", ".join(labels[n] for n in missing)
            )

        # only create symbols for the leaves
        syms = { name: symbols(name) for name in required }
        expr = sympify(company_type.calculation_method, locals=syms)

        base   = round(float(expr.evalf(subs=user_inputs)), 2)
        result = base * moon if base > nissab else 0
        return base, result
from django.db import IntegrityError
from django.core.cache import cache
from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import CompanyType

@api_view(['DELETE'])
def delete_company(request, company_type_id):
    """
    Delete a company type and all its related fields.
    """
    try:
        company_type = CompanyType.objects.get(id=company_type_id)
    except CompanyType.DoesNotExist:
        return Response({"error": f"Company Type with ID {company_type_id} not found"}, status=status.HTTP_404_NOT_FOUND)

    # Delete the company type (cascades to related fields)
    company_type.delete()
    
    # ✅ Ensure a valid DRF Response
    return Response({"message": f"Company Type {company_type_id} deleted successfully"}, status=status.HTTP_200_OK)

@api_view(['PUT', 'PATCH'])
def update_company_with_fields(request, company_type_id):
    """
    Update a company type and its related fields.
    - PUT: Full replace (deletes old fields and adds new ones)
    - PATCH: Modify only provided fields (replace names if needed)
    """
    company_type = get_object_or_404(CompanyType, id=company_type_id)
    
    # Extract request data
    data = request.data
    fields_data = data.pop('fields', None)  # Extract fields if provided

    # Update company type details
    serializer = CompanyTypeSerializer(company_type, data=data, partial=(request.method == "PATCH"))
    
    if serializer.is_valid():
        serializer.save()
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # Handle fields update
    if fields_data is not None:
        if request.method == "PUT":
            # PUT: Remove all fields and add new ones
            company_type.fields.all().delete()
        
        for field_data in fields_data:
            field_name = field_data.get("name")
            if not field_name:
                continue  # Skip invalid fields
            
            existing_field = company_type.fields.filter(name=field_name).first()
            
            if request.method == "PATCH":
                if existing_field:
                    # PATCH: Rename existing field instead of adding duplicate
                    existing_field.name = field_name
                    existing_field.save()
                else:
                    # PATCH: Add new field if it does not exist
                    CompanyField.objects.create(company_type=company_type, **field_data)
            else:
                # PUT: Just add new fields (all old ones were deleted)
                CompanyField.objects.create(company_type=company_type, **field_data)

    return Response(serializer.data, status=status.HTTP_200_OK)


# api/views.py

from django.shortcuts      import get_object_or_404
from django.utils.timezone import now

from rest_framework         import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response   import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views      import APIView

from .models      import CompanyType, CompanyField, ZakatHistory
from .serializer  import (
    CompanyTypeSimpleSerializer,
    ZakatHistorySerializer
)

from rest_framework_simplejwt.tokens import AccessToken, TokenError


from django.shortcuts      import get_object_or_404
from rest_framework.decorators import api_view
from rest_framework.response   import Response
from rest_framework import status

from .models     import CompanyType
from .serializer import CompanyTypeSerializer

@api_view(['GET'])
def get_company_type_fields(request, company_type_id):
    """
    Return id, name and nested fields (no calculation_method).
    """
    company_type = get_object_or_404(CompanyType, id=company_type_id)
    serializer = CompanyTypeSerializer(company_type, context={'request': request})
    data = serializer.data
    # keep id, remove calculation_method only
    data.pop('calculation_method', None)
    return Response(data, status=status.HTTP_200_OK)


@api_view(['GET'])
def list_all_company_types(request):
    """
    Return all company-types with id, name and nested fields.
    """
    qs = CompanyType.objects.all()
    serializer = CompanyTypeSerializer(qs, many=True, context={'request': request})
    data = serializer.data
    for item in data:
        # keep id, remove calculation_method only
        item.pop('calculation_method', None)
    return Response(data, status=status.HTTP_200_OK)



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def zakat_history(request):
    """
    Save zakat calculation in the database for the authenticated user.
    """
    data = request.data
    required = ['zakat_base', 'zakat_result', 'nissab']
    if any(data.get(k) is None for k in required):
        return Response({"error": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)

    record = ZakatHistory.objects.create(
        user             = request.user,
        zakat_base       = data['zakat_base'],
        zakat_result     = data['zakat_result'],
        calculation_date = now().date(),
        nissab           = data['nissab']
    )
    serializer = ZakatHistorySerializer(record, context={'request': request})
    return Response(serializer.data, status=status.HTTP_201_CREATED)


@api_view(['GET'])
def get_zakat_history(request):
    """
    Retrieve all Zakat history records.
    """
    qs = ZakatHistory.objects.all().order_by('-calculation_date')
    serializer = ZakatHistorySerializer(qs, many=True, context={'request': request})
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['GET'])
def get_zakat_history_by_user(request, user_id):
    """
    Retrieve paginated Zakat history for a specific user.
    """
    qs = ZakatHistory.objects.filter(user_id=user_id).order_by('-calculation_date')

    if not qs.exists():
        return Response(
            {"message": "No zakat history found for this user."},
            status=status.HTTP_404_NOT_FOUND
        )

    # ✅ Create paginator
    paginator = PageNumberPagination()
    paginator.page_size = 10  # 10 items per page
    paginated_qs = paginator.paginate_queryset(qs, request)

    serializer = ZakatHistorySerializer(paginated_qs, many=True, context={'request': request})

    # ✅ Return paginated response
    return paginator.get_paginated_response(serializer.data)

class CheckTokenView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        token = request.GET.get("token")
        if not token:
            return Response(False, status=status.HTTP_400_BAD_REQUEST)

        try:
            access = AccessToken(token)
            exp = access["exp"]
            valid = (now().timestamp() < exp)
            return Response(valid, status=status.HTTP_200_OK)
        except (TokenError, Exception):
            return Response(False, status=status.HTTP_401_UNAUTHORIZED)

from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken, TokenError
from datetime import datetime
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken, TokenError
from datetime import datetime

class CheckTokenView(APIView):
    permission_classes = [AllowAny]  # Allow all users to access this view

    def get(self, request):
        token = request.GET.get("token")  # Get token from query parameters

        if not token:
            return Response(False, status=400)  # Return False if no token is provided

        try:
            access_token = AccessToken(token)  # Decode token
            exp_time = access_token["exp"]  # Get expiration timestamp
            is_expired = datetime.fromtimestamp(exp_time) < datetime.utcnow()  # Compare with current time

            return Response(not is_expired)  # Return True if valid, False if expired

        except (TokenError, Exception):  # Handle expired or invalid tokens
            return Response(False, status=401)  # Return False if the token is invalid or expired


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .serializer import UserInfoSerializer

class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]

    # Runs once when Django loads the class (server start or reload)
    print("🟢 CurrentUserView class loaded")

    def get(self, request):
        # Runs every time a request hits the endpoint
        print("🔵 CurrentUserView called by:", request.user)
        serializer = UserInfoSerializer(request.user)
        return Response(serializer.data)




@api_view(['DELETE'])
def delete_zakat_history(request, pk):
    """
    Delete a specific Zakat history entry by ID.
    """
    try:
        zakat_history = ZakatHistory.objects.get(pk=pk)
    except ZakatHistory.DoesNotExist:
        return Response(
            {"error": "Zakat history not found."},
            status=status.HTTP_404_NOT_FOUND
        )

    zakat_history.delete()
    return Response(
        {"message": "Zakat history deleted successfully."},
        status=status.HTTP_204_NO_CONTENT
    )




from .models import Ma7acil
from .serializer import Ma7acilSerializer  # Make sure you have this serializer


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_ma7acil(request):
    """
    Save a Ma7acil record for the authenticated user.
    """
    data = request.data
    required_fields = ['zakat_amount', 'total_amount', 'corp_type']
    
    # Validate input
    if any(data.get(field) is None for field in required_fields):
        return Response({"error": "Invalid or missing data."}, status=status.HTTP_400_BAD_REQUEST)
    
    # Create record
    record = Ma7acil.objects.create(
        id_user=request.user,
        zakat_amount=data['zakat_amount'],
        total_amount=data['total_amount'],
        corp_type=data['corp_type'],
        date=now().date()
    )

    serializer = Ma7acilSerializer(record, context={'request': request})
    return Response(serializer.data, status=status.HTTP_201_CREATED)





@api_view(['GET'])
def get_ma7acil_by_user(request, user_id):
    """
    Retrieve paginated Ma7acil records for a specific user.
    """
    qs = Ma7acil.objects.filter(id_user_id=user_id).order_by('-date')

    if not qs.exists():
        return Response(
            {"message": "No ma7acil records found for this user."},
            status=status.HTTP_404_NOT_FOUND
        )

    # ✅ Create paginator
    paginator = PageNumberPagination()
    paginator.page_size = 10  # 10 items per page
    paginated_qs = paginator.paginate_queryset(qs, request)

    serializer = Ma7acilSerializer(paginated_qs, many=True, context={'request': request})

    # ✅ Return paginated response
    return paginator.get_paginated_response(serializer.data)

@api_view(['DELETE'])
def delete_ma7acil(request, pk):
    """
    Delete a specific Ma7acil entry by ID.
    """
    try:
        ma7acil_entry = Ma7acil.objects.get(pk=pk)
    except Ma7acil.DoesNotExist:
        return Response(
            {"error": "Ma7acil record not found."},
            status=status.HTTP_404_NOT_FOUND
        )

    ma7acil_entry.delete()
    return Response(
        {"message": "Ma7acil record deleted successfully."},
        status=status.HTTP_204_NO_CONTENT
    )




from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework.response import Response
from rest_framework import status

class CookieTokenRefreshView(TokenRefreshView):
    """
    Custom TokenRefreshView that reads the refresh token from HttpOnly cookies.
    """
    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get('refresh_token')

        if refresh_token is None:
            return Response({'detail': 'Refresh token not found in cookies.'}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = self.get_serializer(data={'refresh': refresh_token})

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        # Optionally: also set a new access_token cookie
        data = serializer.validated_data
        response = Response(data, status=status.HTTP_200_OK)
        response.set_cookie(
            key="access_token",
            value=data["access"],
            httponly=True,
            secure=False,  # True in production with HTTPS
            samesite="Lax",
            max_age=15 * 60,  # match access token lifetime
        )
        return response
