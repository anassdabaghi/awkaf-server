from django.db import models
from django.contrib.auth.models import User
from django_otp.models import Device
import random
from django.utils.timezone import now,timedelta
from django.core.mail import send_mail

# Ensure email is unique in the User model
User._meta.get_field('email')._unique = True  

class Employee(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    company = models.CharField(max_length=100)


    def __str__(self):
        return f"{self.user.username} works at {self.company}"

class InputField(models.Model):
    INPUT_TYPE_CHOICES = [
        ('text', 'Text'),
        ('telephone', 'Telephone'),
        ('radio', 'Radio'),
        ('checkbox', 'Checkbox'),
        ('number', 'Number'),
        ('email', 'Email'),
        ('date', 'Date'),
        ('file', 'File'),
    ]

    label = models.CharField(max_length=255)
    placeholder = models.CharField(max_length=255, blank=True)
    input_type = models.CharField(max_length=50, choices=INPUT_TYPE_CHOICES)
    is_required = models.BooleanField(default=False)
    max_characters = models.IntegerField(null=True, blank=True)
    min_characters = models.IntegerField(null=True, blank=True)
    file = models.FileField(upload_to='uploads/', null=True, blank=True)  # For file uploads

    def __str__(self):
        return self.label

class WaqfProject(models.Model):
    name = models.CharField(max_length=255, default="Unnamed Project")  
    domain = models.CharField(max_length=255, default="General")  
    objectives = models.TextField(default="No objectives specified")  
    partners = models.TextField(default="No partners specified")  
    image = models.ImageField(upload_to="waqf_images/", null=True, blank=True)
    created_at = models.DateTimeField(default=now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


    
class OTPCode(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)  # 6-digit OTP
    created_at = models.DateTimeField(default=now)  # Timestamp

    def is_valid(self):
        """Check if OTP is still valid (expires after 5 minutes)."""
        return (now() - self.created_at) < timedelta(minutes=5)
    
class CompanyType(models.Model):
    name = models.CharField(max_length=255, unique=True)
    calculation_method = models.TextField()

class CompanyField(models.Model):
    company_type = models.ForeignKey(
        CompanyType,
        related_name='fields',
        on_delete=models.CASCADE
    )
    parent = models.ForeignKey(
        'self',
        null=True,
        blank=True,
        related_name='children',
        on_delete=models.CASCADE
    )
    name = models.CharField(max_length=100)   # utilisé dans les formules
    label = models.CharField(max_length=255)  # étiquette d’affichage
    
class ZakatHistory(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='zakat_histories',
        null=True,  # facultatif
        blank=True
    )
    zakat_base = models.FloatField(default=0.0)
    zakat_result = models.FloatField(default=0.0)
    month_type = models.CharField(max_length=50, default="Unknown")
    calculation_date = models.DateField(default=now)
    nissab = models.FloatField(default=0.0)

    def __str__(self):
        return f"ZakatHistory({self.user.username} - {self.month_type} - {self.calculation_date})"



from django.db import models
from django.contrib.auth.models import User
from django.utils.timezone import now

class Ma7acil(models.Model):
    id_user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='ma7acil_entries'
    )
    zakat_amount = models.FloatField(default=0.0)
    total_amount = models.FloatField(default=0.0)
    corp_type = models.CharField(max_length=100)
    date = models.DateField(default=now)

    class Meta:
        db_table = 'ma7acil'  # database table name

    def __str__(self):
        return f"Ma7acil({self.id_user.username} - {self.corp_type} - {self.date})"
