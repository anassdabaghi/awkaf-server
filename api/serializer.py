from django.contrib.auth.models import User
from rest_framework import serializers
from .models import InputField,ZakatHistory,WaqfProject,Employee
from django.contrib.auth.models import User
from rest_framework import serializers
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from .models import InputField, ZakatHistory, WaqfProject
from django.db import connection
from rest_framework.validators import UniqueValidator
from rest_framework import serializers
from .models import CompanyType, CompanyField




from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Employee
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives


from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Employee
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives

# serializers.py

from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from rest_framework import serializers

User = get_user_model()

from django.contrib.auth.models import User
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from rest_framework import serializers


from django.core.exceptions import ValidationError
from rest_framework import serializers
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for Django User, with optional old_password enforcement when changing own password.
    """
    is_verified = serializers.BooleanField(source="is_active", read_only=True)
    date_joined = serializers.SerializerMethodField()
    old_password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = [
            "id", "username", "first_name", "last_name",
            "email", "password", "old_password",
            "is_verified", "date_joined"
        ]
        extra_kwargs = {
            "password": {"write_only": True, "required": False},
        }

    def get_date_joined(self, obj):
        return obj.date_joined.strftime("%Y-%m-%d")

    def validate_email(self, value):
        qs = User.objects.filter(email=value)
        if self.instance:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def validate(self, data):
        request = self.context.get("request")
        if "password" in data and request and request.user == self.instance:
            old = data.get("old_password")
            if not old:
                raise serializers.ValidationError({
                    "old_password": "كلمة المرور الحالية مطلوبة عند تغيير كلمة المرور."
                })
            if not self.instance.check_password(old):
                raise serializers.ValidationError({
                    "old_password": "كلمة المرور الحالية غير صحيحة."
                })
        return data


    def create(self, validated_data):
        password = validated_data.pop("password", None)
        user = User.objects.create(**validated_data)
        if password:
            user.set_password(password)
        user.is_active = False
        user.save()

        # ✅ Send email verification
        self._send_verification_email(user)

        return user

    def update(self, instance, validated_data):
        validated_data.pop("old_password", None)
        new_pw = validated_data.pop("password", None)

        for attr, val in validated_data.items():
            setattr(instance, attr, val)

        if new_pw:
            instance.set_password(new_pw)

        instance.save()
        return instance

    def _send_verification_email(self, user):
        from django.utils.http import urlsafe_base64_encode
        from django.utils.encoding import force_bytes
        from django.contrib.auth.tokens import default_token_generator
        from django.template.loader import render_to_string
        from django.core.mail import EmailMultiAlternatives

        request = self.context.get("request")
        host = request.get_host() if request else "localhost:8000"

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        verify_link = f"http://{host}/apif/user/verify-email/{uid}/{token}/"

        subject = "Verify Your Email Address"
        from_email = "noreply@yourdomain.com"
        to_email = [user.email]

        context = {"verify_link": verify_link, "user": user}
        html_content = render_to_string("verify_email.html", context)
        text_content = f"Please verify your email: {verify_link}"

        msg = EmailMultiAlternatives(subject, text_content, from_email, to_email)
        msg.attach_alternative(html_content, "text/html")
        msg.send()


class InputFieldSerializer(serializers.ModelSerializer):
    class Meta:
        model = InputField
        fields = '__all__'


class BulkUpdateInputFieldSerializer(serializers.ModelSerializer):
    class Meta:
        model = InputField
        fields = ["id", "label", "placeholder", "input_type", "is_required", "max_characters", "min_characters"]

    def update(self, instance, validated_data):
        """Ensure updates are applied correctly"""
        for attr, value in validated_data.items():
            setattr(instance, attr, value)  # Apply updates
        instance.save()  # Save changes
        return instance

class BulkUpdateListSerializer(serializers.ListSerializer):
    def update(self, instances, validated_data):
        instance_mapping = {instance.id: instance for instance in instances}
        updated_instances = []

        for item in validated_data:
            instance = instance_mapping.get(item.get('id'))
            if instance:
                for attr, value in item.items():
                    setattr(instance, attr, value)
                instance.save()
                updated_instances.append(instance)

        return updated_instances
class BulkUpdateInputFieldSerializer(serializers.ModelSerializer):
    class Meta:
        model = InputField
        fields = ["id", "label", "placeholder", "input_type", "is_required", "max_characters", "min_characters"]
        list_serializer_class = BulkUpdateListSerializer
        # Use custom bulk update serializer
class ZakatHistorySerializer(serializers.ModelSerializer):
    created_at = serializers.DateField(format="%Y-%m-%d", required=True)
    zakat_amount = serializers.FloatField(required=False, allow_null=True)  # ✅ Optional field
    nisab = serializers.FloatField(required=True)  # ✅ Required field

    class Meta:
        model = ZakatHistory
        fields = "__all__"  # ✅ Include all fields
        extra_kwargs = {
            "user": {"read_only": True}  # ✅ Make 'user' read-only so it's set automatically
        }


class WaqfProjectSerializer(serializers.ModelSerializer):
    name = serializers.CharField(
        max_length=255,
        validators=[UniqueValidator(queryset=WaqfProject.objects.all())]
    )

    class Meta:
        model = WaqfProject
        fields = '__all__'

from rest_framework import serializers
from .models import CompanyType, CompanyField

from rest_framework import serializers
from .models import CompanyField

from rest_framework import serializers
from .models import CompanyType, CompanyField

class CompanyFieldInputSerializer(serializers.Serializer):
    name     = serializers.CharField()
    label    = serializers.CharField()
    children = serializers.ListField(child=serializers.DictField(), required=False)

class CompanyFieldOutputSerializer(serializers.ModelSerializer):
    children = serializers.SerializerMethodField()

    class Meta:
        model  = CompanyField
        fields = ['name', 'label', 'children']

    def get_children(self, obj):
        return CompanyFieldOutputSerializer(obj.children.all(), many=True).data

class CompanyTypeSerializer(serializers.ModelSerializer):
    # incoming
    fields = CompanyFieldInputSerializer(many=True, write_only=True)
    # outgoing
    output_fields = serializers.SerializerMethodField()

    class Meta:
        model  = CompanyType
        fields = ['id', 'name', 'calculation_method', 'fields', 'output_fields']

    def get_output_fields(self, obj):
        # only top-level fields
        roots = obj.fields.filter(parent__isnull=True)
        return CompanyFieldOutputSerializer(roots, many=True).data

    def create(self, validated_data):
        tree = validated_data.pop('fields', [])
        company_type = CompanyType.objects.create(**validated_data)

        def recurse(nodes, parent=None):
            for node in nodes:
                nm  = node['name'].strip().replace(' ', '_')
                lb  = node['label'].strip() or nm
                cf  = CompanyField.objects.create(
                    company_type=company_type,
                    parent=parent,
                    name=nm,
                    label=lb
                )
                recurse(node.get('children', []), parent=cf)

        recurse(tree)
        return company_type

    def to_representation(self, instance):
        data = super().to_representation(instance)
        # rename for client
        data['fields'] = data.pop('output_fields', [])
        return data

class ZakatHistorySerializer(serializers.ModelSerializer):
    user_id = serializers.IntegerField(source='user.id', read_only=True)
    user_name = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model = ZakatHistory
        fields = ['id', 'user_id', 'user_name', 'zakat_base', 'zakat_result', 'month_type', 'calculation_date', 'nissab']
from rest_framework import serializers
from .models import WaqfProject  # Make sure the model path is correct


class WaqfProjectSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(format="%Y-%m-%d", required=False)
    updated_at = serializers.DateTimeField(format="%Y-%m-%d", required=False)

    class Meta:
        model = WaqfProject
        fields = [
            "id",
            "name",
            "domain",
            "objectives",
            "partners",
            "image",
            "created_at",
            "updated_at"
        ]
    from rest_framework import serializers

class CompanyTypeSimpleSerializer(serializers.ModelSerializer):
    """
    Only id, name and a flat list of the top-level fields (name + label).
    """
    custom_fields = serializers.SerializerMethodField()

    class Meta:
        model  = CompanyType
        fields = ['id', 'name', 'custom_fields']

    def get_custom_fields(self, obj):
        # only root (parent=None) fields
        roots = obj.fields.filter(parent__isnull=True)
        return [
            {'name': f.name, 'label': f.label}
            for f in roots
        ]
from django.contrib.auth.models import User
from rest_framework import serializers


class UserInfoSerializer(serializers.ModelSerializer):
    is_staff = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_staff']

    def get_is_staff(self, obj):
        return 1 if obj.is_staff else 0




from rest_framework import serializers
from .models import Ma7acil

class Ma7acilSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ma7acil
        fields = '__all__'
