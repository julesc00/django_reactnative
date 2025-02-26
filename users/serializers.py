from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import AccessToken

from users.models import Token


User = get_user_model()


class TokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = Token
        fields = ("user", "token")


class UserSerializer(serializers.ModelSerializer):
    token = serializers.SerializerMethodField()
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    username = serializers.CharField(
        required=True,
        max_length=32,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    first_name = serializers.CharField(
        required=True,
        max_length=100
    )
    last_name = serializers.CharField(
        required=True,
        max_length=100
    )
    password = serializers.CharField(
        required=True,
        min_length=8,
        write_only=True
    )

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()

        return instance

    def get_token(self, obj) -> str:
        token = AccessToken.for_user(obj)

        return str(token)

    class Meta:
        model = User
        fields = (
            "token",
            "username",
            "first_name",
            "password",
            "last_name",
            "email",
            "is_active",
            "id"
        )


