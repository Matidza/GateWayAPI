from django.contrib.auth.models import User
from rest_framework import serializers 
from .models import User 


# CustomUser Serializer
class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ["id", "email", 'user_type', "password"]
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        """Create user with hashed password"""
        return User.objects.create_user(**validated_data)    