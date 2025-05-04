from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User

class UserAdmin(UserAdmin):
    model = User
    list_display = ("email", "user_type", "is_staff", "is_superuser")
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal Info", {"fields": ("user_type",)}),
        ("Permissions", {"fields": ("is_staff", "is_superuser", "groups", "user_permissions")}),
        ("Important Dates", {"fields": ("last_login", "date_joined")}),
    )
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email", "password1", "password2", "user_type"),
        }),
    )
    search_fields = ("email",)
    ordering = ("email",)

admin.site.register(User, UserAdmin)