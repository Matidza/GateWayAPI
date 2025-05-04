from django.contrib.auth.models import AbstractUser, BaseUserManager, Group
from django.db import models
from django.db.models.signals import post_save
from django.contrib.auth import get_user_model
from django.dispatch import receiver

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        """Create and return a regular user."""
        if not email:
            raise ValueError("The Email field must be set")
        if not password:
            raise ValueError("The Password field must be set")

        email = self.normalize_email(email)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", False)

        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and return a superuser."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        return self.create_user(email, password, **extra_fields)

class User(AbstractUser):
    username = None
    email = models.EmailField(unique=True)
    USER_TYPE_CHOICES = [
        ("job_seeker", "Job Seeker"),
        ("employer", "Employer"),
    ]
    user_type = models.CharField(
        max_length=20, choices=USER_TYPE_CHOICES, blank=True, null=True
    )

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name_plural = "Users"

    def __str__(self):
        return self.email

@receiver(post_save, sender=get_user_model())
def assign_user_group(sender, instance, created, **kwargs):
    """Assign users to groups based on their user_type after registration."""
    if created and instance.user_type:
        group_name = "Job Seekers" if instance.user_type == "job_seeker" else "Employers"
        group_obj, _ = Group.objects.get_or_create(name=group_name)
        instance.groups.add(group_obj)
