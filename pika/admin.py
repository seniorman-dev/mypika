from django.contrib import admin
from .models import User

# Register your models here.

class UserAdmin(admin.ModelAdmin):
    #name of fields of model that you'd like to display
    list_display = ('email', "first_name", "last_name", "is_active", "is_staff", "created_at")

    
# Manage the 'User' in our Django Admin Panel
admin.site.register(model_or_iterable=User, admin_class=UserAdmin)


