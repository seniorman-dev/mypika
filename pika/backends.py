




#myapp/backends.py

from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
from requests import Request

User = get_user_model()

class EmailBackend(BaseBackend):
    def authenticate(self, request: Request, email:str=None, password:str=None, **kwargs) -> None:
        print("[DEBUG] Custom EmailBackend called")
        try:
            user = User.objects.get(email=email)
            print("[DEBUG] EmailBackend called with:", email)
        except User.DoesNotExist:
            return None
        
        if user.check_password(password):
            print("[DEBUG] EmailBackend called with:", email)
            return user
        
        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
