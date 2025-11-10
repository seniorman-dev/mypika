from datetime import timedelta, timezone
import os
import random
from django.shortcuts import render
from django.db import transaction

import requests
from rest_framework import viewsets, status, permissions, generics
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.exceptions import ValidationError
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser
from pika.pagination_cofig import SmallResultsSetPagination
from .models import BankDetail, CartOrder, CryptoWallet, GadgetOrder, GiftCard, LeadershipBoard, Notification, Product, ShipmentOrder, Transaction, Wallet, Message
from .serializers import (
    BankTransferSerializer,
    BuyGiftCardSerializer,
    CartOrderSerializer,
    CryptoWalletSerializer,
    DepositSerializer,
    EmailSerializer,
    GadgetOrderSerializer,
    LeadershipBoardSerializer,
    MessageSerializer,
    NotificationSerializer,
    PanicPinSerializer,
    ProductSerializer,
    RecipientCodeSerializer,
    RedeemGiftCardSerializer,
    ReportTransactionSerializer,
    ShipmentOrderSerializer,
    TransactionSerializer,
    TransferPinSerializer,
    TransferSerializer, 
    UserLoginSerializer, 
    UserRegistrationSerializer, 
    BasicUserSerializer, 
    BankDetailSerializer, 
    KycUpdateSerializer,
    WalletSerializer
)


import hmac, hashlib, json
from django.contrib.auth import logout, get_user_model
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.core.cache import cache
from rest_framework_simplejwt.tokens import RefreshToken, OutstandingToken, BlacklistedToken
from .tasks import delete_user_in_5_days, send_email_to_user
from .giftcards import GiftCardProviderService








class UserRegistrationView(generics.GenericAPIView):
    """
    View to handle user registration.
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = UserRegistrationSerializer
    
    
    def post(self, request: Request) -> Response:
        #serializer = self.get_serializer(data=request.data) ##UserRegistrationSerializer(data=request.data)
        serializer = UserRegistrationSerializer(data=request.data, context={'request': request})
        referral_code = request.data.get("referral_code")
        print("Data:", request.data)
        if serializer.is_valid():
            # Save the user from the serializer
            user = serializer.save()
            #crete default referral count to be zero
            user.referral_count = 0
            user.save()
            # Create FIAT swallet for the user
            Wallet.objects.create(user=user, balance=0.00, currency='NGN')
            #  Generate JWT token pair
            refresh = RefreshToken.for_user(user=user)
            
            # referral code is simply the referrer's user_name
            if referral_code is not None:
                referrer = User.objects.get(user_name=referral_code)
                
                '''referrer_wallet = Wallet.objects.get(user=referrer)
                referrer_wallet.increment_coin()'''
                
                referrer.increment_referral_count(referral_code=referral_code)
            
            return Response({
                "refresh": str(refresh),  #remove token
                "access": str(refresh.access_token),
                "message": "User registered successfully"
            }, status=status.HTTP_201_CREATED)

        # Debugging block (optional)
        print("Registration failed with errors:", serializer.errors)

        return Response({
           "message": "Registration failed",
           "error": serializer.errors
           }, 
           status=status.HTTP_400_BAD_REQUEST
        )
    
    
    

class UserLoginView(generics.GenericAPIView):
    """View for user login"""
    permission_classes = [permissions.AllowAny]
    serializer_class = UserLoginSerializer
    

    def post(self, request: Request) -> Response:
        serializer = UserLoginSerializer(data=request.data, context={'request': request})
        print("Data:", request.data)
        if serializer.is_valid():
           user = serializer.validated_data   # ✅ use this, not self.get_object()
           refresh = RefreshToken.for_user(user)

           return Response({
               "refresh": str(refresh),
               "access": str(refresh.access_token),
               "message": "User logged in successfully"
           }, status=status.HTTP_200_OK)

        return Response(
           {
            "message": "Login failed",
            "error": serializer.errors,
        },
        status=status.HTTP_400_BAD_REQUEST,
        )



class UserLogoutView(generics.GenericAPIView):
    """View for user logout"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request: Request):
        """Handle user logout"""
        print("Data:", request.data)
        # Delete the token
        request.auth.delete()
        
        # Django session logout (if using session authentication)
        logout(request)
        
        return Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)
    
    
class ChangePasswordView(generics.GenericAPIView):
    """View for updating and setting new password"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request) -> Response:
        print("Data:", request.data)
        email: str = request.data.get("email")
        old_password: str = request.data.get('old_password')
        new_password: str = request.data.get('new_password')

        if not all([old_password, new_password]):
            return Response({'error': 'Email, old and new password are required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)

            if not user.check_password(old_password):  # ✅ use check_password
                return Response(
                    {"message": "Old password is invalid or incorrect"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user.set_password(new_password)  # ✅ hashes automatically
            user.save()
            return Response(
                {"message": "Password updated successfully"},
                status=status.HTTP_200_OK,
            )                    
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)




User = get_user_model()
class SoftDeleteUserView(generics.DestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

    def perform_destroy(self, instance):
        
        #user = self.get_object()
        # 1. Soft delete
        instance.is_deleted = True
        instance.deleted_at = timezone.now()
        instance.save()

        # 2. Invalidate all tokens (SimpleJWT-based)
        try:
            tokens = OutstandingToken.objects.filter(user=instance)  #instance
            for token in tokens:
                BlacklistedToken.objects.get_or_create(token=token)
        except:
            pass  # silently fail if not using token blacklisting

        # 3. Optionally, also log them out by deleting session
        if hasattr(instance, 'auth_token'):
            instance.auth_token.delete()

        # (Optional) 4. Send a Celery task or log a cron timestamp for hard-deletion
        #delete_user_in_5_days.delay(user_id=instance.id)
        # Schedule Celery task to run in 5 days 
        delete_user_in_5_days.apply_async((instance.id,), countdown=5*24*60*60)

    def delete(self, request: Request, *args, **kwargs):
        user = self.get_object()
        self.perform_destroy(instance=user)
        return Response({
            "message": "Account marked for deletion. Your data will be removed in 5 days."},
            status=status.HTTP_204_NO_CONTENT
        )



class PasswordResetView(generics.GenericAPIView):

    """View for sending OTP to user's email"""
    permission_classes = [permissions.AllowAny]
    

    def post(self, request: Request) -> Response:
        print("Data:", request.data)
        email = request.data.get('email')
        if not email:
            return Response({'message': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'message': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)

        # Generate a random 4-digit OTP
        otp = str(random.randint(1000, 9999))

        # Cache it with a timeout of 3 minutes (180  seconds)
        cache.set(f'password_reset_otp_{email}', otp, timeout=180)
        
        # Log the otp
        print(f"your otp is: {otp}")

        # Send OTP to user's email
        send_mail(
            subject='Your Password Reset OTP',
            message=f'Your OTP for password reset is: {otp}',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            
        )

        return Response({'message': 'OTP has been sent to your email'}, status=status.HTTP_200_OK)





class ConfirmPasswordView(generics.GenericAPIView):
    """View for verifying OTP and setting new password"""
    permission_classes = [permissions.AllowAny]

    def post(self, request: Request) -> Response:
        print("Data:", request.data)
        email = request.data.get('email')
        otp = request.data.get('otp')
        new_password = request.data.get('new_password')

        if not all([email, otp, new_password]):
            return Response({'message': 'Email, OTP, and new password are required'}, status=status.HTTP_400_BAD_REQUEST)

        cached_otp = cache.get(f'password_reset_otp_{email}')
        if not cached_otp:
            return Response({'message': 'OTP expired or not found'}, status=status.HTTP_400_BAD_REQUEST)

        if otp != cached_otp:
            return Response({'message': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        user.set_password(new_password)
        user.save()

        # Delete OTP after successful reset
        cache.delete(f'password_reset_otp_{email}')

        return Response({'message': 'Password reset successful. You can now log in with your new password.'}, status=status.HTTP_200_OK)
    


class  UserViewSet(viewsets.ModelViewSet):
    """
    An Authenticated ViewSet for managing users.
    Supports:
      - create user
      - update user
      - delete user
      - get all users (fetch/list)
      - retrieve user
      - delete all users at once (custom)
    """
    queryset = User.objects.all().order_by('-created_at')
    serializer_class = BasicUserSerializer

    # Optionally: Add custom permission
    permission_classes = [permissions.IsAuthenticated]
    #permission_classes = [permissions.AllowAny]
    #pagination_class = SmallResultsSetPagination  # 👈 use custom pagination here
    
    
    def handle_serializer_errors(self, serializer=None, success_message=None, success_status=status.HTTP_200_OK):
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(
                {"success": True, "message": success_message, "data": serializer.data},
                status=success_status
            )
        except ValidationError as exc:
            return Response(
                {"success": False, "error": "Validation failed", "message": exc.detail},
                status=status.HTTP_400_BAD_REQUEST
            )
            
    # You can override create() if you want a custom response (For Test Purpose -> Not Secure)
    def create(self, request: Request, *args, **kwargs):
        print("Data:", request.data)
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            return Response(
                {
                    "success": True,
                    "message": "User created successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_201_CREATED
            )
        except ValidationError as exc:
            return Response(
                {
                    "success": False,
                    "message": "User creation failed. Please fix the errors below.",
                    "errors": exc.detail,  # contains field-level validation errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )
            
            
    #  GET ALL USERS "Paginated Response" (ADMIN API)
    def list(self, request: Request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(
          {"success": True, "message": "Users retrieved successfully", "data": serializer.data},
          status=status.HTTP_200_OK
        )
    
    #  GET USER BY ID
    def retrieve(self, request: Request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(
          {"success": True, "message": "User retrieved successfully", "data": serializer.data},
          status=status.HTTP_200_OK
        )
    
    #  UPDATE USER BY ID
    def update(self, request: Request, *args, **kwargs):
        print("Data:", request.data)
        #fetches user object by id
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return self.handle_serializer_errors(serializer, success_message=f"{serializer.data}", success_status=status.HTTP_200_OK)
    
    #  DELETE USER BY ID
    def destroy(self, request: Request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(
            {"message": "User deleted successfully"},
            status=status.HTTP_204_NO_CONTENT
        )
        
    #  DELETE ALL USERS AT ONCE
    # Custom DELETE endpoint — delete all users
    @action(detail=False, methods=['delete'])
    def delete_all(self, request: Request):
        """Delete all users at once."""
        count = User.objects.count()
        User.objects.all().delete()
        return Response(
            {"message": f"Successfully deleted all ({count}) users."},
            status=status.HTTP_204_NO_CONTENT
        )
        

class BankDetailViewSet(viewsets.ModelViewSet):
    """
    An Authenticated ViewSet for managing bank details.
    Supports:
      - create bank detail
      - update bank detail
      - delete bank detail
      - get all bank details (fetch/list)
      - retrieve specific bank detail
      - delete all bank details at once (custom)
    """
    queryset = BankDetail.objects.all().order_by('-created_at')
    serializer_class = BankDetailSerializer

    # Optionally: Add custom permission
    permission_classes = [permissions.IsAuthenticated]
    #pagination_class = SmallResultsSetPagination  # 👈 use custom pagination here
    
    '''def handle_serializer_errors(self, serializer=None, success_message=None, success_status=status.HTTP_200_OK):
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(
                {"success": True, "message": success_message, "data": serializer.data},
                status=success_status
            )
        except ValidationError as exc:
            return Response(
                {"success": False, "error": "Validation failed", "message": exc.detail},
                status=status.HTTP_400_BAD_REQUEST
            )'''
            
    def perform_create(self, serializer):
        # Automatically attach the current logged-in user
        serializer.save(user=self.request.user)
            
            
    # You can override create() if you want a custom response
    def create(self, request: Request, *args, **kwargs):
        print("Data:", request.data)

        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            #inject the user field in the serializer
            #serializer.save(user=self.request.user)
            self.perform_create(serializer)
            return Response(
                {
                    "success": True,
                    "message": "Bank detail created successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_201_CREATED
            )
        except ValidationError as exc:
            return Response(
                {
                    "success": False,
                    "message": "Bank detail creation failed. Please fix the errors below.",
                    "errors": exc.detail,  # contains field-level validation errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )
            
    #  GET USER BANKS
    @action(detail=False, methods=['get'])
    def user_banks(self, request: Request, *args, **kwargs):
        #get the user from the request
        user = request.user
        #fetch the queryset
        banks = BankDetail.objects.filter(
            user=user,
        )
        #serialize the queryset
        serializer = self.get_serializer(banks, many=True)
        return Response(
            {
                "success": True,
                "message": "Logged-in user banks retrieved successfully",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK
        )
          
            
            
    #  GET ALL BANKS "Paginated Response" (ADMIN API)
    def list(self, request: Request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(
          {"success": True, "message": "Banks retrieved successfully", "data": serializer.data},
          status=status.HTTP_200_OK
        )
    
    #  GET BANK BY ID
    def retrieve(self, request: Request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(
          {"success": True, "message": "Bank retrieved successfully", "data": serializer.data},
          status=status.HTTP_200_OK
        )

          
    #  Update BANK BY ID
    def update(self, request: Request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(
          {"success": True, "message": "Bank updated successfully", "data": serializer.data},
          status=status.HTTP_200_OK
        )
            
    #  DELETE BANK BY ID
    def destroy(self, request: Request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(
            {"message": "Bank deleted successfully"},
            status=status.HTTP_204_NO_CONTENT
        )
        
    #  DELETE ALL BABNKS AT ONCE
    @action(detail=False, methods=['delete'])
    def delete_all(self, request: Request):
        """Delete all users at once."""
        count = BankDetail.objects.count()
        BankDetail.objects.all().delete()
        return Response(
            {"message": f"Successfully deleted all ({count}) banks."},
            status=status.HTTP_204_NO_CONTENT
        )
        
    def get_view_name(self):
        # This helps debug what view is being called
        print(f"Action: {self.action}")
        print(f"Allowed methods: {self.allowed_methods}")
        return super().get_view_name()
        
        
        
        
class UpdateKycView(generics.UpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = KycUpdateSerializer
    parser_classes = [MultiPartParser, FormParser]  # For file uploads
    
    def get_object(self):
        return self.request.user
    
    def put(self, request: Request, *args, **kwargs) -> Response:
        print("Data:", request.data)
        
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            # CREATE NOTIFICATION OBJECT FOR USER AFTER SUCCESSFUL KYC UPDATE RESPONSE
            Notification.objects.create(
                user=self.request.user,
                title=f"KYC Documents Submitted Successfully",
                content=f"verification has commenced and you will be updated in due time.",
                type="normal"  #alert, normal, promotion
            )
            # SEND NOTIFICATION EMAIL TO USER
            self.request.user.send_mail(
                subject='KYC Documents Submitted Successfully',
                message=f'Hi {self.request.user.first_name},\nverification has commenced and you will be updated in due time',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[self.request.user.email],
            )
            return Response(
                {
                    "success": True,
                    "message": "KYC document updated successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_201_CREATED
            )
        except ValidationError as exc:
            return Response(
                {
                    "success": False,
                    "message": "KYC document update failed. Please fix the errors below.",
                    "errors": exc.detail,  # contains field-level validation errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )
    
    
#TRANSACTION LIST VIEW (USER)
class TransactionListView(generics.ListAPIView):
    """View for listing transactions"""
    serializer_class = TransactionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get transactions for the current user"""
        user_transactions_queryset = Transaction.objects.filter(user=self.request.user).order_by('-created_at')
        serializer = self.get_serializer(user_transactions_queryset, many=True)
        if not user_transactions_queryset:
            return Response({"success": False, "message": serializer.data}, status=status.HTTP_200_OK)
        return Response({"success": True, "message": serializer.data}, status=status.HTTP_200_OK)
            

    
    def get(self, request: Request, *args, **kwargs) -> Response:
        """Get one transaction object by id for the current user"""
        try:
            print("Data:", request.data)
            transaction_id: str = kwargs.get("id")  # assuming it's passed in the URL as /transactions/<id>/
            transaction = Transaction.objects.get(id=transaction_id, user=request.user)
            return transaction
        except Transaction.DoesNotExist:
            return Response({"message": "Transaction not found"}, status=status.HTTP_404_NOT_FOUND)
        

    
class FiatWalletViewSet(viewsets.ModelViewSet):
    """
    An Authenticated ViewSet for managing Fiat wallets.
    Supports:
      - create Fiat wallet
      - update Fiat wallet
      - delete Fiat wallet
      - get all Fiat wallets (fetch/list)
      - retrieve specific Fiat wallet
      - delete all Fiat wallet at once (custom)
    """
    queryset = Wallet.objects.all().order_by('-created_at')
    serializer_class = WalletSerializer

    # Optionally: Add custom permission
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = SmallResultsSetPagination  # 👈 use custom pagination here
    
    def handle_serializer_errors(self, serializer=None, success_message=None, success_status=status.HTTP_200_OK):
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(
                {"success": True, "message": success_message, "data": serializer.data},
                status=success_status
            )
        except ValidationError as exc:
            return Response(
                {"success": False, "error": "Validation failed", "message": exc.detail},
                status=status.HTTP_400_BAD_REQUEST
            )
            
    
    # You can override create() if you want a custom response
    def create(self, request: Request, *args, **kwargs):
        print("Data:", request.data)
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            #inject the user field in the serializer
            serializer.save(user=self.request.user)
            self.perform_create(serializer)
            return Response(
                {
                    "success": True,
                    "message": "Wallet created successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_201_CREATED
            )
        except ValidationError as exc:
            return Response(
                {
                    "success": False,
                    "message": "Wallet creation failed. Please fix the errors below.",
                    "errors": exc.detail,  # contains field-level validation errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )
            
            
    #  GET ALL WALLETS "Paginated Response" (ADMIN API)
    def list(self, request: Request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(
          {"success": True, "message": "Wallets retrieved successfully", "data": serializer.data},
          status=status.HTTP_200_OK
        )
    
    #  GET WALLET BY ID
    def retrieve(self, request: Request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(
          {"success": True, "message": "User fiat wallet retrieved successfully", "data": serializer.data},
          status=status.HTTP_200_OK
        )
        
    #  GET WALLET BY user
    @action(detail=False, methods=['get'])
    def get_user_wallet(self, request: Request, *args, **kwargs):
        user = request.user
        if not user:
            return Response(
                {"success": False, "message": "This user doesn't exist"},
                status=status.HTTP_404_NOT_FOUND
            )
            
        # get one object or None
        user_wallet = Wallet.objects.filter(
            user=request.user,
        ).first() 

        if not user_wallet:
            return Response({"message": "No wallet found for this user"}, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(user_wallet)
        return Response(
            {"success": True, "message": "User fiat wallet retrieved successfully", "data": serializer.data},
            status=status.HTTP_200_OK
        )
            
    #  DELETE WALLET BY ID (ADMIN & USER)
    def destroy(self, request: Request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(
            {"message": "User fiat wallet deleted successfully"},
            status=status.HTTP_204_NO_CONTENT
        )
        
    #  DELETE ALL BABNKS AT ONCE (ADMIN)
    @action(detail=False, methods=['delete'])
    def delete_all(self, request: Request):
        """Delete all wallet rows at once."""
        count = Wallet.objects.count()
        Wallet.objects.all().delete()
        return Response(
            {"message": f"Successfully deleted all ({count}) fiat wallets."},
            status=status.HTTP_204_NO_CONTENT
        )
            
            
            

class CryptoWalletViewSet(viewsets.ModelViewSet):
    """
    An Authenticated ViewSet for managing Crypto wallets.
    Supports:
      - create Crypto wallet
      - update Crypto wallet
      - delete Crypto wallet
      - get all Crypto wallets (fetch/list)
      - retrieve specific Crypto wallet
      - delete all Crypto wallet at once (custom)
    """
    queryset = CryptoWallet.objects.all().order_by('-created_at')
    serializer_class = CryptoWalletSerializer

    # Optionally: Add custom permission
    permission_classes = [permissions.IsAuthenticated]
    #pagination_class = SmallResultsSetPagination  # 👈 use custom pagination here
    
    
    def perform_create(self, serializer):
        # Automatically attach the current logged-in user
        serializer.save(user=self.request.user)
    
    def handle_serializer_errors(self, *, serializer=None, success_message=None, success_status=status.HTTP_200_OK):
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(
                {"success": True, "message": success_message, "data": serializer.data},
                status=success_status
            )
        except ValidationError as exc:
            return Response(
                {"success": False, "error": "Validation failed", "message": exc.detail},
                status=status.HTTP_400_BAD_REQUEST
            )
            
    
    # You can override create() if you want a custom response
    def create(self, request: Request, *args, **kwargs):
        print("Data:", request.data)
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            #inject the user field in the serializer
            serializer.save(user=self.request.user)
            self.perform_create(serializer)
            return Response(
                {
                    "success": True,
                    "message": "Crypto wallet created successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_201_CREATED
            )
        except ValidationError as exc:
            return Response(
                {
                    "success": False,
                    "message": "Crypto wallet creation failed. Please fix the errors below.",
                    "errors": exc.detail,  # contains field-level validation errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )
            
            
            
            
    #  UPDATE CRYPTO WALLET BY USER Auth RATHER THAN ID
    @action(detail=False, methods=['patch'])
    def update_crypto_wallet(self, request: Request, *args, **kwargs):
        print("Data:", request.data)
        crypto_type = request.data.get("type")
        if not crypto_type:
            return Response(
                {"success": False, "message": "Crypto type is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        #self.get_object() <- it fetches by id
        instance = CryptoWallet.objects.filter(
            user=self.request.user,
            type=crypto_type
        )    
        #patch request
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return self.handle_serializer_errors(serializer, success_message=f"{serializer.data}", success_status=status.HTTP_200_OK)
            
            
    #  GET ALL WALLETS "Paginated Response" (ADMIN API)
    def list(self, request: Request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(
          {"success": True, "message": "Crypto wallets retrieved successfully", "data": serializer.data},
          status=status.HTTP_200_OK
        )
    
    #  GET WALLET BY type rather than id
    @action(detail=False, methods=['get'])
    def get_crypto_wallet(self, request: Request, *args, **kwargs):
        wallet_type = request.query_params.get("type")
        if not wallet_type:
            return Response(
                {"success": False, "message": "Wallet type is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # get one object or None
        wallet = CryptoWallet.objects.filter(
            user=request.user,
            type=wallet_type
        ).first() 

        if not wallet:
            return Response({"message": "No wallet found for this type."}, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(wallet)
        return Response(
            {"success": True, "message": "User crypto wallet retrieved successfully", "data": serializer.data},
            status=status.HTTP_200_OK
        )
            
    #  DELETE WALLET BY ID (ADMIN & USER)
    def destroy(self, request: Request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(
            {"message": "User crypto wallet deleted successfully"},
            status=status.HTTP_204_NO_CONTENT
        )
        
    #  DELETE ALL WALLETS AT ONCE (ADMIN)
    @action(detail=False, methods=['delete'])
    def delete_all(self, request: Request):
        """Delete all wallet rows at once."""
        count = CryptoWallet.objects.count()
        CryptoWallet.objects.all().delete()
        return Response(
            {"message": f"Successfully deleted all ({count}) crypto wallets in database."},
            status=status.HTTP_204_NO_CONTENT
        )
            
   
class FetchCommercialBanksView(generics.GenericAPIView):
    """View for fetching commercial banks from Paystack API"""
    permission_classes = [permissions.IsAuthenticated]

    def fetch_banks(self) -> Response:
        """FETCH LIST OF BANKS FROM PAYSTACK API"""
        url = "https://api.paystack.co/bank"
        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_TEST_SECRET_KEY}",
            "Content-Type": "application/json"
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            print("JSON DATA", data)
            return Response(data=data["data"], status=status.HTTP_200_OK)
        else:
            # ✅ Fix: `data` is only defined if 200, so use response.json() here
            data = response.json()
            print("JSON DATA", data)
            return Response({"message": f"Paystack error: {data.get('message')}"}, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request: Request) -> Response:
        print("User data", request.data)
        user = request.user
        if not user or not user.is_authenticated:
           return Response({"message": "User does not exist"}, status=status.HTTP_404_NOT_FOUND)
        # ✅ Fix: RETURN the result of fetch_banks
        return self.fetch_banks()
    
    
class ResolveAccountView(generics.GenericAPIView):
    """View for resolving a user's account details via Paystack API"""
    permission_classes = [permissions.IsAuthenticated]
    

    def resolve_account(self, account_number: str, bank_code: str) -> Response:
        """RESOLVE USER BANK ACCOUNT DETAILS VIA PAYSTACK API"""
        url = f"https://api.paystack.co/bank/resolve?account_number={account_number}&bank_code={bank_code}"
        headers = {
           "Authorization": f"Bearer {settings.PAYSTACK_TEST_SECRET_KEY}",
           "Content-Type": "application/json"
        }
        response = requests.get(url,headers=headers)
        if response.status_code == 200:
            data = response.json()
            print("JSON DATA", data)
            return Response(data=data["data"], status=status.HTTP_200_OK)
        else:
           data = response.json()
           print("JSON DATA", data)
           return Response({"error": f"Paystack error: {data.get('message')}"}, status=status.HTTP_400_BAD_REQUEST)
       
    def get(self, request: Request, *args, **kwargs) -> Response:
        print("User data", request.data)
        user = request.user
        account_number: str = kwargs.get("account_number")  # assuming it's passed in the URL as /xxx/<id>/
        bank_code: str = kwargs.get("bank_code")
        if not user or not user.is_authenticated:
           return Response({"error": "User does not exist"}, status=status.HTTP_404_NOT_FOUND)
        return self.resolve_account(account_number=account_number, bank_code=bank_code)
    
    

class TransferPinView(generics.GenericAPIView):
    """View for setting/updating transfer pin"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request: Request) -> Response:
        """Set or update transfer pin"""
        serializer = TransferPinSerializer(data=request.data, context={'request': request})
        print("Data:", request.data)
        if serializer.is_valid():
            user = request.user
            new_pin = serializer.validated_data.get('new_pin')
             
            # Update the transfer pin
            user.transfer_pin = new_pin
            user.save()
            
            return Response({'message': 'Transfer pin updated successfully'}, status=status.HTTP_200_OK)
        
        return Response({'message': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)




class PanicPinView(generics.GenericAPIView):
    """View for setting/updating panic pin"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request: Request) -> Response:
        """Set or update panic pin"""
        serializer = PanicPinSerializer(data=request.data, context={'request': request})
        print("Data:", request.data)
        if serializer.is_valid():
            user = request.user
            new_pin = serializer.validated_data.get('new_pin')
            
            # Update the panic pin
            user.panic_transfer_pin = new_pin
            user.save()
            
            return Response({'message': 'Panic pin updated successfully'}, status=status.HTTP_200_OK)
        
        return Response({'message': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)




#FETCH AND CREATE TRANSFER RECIPIENT VIEW
class RecipientView(generics.GenericAPIView):
    serializer_class = RecipientCodeSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = RecipientCodeSerializer(data=request.data, context={'request': request},)  #self.get_serializer(data=request.data, context={"request": request}) 
        print("Data:", request.data)
        serializer.is_valid(raise_exception=True)
        bank_code = serializer.validated_data.get('bank_code')
        account_name = serializer.validated_data.get('account_name', '')
        account_number = serializer.validated_data.get('account_number', "")
        #GET USER WALLET THEN CALL THE WALLET TRANSFER METHOD
        wallet = Wallet.objects.get(user=request.user)
        wallet.fetch_transfer_recipient(
            bank_code=bank_code,
            account_name=account_name, 
            account_number=account_number, 
        )
        result = serializer.save()
        return Response(result, status=status.HTTP_201_CREATED)



#DEPOSIT TO WALLET VIEW
class DepositView(generics.GenericAPIView):
    """View for depositing funds into wallet"""
    serializer_class = DepositSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request: Request) -> Response:
        """Handle deposit request"""
        serializer = DepositSerializer(data=request.data)
        print("Data:", request.data)
        
        if serializer.is_valid():
            user = request.user
            amount = serializer.validated_data.get('amount')
            reason = serializer.validated_data.get('reason', '')
            
            # Get the user's wallet
            wallet = Wallet.objects.get(user=request.user)
    
            #date time of the trx
            trx_ref = f"PIKA-{timedelta.microseconds}-{random.randint(1000, 9999)}"

            # Create a transaction record  for sender  
            transaction =  Transaction.objects.create(
                user=request.user,
                transaction_reference=trx_ref,
                transaction_type="DEPOSIT",
                amount=amount,
                #currency="NGN",
                status="COMPLETED",
                reason=reason,
                crypto_name="",
                crypto_wallet_address="",
                recipient=request.user,
            )
            
            # Deposit the amount
            wallet.deposit(amount)
            
            # Return the updated wallet and transaction info (More like JSON.Decode())
            wallet_serializer = WalletSerializer(wallet)
            transaction_serializer = TransactionSerializer(transaction)
            
            #CREATE NOTIFICATION AFTER SUCCESSFUL DEPOSIT
            Notification.objects.create(
              user=user,
              title=f"Transaction Succesful",
              content=f"NGN {amount} has been deposited into your wallet.",
              type="normal"  #alert, normal, promotion
            )
            
            # Send email to the user (configure google smtp password to activate)
            subject = "Transaction Notification"
            request.user.email_user(
                subject=subject,
                message=f"You've successfully deposited ₦{amount} in your wallet.",
                from_email='support@pika.com',
                to_email=user.email
            )
            
            return Response({
                'wallet': wallet_serializer.data,
                'transaction': transaction_serializer.data,
                'message': 'Deposit successful'
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



#WALLET TRANSFER VIEW
class TransferView(generics.GenericAPIView):
    serializer_class = TransferSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, *args, **kwargs) -> Response:
        user = request.user
        print("Data:", request.data)
        serializer = TransferSerializer(data=request.data, context={'request': request}) #self.get_serializer(data=request.data, context={"request": request}) 
        serializer.is_valid(raise_exception=True)
        
        recipient_id=serializer.validated_data.get('recipient_id', '')
        amount = serializer.validated_data.get('amount')
        transfer_pin = serializer.validated_data.get('transfer_pin')
        reason = serializer.validated_data.get('reason', '')
        
        #GET USER WALLET THEN CALL THE WALLET TRANSFER METHOD
        wallet = Wallet.objects.get(user=request.user)
        wallet.transfer(
            recipient_user_id=recipient_id,
            amount=amount, 
            transfer_pin=int(transfer_pin), 
            reason=reason
        )
        result = serializer.save()
        #CREATE NOTIFICATION AFTER SUCCESSFUL TRANSFER
        Notification.objects.create(
            user=user,
            title=f"Transaction Succesful",
            content=f"NGN {amount} has been deducted from your wallet.",
            type="normal"  #alert, normal, promotion
        )
        return Response(result, status=status.HTTP_201_CREATED)



#BANK TRANSFER VIEW
class BankTransferView(generics.GenericAPIView):
    serializer_class = BankTransferSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, *args, **kwargs) -> Response:
        user = request.user
        print("Data:", request.data)
        data = request.data #{**request.data, 'transaction_type': 'COMPLETED'}  # 👈 auto inject
        serializer = self.get_serializer(data=data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        amount = serializer.validated_data.get('amount')
        recipient_code = serializer.validated_data.get('recipient_code')
        transfer_pin = serializer.validated_data.get('transfer_pin')
        reason = serializer.validated_data.get('reason')
        
        #GET USER WALLET THEN CALL THE BANK TRANSFER METHOD
        wallet = Wallet.objects.get(user=request.user)
        wallet.bank_transfer(amount=amount, recipient_code=recipient_code, transfer_pin=int(transfer_pin), reason=reason)

        result = serializer.save()

        Notification.objects.create(
            user=user,
            title="Transaction Successful",
            content=f"NGN {amount} has been deducted from your wallet.",
            type="normal"
        )

        return Response(result, status=status.HTTP_201_CREATED)




class ReportTransactionView(generics.GenericAPIView):
    """View for reporting a transaction"""
    serializer_class = ReportTransactionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request: Request,*args, **kwargs) -> Response:
        """Handle transaction report"""
        print("Data:", request.data)
        #transaction = get_object_or_404(Transaction, transaction_id=, user=request.user)
        #transaction = Transaction.objects.get(user=request.user, id=kwargs.get("id"))
        
        user = request.user
        serializer = self.get_serializer(data=request.data)
        
        if serializer.is_valid():
            user = request.user
            reason = serializer.validated_data['reason']
            
            
            transaction = get_object_or_404(
                Transaction, 
                user=user, 
                id=kwargs.get("id")
            )
            # Freeze the transaction
            transaction.freeze(reason)
            
            
            
            #CREATE NOTIFICATION AFTER SUCCESSFUL TRANASACTION REPORT
            Notification.objects.create(
                user=user,
                title=f"Transaction Reported",
                content=f"Hi {user.first_name}, \nwe have marked the transaction with the corresponding ID - '{transaction_id}' for immediate investigation.\nA follow-up email will be sent to you soon.",
                type="alert"  #alert, normal, promotion
            )
            
            # SEND MAIL TO THE USER
            user.email_user(
                subject="Transaction Reported!",
                message=f"Hi {user.first_name}, \nwe have marked the transaction with the corresponding ID - '{transaction_id}' for immediate investigation and a follow up email will be sent to you.",
                from_email='support@pika.com',
                to_email=user.email
            )
            
            return Response({
                'message': 'Transaction reported and frozen',
                'transaction': TransactionSerializer(transaction).data
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



# GENERIC SEND MAIL
class SendEmailView(generics.GenericAPIView):
    """View for sending emails to users"""
    permission_classes = [permissions.AllowAny]
    
    #to get user object if authenticated
    def get_object(self):
        return self.request.user
    
    def post(self, request: Request,) -> Response:
        """Send email to a user"""
        
        serializer = EmailSerializer(data=request.data)
        print("Data:", request.data)
        
        if serializer.is_valid(raise_exception=True):
            from_email = serializer.validated_data['from_email']
            to_email = serializer.validated_data['to_email']
            subject = serializer.validated_data['subject']
            message = serializer.validated_data['message']
            
            # Send the email
            send_mail(subject=subject, message=message, from_email=from_email, recipient_list=[to_email])
            
            return Response({'message': f'Email sent successfully to {to_email}'}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
    
#GET POST
class NotificationListCreateView(generics.ListCreateAPIView):
    """View for listing and creating notifications"""
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get all notification objects belonging to the current user"""
        return Notification.objects.filter(user=self.request.user)
    
    #DRF handles all these internally though
    def perform_create(self, serializer):
        """Create a new notification object for the current user"""
        serializer.save(user=self.request.user)


#UPDATE DELETE
class NotificationUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    """View for retrieving, updating and deleting notification details"""
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get all notification objects belonging to the current user"""
        return Notification.objects.filter(user=self.request.user)
    
    #DRF handles all these internally though
    def perform_update(self, serializer):
        serializer.save()
    
    #DRF handles all these internally though
    def perform_destroy(self, instance):
        instance.delete()
        
        

# 🔹 Admin: List all messages (optional)
class AllMessagesView(generics.ListAPIView):
    serializer_class = MessageSerializer
    #permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Message.objects.all().order_by("-created_at")
    
    

class GadgetOrderViewSet(viewsets.ModelViewSet):
    """
    An Authenticated ViewSet for managing Gadget Orders.
    Supports:
      - create gadget order
      - retrieve user gadget orders
      - update gadget order (essential to update order status - Admin)
      - delete gadget order (essential to delete order - Admin)
      - get all gadget orders (fetch/list - Admin)
      - retrieve a specific gadget order by id (if needed - Admin)
      - delete all gadget orders form database at once (custom - Admin)
    """
    queryset = GadgetOrder.objects.all().order_by('-created_at')
    serializer_class = GadgetOrderSerializer

    # Optionally: Add custom permission
    permission_classes = [permissions.IsAuthenticated]
    #pagination_class = SmallResultsSetPagination  # 👈 use custom pagination here
    
    
    def perform_create(self, serializer):
        # Automatically attach the current logged-in user
        serializer.save(user=self.request.user)
    
    def handle_serializer_errors(self, serializer=None, success_message=None, success_status=status.HTTP_200_OK):
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(
                {"success": True, "message": success_message, "data": serializer.data},
                status=success_status
            )
        except ValidationError as exc:
            return Response(
                {"success": False, "error": "Validation failed", "message": exc.detail},
                status=status.HTTP_400_BAD_REQUEST
            )
            
    
    # You can override create() if you want a custom response
    def create(self, request: Request, *args, **kwargs):
        print("Data:", request.data)
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            #inject the user field in the serializer
            #serializer.save(user=self.request.user)
            self.perform_create(serializer)
            return Response(
                {
                    "success": True,
                    "message": "Gadget order created successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_201_CREATED
            )
        except ValidationError as exc:
            return Response(
                {
                    "success": False,
                    "message": "Gadget order creation failed. Please fix the errors below.",
                    "errors": exc.detail,  # contains field-level validation errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )
            
    #  GET USER GADGET ORDERS
    @action(detail=False, methods=['get'])
    def user_gadget_orders(self, request: Request, *args, **kwargs):
        #get the user from the request
        user = request.user
        #fetch the queryset
        gadget_orders = GadgetOrder.objects.filter(
            user=user,
        )
        #serialize the queryset
        serializer = self.get_serializer(gadget_orders, many=True)
        return Response(
            {
                "success": True,
                "message": "User gadget orders retrieved successfully",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK
        )
            
    #  UPDATE Gadget order BY ID (ADMIN API) (PATCH REQUEST)
    def update(self, request: Request, *args, **kwargs):
        print("Data:", request.data)
        #self.get_object() <- it fetches by id
        instance = self.get_object() 
        #patch request
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return self.handle_serializer_errors(serializer, success_message=f"{serializer.data}", success_status=status.HTTP_200_OK)
            
            
    #  GET ALL Gadget orders in the system "Paginated Response" (ADMIN API)
    def list(self, request: Request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(
          {"success": True, "message": "Gadget orders retrieved successfully", "data": serializer.data},
          status=status.HTTP_200_OK
        )
    
            
    #  DELETE GADGET ORDER BY ID (ADMIN & USER)
    def destroy(self, request: Request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(
            {"message": "User gadget order deleted successfully"},
            status=status.HTTP_204_NO_CONTENT
        )
        
    #  DELETE ALL GADGET ORDERS AT ONCE (ADMIN APIs)
    @action(detail=False, methods=['delete'])
    def delete_all(self, request: Request):
        """Delete all gadget order rows at once."""
        count = GadgetOrder.objects.count()
        GadgetOrder.objects.all().delete()
        return Response(
            {"message": f"Successfully deleted all ({count}) gadget orders in database."},
            status=status.HTTP_204_NO_CONTENT
        )
        
        
class CartOrderViewSet(viewsets.ModelViewSet):
    """
    An Authenticated ViewSet for managing Cart Items.
    Supports:
      - create cart item
      - retrieve user cart items
      - delete cart item
      - delete all cart items form database at once (custom - Admin)
    """
    
    queryset = CartOrder.objects.all().order_by('-created_at')
    serializer_class = CartOrderSerializer

    # Optionally: Add custom permission
    permission_classes = [permissions.IsAuthenticated]
    #pagination_class = SmallResultsSetPagination  # 👈 use custom pagination here
    
    
    def perform_create(self, serializer):
        # Automatically attach the current logged-in user
        serializer.save(user=self.request.user)
    
    def handle_serializer_errors(self, serializer=None, success_message=None, success_status=status.HTTP_200_OK):
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(
                {"success": True, "message": success_message, "data": serializer.data},
                status=success_status
            )
        except ValidationError as exc:
            return Response(
                {"success": False, "error": "Validation failed", "message": exc.detail},
                status=status.HTTP_400_BAD_REQUEST
            )
            
    def create(self, request: Request, *args, **kwargs):
        print("Data:", request.data)
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            #inject the user field in the serializer
            #serializer.save(user=self.request.user)
            self.perform_create(serializer)
            return Response(
                {
                    "success": True,
                    "message": "Cart item created successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_201_CREATED
            )
        except ValidationError as exc:
            return Response(
                {
                    "success": False,
                    "message": "Cart item creation failed. Please fix the errors below.",
                    "errors": exc.detail,  # contains field-level validation errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )
            
    #  GET USER CART ITEMS (ARRAY)
    @action(detail=False, methods=['get'])
    def user_cart_list(self, request: Request, *args, **kwargs):
        #get the user from the request
        user = request.user
        #fetch the queryset
        cart_items = CartOrder.objects.filter(
            user=user,
        )
        #serialize the queryset
        serializer = self.get_serializer(cart_items, many=True)
        return Response(
            {
                "success": True,
                "message": "User cart items retrieved successfully",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK
        )
        
    #  DELETE CART ITEM BY ID (ADMIN & USER)
    def destroy(self, request: Request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(
            {"message": "User cart item deleted successfully"},
            status=status.HTTP_204_NO_CONTENT
        )
        
    #  DELETE ALL CART ITEMS AT ONCE (ADMIN APIs)
    @action(detail=False, methods=['delete'])
    def delete_all(self, request: Request):
        """Delete all cart item rows at once."""
        count = CartOrder.objects.count()
        CartOrder.objects.all().delete()
        return Response(
            {"message": f"Successfully deleted all ({count}) cart items in database."},
            status=status.HTTP_204_NO_CONTENT
        )
            






class ShipmentOrderViewSet(viewsets.ModelViewSet):
    """
    An Authenticated ViewSet for managing Shipment Ordeer
    Supports:
      - create shipment order
      - retrieve user shipment oder
      - delete shipment orde (Admin Control)
      - delete all shipment orders from database at once (custom - Admin)
    """
    
    queryset = ShipmentOrder.objects.all().order_by('-created_at')
    serializer_class = ShipmentOrderSerializer

    # Optionally: Add custom permission
    permission_classes = [permissions.IsAuthenticated]
    #pagination_class = SmallResultsSetPagination  # 👈 use custom pagination here
    
    
    def perform_create(self, serializer):
        # Automatically attach the current logged-in user
        serializer.save(user=self.request.user)
    
    def handle_serializer_errors(self, serializer=None, success_message=None, success_status=status.HTTP_200_OK):
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(
                {"success": True, "message": success_message, "data": serializer.data},
                status=success_status
            )
        except ValidationError as exc:
            return Response(
                {"success": False, "error": "Validation failed", "message": exc.detail},
                status=status.HTTP_400_BAD_REQUEST
            )
            
    def create(self, request: Request, *args, **kwargs):
        print("Data:", request.data)
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            #inject the user field in the serializer
            #serializer.save(user=self.request.user)
            self.perform_create(serializer)
            return Response(
                {
                    "success": True,
                    "message": "Shipment order created successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_201_CREATED
            )
        except ValidationError as exc:
            return Response(
                {
                    "success": False,
                    "message": "Shipment creation failed. Please fix the errors below.",
                    "errors": exc.detail,  # contains field-level validation errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )
            
    #  GET USER SHIPMENT ORDERS (ARRAY)
    @action(detail=False, methods=['get'])
    def user_shipments(self, request: Request, *args, **kwargs):
        #get the user from the request
        user = request.user
        #fetch the queryset
        cart_items = ShipmentOrder.objects.filter(
            user=user,
        )
        #serialize the queryset
        serializer = self.get_serializer(cart_items, many=True)
        return Response(
            {
                "success": True,
                "message": "User shipments retrieved successfully",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK
        )
        
    #  DELETE SHIPMENTS BY ID (ADMIN & USER)
    def destroy(self, request: Request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(
            {"message": "User shipment deleted successfully"},
            status=status.HTTP_204_NO_CONTENT
        )
        
    #  DELETE ALL SHIPMENTS AT ONCE (ADMIN APIs)
    @action(detail=False, methods=['delete'])
    def delete_all(self, request: Request):
        """Delete all cart item rows at once."""
        count = CartOrder.objects.count()
        CartOrder.objects.all().delete()
        return Response(
            {"message": f"Successfully deleted all ({count}) cart items in database."},
            status=status.HTTP_204_NO_CONTENT
        )
        
        
    #  GETALL SHIPMENTS AT ONCE (ADMIN APIs)
    @action(detail=False, methods=['get'])
    def get_all_shipments(self, request: Request):
        """Get all shipment rows at once."""
        count = ShipmentOrder.objects.count()
        shipments = ShipmentOrder.objects.all()
        return Response(
            {"message": f"Successfully fetched all ({count}) shipments in database."},
            status=status.HTTP_204_NO_CONTENT
        )
            
            

########VIEW SETS#######
class ProductViewSet(viewsets.ModelViewSet):
    """
    A ViewSet for managing products.
    Supports:
      - create
      - update
      - delete
      - list
      - retrieve
      - delete all products (custom)
    """
    queryset = Product.objects.all().order_by('-created_at')
    serializer_class = ProductSerializer

    # Optionally: Add custom permission (only admin can manage)
    permission_classes = [permissions.AllowAny]
    #pagination_class = SmallResultsSetPagination  custom pagination
    
    
    def handle_serializer_errors(self, serializer=None, success_message=None, success_status=status.HTTP_200_OK):
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(
                {"success": True, "message": success_message, "data": serializer.data},
                status=success_status
            )
        except ValidationError as exc:
            return Response(
                {"success": False, "error": "Validation failed", "message": exc.detail},
                status=status.HTTP_400_BAD_REQUEST
            )

    
    
    #  GET ALL PRODUCTS
    def list(self, request: Request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(
          {"success": True, "message": "Products retrieved successfully", "data": serializer.data},
          status=status.HTTP_200_OK
        )
    
    
    #  Retrieve Particular Product BY ID
    def retrieve(self, request: Request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(
          {"success": True, "message": "Specific Product retrieved successfully", "data": serializer.data},
          status=status.HTTP_200_OK
        )
        
    
    #  Retrieve Products BY type "sweet-deals" rather than ID
    @action(detail=False, methods=['get'])
    def retrieve_product_by_type(self, request: Request, *args, **kwargs):
        is_sweet_deal_param = request.query_params.get("is_sweet_deal")

        # Convert string to boolean safely
        if is_sweet_deal_param is not None:
            is_sweet_deal = is_sweet_deal_param.lower() == "true"
            products = Product.objects.filter(is_sweet_deal=is_sweet_deal)
        else:
            products = Product.objects.all()

        serializer = self.get_serializer(products, many=True)

        return Response(
            {"success": True, "message": "Products retrieved successfully", "data": serializer.data},
            status=status.HTTP_200_OK
        )


    #  Retrieve Products BY type = phone, tablet, laptop
    @action(detail=False, methods=['get'])
    def get_product_by_type(self, request: Request, *args, **kwargs):
        type: str = request.query_params.get("type")

        # Convert string to boolean safely
        if type is not None:
            products = Product.objects.filter(type=type)
        else:
            products = Product.objects.all()

        serializer = self.get_serializer(products, many=True)

        return Response(
            {"success": True, "message": f"Products with type {type} retrieved successfully", "data": serializer.data},
            status=status.HTTP_200_OK
        )



    # Custom DELETE endpoint — delete all products
    @action(detail=False, methods=['delete'])
    def delete_all(self, request: Request):
        """Delete all products at once."""
        count = Product.objects.count()
        Product.objects.all().delete()
        return Response(
            {"message": f"Successfully deleted all ({count}) products."},
            status=status.HTTP_204_NO_CONTENT
        )
    

    # You can override create() if you want a custom response
    def create(self, request: Request, *args, **kwargs):
        print("Data:", request.data)
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            return Response(
                {
                    "success": True,
                    "message": "Product created successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_201_CREATED
            )
        except ValidationError as exc:
            return Response(
                {
                    "success": False,
                    "message": "Product creation failed. Please fix the errors below.",
                    "errors": exc.detail,  # contains field-level validation errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )
            
    @action(detail=True, methods=['patch'])
    def update_product(self, request, *args, **kwargs):
        instance = self.get_object()  # now works fine
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(
            {"message": "Product updated successfully", "data": serializer.data},
            status=status.HTTP_200_OK
        )


    #  You can override destroy() for a clean delete response
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(
            {"message": "Product deleted successfully"},
            status=status.HTTP_204_NO_CONTENT
        )
        
        



class GiftCardProcessorView(generics.GenericAPIView):
    
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request: Request) -> Response:
        
        serializer = RedeemGiftCardSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        code = serializer.validated_data.get("code")
        amount = serializer.validated_data.get("amount")
        currency = serializer.validated_data.get("currency")
        brand = serializer.validated_data.get("brand")
        card_type = serializer.validated_data.get("card_type")
        country = serializer.validated_data.get("country")
        upload_image = serializer.validated_data.get("upload_image")
        #client should pass it
        callback_url = request.data.get("callback_url")
        
        # assumes authentication
        user = request.user 
        
        # Atomically handle gift card redemption to prevent race conditions
        with transaction.atomic():
            #create giftcard object in database or fetch it if it already exists for the user
            giftcard, created  = GiftCard.objects.get_or_create(
                user=user, 
                code=code,
                currency=currency,
                amount=amount,
                brand=brand,
                card_type=card_type,
                country=country,
                upload_image=upload_image
            )

            # External verification (simulate provider)
            provider_response = GiftCardProviderService.verify_card(code=code, callback_url=callback_url)
            if not provider_response.get("valid", False):
                giftcard.status = "invalid"
                giftcard.metadata.update({
                    "provider_ref": provider_response['provider_ref'],
                    "remarks": provider_response['remarks'],
                })
                giftcard.save()
                return Response(
                    {"error": "Gift card invalid or unrecognized."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            giftcard.status = "valid"
            giftcard.metadata.update({
                "provider_ref": provider_response['provider_ref'],
                "remarks": provider_response['remarks'],
            })
            giftcard.save()
            return Response(
                {
                    "message": "Gift card recognized by provider and is valid.",
                    "provider_response": provider_response
                },
                status=status.HTTP_200_OK
            )
            



class GiftCardBuyProcessorView(generics.GenericAPIView):
    
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request: Request) -> Response:
        
        serializer = BuyGiftCardSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        amount = serializer.validated_data.get("amount")
        currency = serializer.validated_data.get("currency")
        brand = serializer.validated_data.get("brand")
        card_type = serializer.validated_data.get("card_type")
        country = serializer.validated_data.get("country")
        #client should pass it
        callback_url = request.data.get("callback_url")
        
        # assumes authentication
        user = request.user 
        
        # Atomically handle gift card redemption to prevent race conditions
        with transaction.atomic():
            #create giftcard object in database or fetch it if it already exists for the user
            giftcard, created  = GiftCard.objects.get_or_create(
                user=user, 
                currency=currency,
                amount=amount,
                brand=brand,
                card_type=card_type,
                country=country,
            )

            # External verification for giftcard purchase(simulate provider) to be purchased
            provider_response = GiftCardProviderService.verify_card_for_prurchase(
                brand=brand,
                card_type=card_type,
                country=country,
                currency=currency,
                amount=amount,
                callback_url=callback_url
            )
            if not provider_response.get("valid", False):
                giftcard.status = "invalid"
                giftcard.metadata.update({
                    "provider_ref": provider_response['provider_ref'],
                    "remarks": provider_response['remarks'],
                })
                giftcard.save()
                return Response(
                    {"error": "Gift card invalid or unrecognized."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            giftcard.status = "valid"
            giftcard.metadata.update({
                "provider_ref": provider_response['provider_ref'],
                "remarks": provider_response['remarks'],
            })
            giftcard.save()
            return Response(
                {
                    "message": "Gift card recognized/generated by provider and is valid.",
                    "provider_response": provider_response
                },
                status=status.HTTP_200_OK
            )
            



class GiftCardVerificationWebhook(generics.GenericAPIView):
    
    """
    Handles webhook callbacks from partner verification systems.
    Example POST payload:
    {
        "reference": "GC-20251026-0001",
        "status": "success",
        "verified_amount": 100,
        "verified_currency": "USD",
        "brand": "amazon",
        "remarks": "Valid gift card",
        "provider_ref": "ABC123456"
    }
    """
    
    """
    Redeem a gift card, verify with provider, credit wallet, log transaction.
    """
    
    # Webhooks usually use HMAC auth, not DRF auth
    authentication_classes = [] 
    permission_classes = []   
    
    
    def verify_signature(self, request: Request):
        """Optional: Validate webhook signature (recommended)."""
        secret: str = os.getenv("WEBHOOK_SECRET", "none")
        if not secret:
            return True
        signature = request.headers.get("X-Signature", "")
        computed = hmac.new(secret.encode(), request.body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, computed)
    
        
    def post(self, request: Request) -> Response:
        '''if not self.verify_signature(request):
            return Response({"detail": "Invalid signature"}, status=status.HTTP_403_FORBIDDEN)'''

        data = request.data
        print(f'webhook data: {data}')
        ref = data.get("reference")  #should be same as the giftcard object id
        status_str = data.get("status")
        verified_amount = data.get("verified_amount")
        verified_currency = data.get("verified_currency", "USD")
        brand = data.get("brand")
        remarks = data.get("remarks", "")
        provider_ref = data.get("provider_ref")

        try:
            giftcard = GiftCard.objects.select_related("redeemed_by").get(metadata__provider_ref=provider_ref)     #metadata__reference=ref
        except GiftCard.DoesNotExist:
            return Response({"detail": "GiftCard not found for this corresponding user provider reference"}, status=status.HTTP_404_NOT_FOUND)

        # Already processed?
        if giftcard.status == "redeemed":
            return Response({"detail": "Already processed"}, status=status.HTTP_200_OK)

        # Update according to webhook data
        with transaction.atomic():
            if status_str == "success":
                user = giftcard.redeemed_by
                rate = GiftCardProviderService.get_rate_for_brand(bran=brand, from_currency=verified_currency, to_currency="NGN") or 1
                payout = float(verified_amount) * float(rate)
                
                #Credit wallet
                wallet = Wallet.objects.get(user=user)
                wallet.deposit(amount=payout)
                
                # ✅ Mark as redeemed
                giftcard.amount = verified_amount
                giftcard.currency = verified_currency
                giftcard.redeemed_at = timezone.now()
                giftcard.redeemed_by = user
                giftcard.metadata.update({
                    "provider_ref": provider_ref,
                    "remarks": remarks,
                })
                giftcard.save()

                #Log transaction # Create a transaction record  for user
                trx_ref = f"PIKA-{timedelta.microseconds}-{random.randint(1000, 9999)}"
                transaction =  Transaction.objects.create(
                    user=user,
                    transaction_reference=trx_ref,
                    transaction_type="GIFTCARD-REDEEM",
                    amount=payout,
                    #currency="NGN",
                    status="COMPLETED",
                    reason="I want to use the funds to guide!",
                    crypto_name="",
                    crypto_wallet_address="",
                    recipient=user,
                )
            
                #CREATE NOTIFICATION AFTER SUCCESSFUL TRANASACTION Redemption
                Notification.objects.create(
                    user=user,
                    title=f"Transaction Successful!",
                    content=f"Hi {user.first_name},\n Your giftcard has been redeemed successfully!",
                    type="normal"  #alert, normal, promotion
                )
                
                #UPDATE THE USER LEADERSHIP BOARD
                leaderboard = LeadershipBoard.objects.filter(user=user).first()
                leaderboard.total_traded_amount += int(verified_amount)  #(USD)
                leaderboard.total_trades += 1
                leaderboard.save()

                # (Optional) Trigger async email confirmation
                send_email_to_user.delay(user_id=user.id, content='Your giftcard has been redeemed successfully and your wallet credited!')

                return Response({"status": "processed", "credited": payout}, status=status.HTTP_200_OK)

            else:
                giftcard.status = "rejected"
                giftcard.metadata.update({
                    "provider_ref": provider_ref,
                    "remarks": remarks,
                })
                giftcard.save()
                return Response({"status": "rejected"}, status=status.HTTP_200_OK)
            
            

class GiftCardPurchaseVerificationWebhook(generics.GenericAPIView):
    
    """
    Handles webhook callbacks from partner verification systems.
    Example POST payload:
    {
        "reference": "GC-20251026-0001",
        "status": "success",
        "amount": 100,
        "country": "US",
        "currency": "USD",
        "code": "code", #redemption code
        "brand": "amazon",
        "remarks": "Gift card purchased successfully",
        "provider_ref": "ABC123456"
    }
    """
    
    """
    Purchase a verified gift card from provider, debit wallet, log transaction.
    """
    
    # Webhooks usually use HMAC auth, not DRF auth
    authentication_classes = [] 
    permission_classes = []   
    
    
    def verify_signature(self, request: Request):
        """Optional: Validate webhook signature (recommended)."""
        secret: str = os.getenv("WEBHOOK_SECRET", "none")
        if not secret:
            return True
        signature = request.headers.get("X-Signature", "")
        computed = hmac.new(secret.encode(), request.body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, computed)
    
        
    def post(self, request: Request) -> Response:
        '''if not self.verify_signature(request):
            return Response({"detail": "Invalid signature"}, status=status.HTTP_403_FORBIDDEN)'''

        data = request.data
        print(f'webhook data: {data}')
        ref = data.get("reference")  #should be same as the giftcard object id
        status_str = data.get("status")
        amount = data.get("amount")
        currency = data.get("currency", "USD")
        country = data.get("country")
        code = data.get("code")
        brand = data.get("brand")
        remarks = data.get("remarks", "")
        provider_ref = data.get("provider_ref")

        try:
            giftcard = GiftCard.objects.select_related("user").get(metadata__provider_ref=provider_ref)     #metadata__reference=ref
        except GiftCard.DoesNotExist:
            return Response({"detail": "GiftCard not found for this corresponding user provider reference"}, status=status.HTTP_404_NOT_FOUND)

        # Already processed?
        if giftcard.status == "redeemed":
            return Response({"detail": "Already processed"}, status=status.HTTP_200_OK)

        # Update according to webhook data
        with transaction.atomic():
            if status_str == "success":
                user = giftcard.user #redeemed_by
                rate = GiftCardProviderService.get_rate_for_brand(bran=brand, from_currency=currency, to_currency="NGN") or 1
                debit = float(amount) * float(rate)
                
                #Debit wallet
                wallet = Wallet.objects.get(user=user)
                wallet.debit(amount=debit)
                
                # ✅ Mark as redeemed 
                giftcard.amount = amount
                giftcard.currency = currency
                giftcard.country = country
                giftcard.code = code
            
                giftcard.metadata.update({
                    "provider_ref": provider_ref,
                    "remarks": remarks,
                })
                giftcard.save()

                #Log transaction # Create a transaction record  for user
                trx_ref = f"PIKA-{timedelta.microseconds}-{random.randint(1000, 9999)}"
                transaction =  Transaction.objects.create(
                    user=user,
                    transaction_reference=trx_ref,
                    transaction_type="GIFTCARD-PURCHASE",
                    amount=debit,
                    #currency="NGN",
                    status="COMPLETED",
                    reason="I want to send giftcard to my loved ones!",
                    crypto_name="",
                    crypto_wallet_address="",
                    recipient=user,
                )
            
                #CREATE NOTIFICATION AFTER SUCCESSFUL TRANASACTION Redemption
                Notification.objects.create(
                    user=user,
                    title=f"Transaction Successful!",
                    content=f"Hi {user.first_name}, \nYour {amount} {currency} giftcard has been purchased successfully and your code is {code}. \nKindly check your email for more information.!",
                    type="normal"  #alert, normal, promotion
                )
                
                #UPDATE THE USER LEADERSHIP BOARD
                leaderboard = LeadershipBoard.objects.filter(user=user).first()
                leaderboard.total_traded_amount += int(amount)  #(USD)
                leaderboard.total_trades += 1
                leaderboard.save()

                # (Optional) Trigger async email confirmation
                send_email_to_user.delay(user_id=user.id, content=f"You have successfully purchased {amount} {currency} giftcard and your code is {code}.")

                return Response({"status": "processed", "debited": debit}, status=status.HTTP_200_OK)

            else:
                giftcard.status = "failed"
                giftcard.metadata.update({
                    "provider_ref": provider_ref,
                    "remarks": remarks,
                })
                giftcard.save()
                return Response({"status": "failed"}, status=status.HTTP_200_OK)
            


class LeadershipBoardView(generics.GenericAPIView):
    """View for fetching and updating leadership board details"""
    queryset = LeadershipBoard.objects.all().order_by('-created_at')
    serializer_class = LeadershipBoardSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    
    def get(self, request: Request, *args, **kwargs) -> Response:
        #get object from db then serializse
        instance=self.get_object()
        serializer = self.get_serializer(instance=instance)
        
        return Response(
            {
                "message": "User Leaderboard Retrieved successfully.",
                "data": serializer.data
            },
            status=status.HTTP_200_OK
        )
        
    def put(self, request: Request) -> Response:
        user = self.request.user
        data = request.data
        print(f'data: {data}')
        amount = data.get("amount", 0) 
        #UPDATE THE USER LEADERSHIP BOARD
        leaderboard = LeadershipBoard.objects.filter(user=user).first()
        if not leaderboard:
            return Response(
                {
                    "message": "User Leaderboard not found.",
                },
                status=status.HTTP_404_NOT_FOUND
            )
        leaderboard.total_traded_amount += amount  #(USD)
        leaderboard.total_trades += 1
        leaderboard.save()
        return Response(
            {
                "message": "User Leaderboard Updated successfully.",
                "data": amount
            },
            status=status.HTTP_200_OK
        )