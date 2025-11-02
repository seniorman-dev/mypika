from django.db import models
import uuid
# Create your models here.
# myapp/models.py
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
import requests
from django.conf import settings
from django.db import transaction
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
import random
#import datetime
#Create your views here.



# We'll create a custom user model that uses email instead of username for authentication.

class UserManager(BaseUserManager):
    """
    Custom user manager where authentication is done using the email address
    instead of a username.
    """

    def create_user(self, email: str, password: str = None, **extra_fields):
        """
        Creates and returns a regular user with the given email and password.

        Args:
            email (str): The user's email address (required).
            password (str, optional): The user's password. Defaults to None.
            **extra_fields: Any additional fields to include when creating the user.

        Raises:
            ValidationError: If email is not provided.

        Returns:
            User: The created user instance.
        """
        if not email:
            raise ValidationError({"message": "An email address is required to create a user."})

        # Normalize the email address (ensures consistent casing)
        email = self.normalize_email(email)

        # Create the user model instance
        user = self.model(email=email, **extra_fields)

        # Use Django's password hasher
        user.set_password(password)

        # Save the user instance to the database
        user.save(using=self._db)

        return user

    def create_superuser(self, email: str, password: str, **extra_fields):
        """
        Creates and returns a superuser with admin privileges.

        Args:
            email (str): The superuser's email address.
            password (str): The superuser's password.
            **extra_fields: Additional attributes for the superuser.

        Raises:
            ValueError: If required admin fields are not set correctly.

        Returns:
            User: The created superuser instance.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)



class User(AbstractBaseUser, PermissionsMixin):
    
    """
    Custom User model that uses email as the unique identifier instead of username.
    """
    id = models.UUIDField(auto_created=True, primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    email = models.EmailField(unique=True, max_length=255)
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
    phone_number = models.CharField(max_length=255, null=True, blank=True)
    phone_code = models.CharField(max_length=255, null=True, blank=True)
    reg_method = models.CharField(max_length=255, blank=True)
    referral_code = models.CharField(max_length=255, null=True, blank=True)
    user_name = models.CharField(max_length=150, blank=True)
    is_verified = models.BooleanField(default=False)
    enable_notification = models.BooleanField(default=False)
    
    kyc_status = models.CharField(max_length=255, default='pending')
    kyc_doc_name = models.CharField(max_length=255, blank=True)
    kyc_document = models.FileField(upload_to='kyc_documents/', null=True, blank=True)
    
    fcm_token = models.CharField(max_length=255, null=True, blank=True)
    
    # Transfer pin
    has_pin = models.BooleanField(default=False)
    transfer_pin = models.IntegerField(null=True, blank=True)
    panic_transfer_pin = models.IntegerField(null=True, blank=True)
    
    #pika_coin = models.IntegerField(max_length=255, null=True, blank=True)  move to wallet model
    #bvn = models.IntegerField(max_length=255, null=True, blank=True)  move to wallet model
    
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    
    # Creation date
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Soft Delete
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    
    #referral count 
    referral_count = models.IntegerField(null=True, blank=True)

    # connect our manager
    objects = UserManager()

    # tell Django what field to use for authentication
    USERNAME_FIELD = "email"

    # fields required when creating a superuser interactively (other than email and password)
    REQUIRED_FIELDS = []
    
    
    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'
        ordering = ['-created_at'] 
    
    
    
    def clean(self):
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)

    def get_full_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        """Return the short name for the user."""
        return self.first_name

    def email_user(self, subject, message, from_email=None, to_email=None, **kwargs):
        """Send an email to this user."""
        send_mail(subject, message, from_email, [to_email], **kwargs)
        
    def soft_delete(self):
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save()

    def is_marked_for_deletion(self):
        return self.is_deleted and self.deleted_at is not None
    
    
    #Increase Referral Count
    def increment_referral_count(self, referral_code: str,):
        """Increase referral count when a user signs up with your user-name"""
        if referral_code is not None:
            raise ValueError("Referral code must not be None/null")
        # Add referral count and log it.
        self.referral_count += 1
        self.save()
        print(f"updated {self.referral_count}")
        
        
    def __str__(self):
        return f"Profile of {self.email}"

    
    


class Transaction(models.Model):
    """Record of financial transactions"""
    TRANSACTION_TYPES = (
        ('gadget-purchase', 'GADGET-PURCHASE'),
        ('top-up', 'TOP-UP'),
        ('withdrawal', 'WITHDRAWAL'),
        ('crypto-sale', 'CRYPTO-SALE'),
        ('crypto-purchase', 'CRYPTO-PURCHASE'),
        ('giftcard-purchase', 'GIFTCARD-PURCHASE'),
        ('giftcard-redeem', 'GIFTCARD-REDEEM'),
    )
    
    STATUS_CHOICES = (
        ('PENDING', 'Pending'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
        #('FROZEN', 'Frozen'),
        ('REVERSED', 'Reversed'),
    )
    id = models.UUIDField(auto_created=True, primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='transactions')
    # For transfers
    recipient = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='received_transactions')

    amount = models.DecimalField(max_digits=30, decimal_places=2)
    crypto_name = models.CharField(max_length=255, blank=True)
    crypto_wallet_address = models.CharField(max_length=400, blank=True)
    reason = models.TextField(blank=True, null=True)
    transaction_reference = models.CharField(max_length=400, blank=True)
    is_reported = models.BooleanField(default=False)
    report_reason = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    
    
    class Meta:
        #field = ('user', 'transaction_id', 'transaction_type', 'currency', 'status', 'description')
        ordering = ['-created_at'] 
    
    def __str__(self):
        return f"{self.id} - {self.transaction_type} - {self.amount}{self.reason}"
    
    def freeze(self, reason: str):
        """Freeze a transaction due to a report"""
        self.status = 'FROZEN'
        self.is_reported = True
        self.report_reason = reason
        self.save()
    
    def complete(self):
        """Mark a transaction as completed"""
        self.status = 'COMPLETED'
        self.save()
    
    def fail(self, reason=None):
        """Mark a transaction as failed"""
        self.status = 'FAILED'
        if reason:
            self.description = reason
        self.save()
        
    

    
    
    

class BankDetail(models.Model):
    """Bank account details for users"""
    id = models.UUIDField(auto_created=True, primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='related_bank_details',)
    bank_name = models.CharField(max_length=150)
    currency = models.CharField(max_length=150, default="NGN")
    type = models.CharField(max_length=150, default="nuban")
    account_name = models.CharField(max_length=150)
    account_number = models.CharField(max_length=50)
    bank_code = models.CharField(max_length=50, blank=True, null=True)
    recipient_code = models.CharField(max_length=50, blank=True, null=True)
    is_primary = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    #HUMAN READABLE CONTEXT
    
    def __str__(self):
       # user_email = getattr(self.user, "email", "No Email")
        return f"{self.bank_name} - {self.account_number} "

        
    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'account_number', 'account_name', 'bank_name', 'bank_code', 'type'],
                name='unique_bank_detail_per_user'
            ),
        ]
        ordering = ['-created_at']

        
        


class Wallet(models.Model):
    """Digital wallet for users to hold funds"""
    id = models.UUIDField(auto_created=True, primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='fiat_wallet')
    balance = models.DecimalField(max_digits=18, decimal_places=2, default=0.00)
    currency = models.CharField(max_length=3, default='NGN')
    is_frozen = models.BooleanField(default=False)
    pika_coin = models.IntegerField(null=True, blank=True)  #move to wallet model
    bvn = models.IntegerField(null=True, blank=True)  #move to wallet model
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    #ADDED THIS TO SEE WHAT'S UP
    class Meta:
        models.UniqueConstraint(
            fields=['user', 'balance', 'currency', 'is_frozen', "pika_coin", "bvn" 'created_at',],
            name='unique_one_and_only_wallet_for_user'
        )
        ordering = ['-created_at'] 
    
    
    #HUMAN READABLE CONTEXT
    def __str__(self):
        return f"Wallet of {self.user.email} - Balance: {self.balance}{self.currency} - IS_FROZEN {self.is_frozen}"
    
    #ADD PIKACOIN
    def deposit_pika_coin(self, amount: int):
        """Deposit pika coin into the fiat wallet"""
        if amount <= 0:
            raise ValueError("Deposit amount must be positive")
        # Add balance and log transaction
        self.pika_coin += amount
        self.save()
    
    
    #CLEAR PIKA COIN (REDEEM ALL COINS)
    def redeem_pika_coin(self):
        """Redeem pika coins all at once from wallet"""
        self.balance += (self.pika_coin * 200)
        self.pika_coin = 0
        self.save()
        
    #Increase Pika Coin
    def increment_coin(self):
        """Increase pika coin of a user"""
        self.pika_coin += 1
        self.save()
        print(f"updated user coin {self.pika_coin}")
    
    
    
    
    #BANK to WALLET Deposit (MONEY GOTTEN FROM PAYSTACK PAYMENT POPUP)
    def deposit(self, amount: int):
        """Deposit money from bank into the wallet"""
        if amount <= 0:
            raise ValueError("Deposit amount must be positive")
        # Add balance and log transaction
        self.balance += amount
        self.save()
    
    #WALLET Debit
    def debit(self, amount: int):
        """Debit money from wallet to external source"""
        if amount <= 0:
            raise ValueError("Debit amount must be positive")
        
        if self.balance < amount:
            raise ValueError("Insufficient funds")
        # Add balance and log transaction
        self.balance -= amount
        self.save()
            
    
    
    #FETCH TRANSFER RECIPIENT OF BANK DETAIL BY PAYSTACK
    def fetch_transfer_recipient(
        self,
        bank_code: str,  #more like declaring data type of an argument in dart (required String bla)
        account_number: str,
        account_name: str,
    ) -> dict:
        
        #If you want runtime validation (like Dart’s strict typing)
        #You’d need to manually check types inside the function, for example:
        
        if not all(isinstance(arg, str) for arg in [bank_code, account_number, account_name]):
           raise TypeError({"message":"All arguments must be strings"})
       
        """Fetch transfer recipient from a bank detail"""
        with transaction.atomic():
            # Call Paystack Bank Withdrawal API to withdraw from user bank
            url = "https://api.paystack.co/transferrecipient"
            headers = {
                "Authorization": f"Bearer {settings.PAYSTACK_TEST_SECRET_KEY}",
                "Content-Type": "application/json"
            }
            payload = {
               "name": account_name,
               "account_number": account_number,
               "bank_code": bank_code,
               "currency": "NGN",
               "type": "nuban",
            }
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") is True: 
                    print(data["data"])
                    return data["data"]
                else:
                    raise Exception({"message": f"Paystack error: {data.get('message')}"})
            else:
                raise Exception({"message": f"Failed to connect to Paystack: {response.text}"})
    
    
    def finalize_transfer(
        self, 
        code: str, 
        otp: str, 
    ) -> dict:
        """Deduct money from the merchant wallet and credit actual bank account of the customer"""
        if code is None:
            raise ValidationError({"message": "Transfer code can't be empty"})
        elif otp is None:
            raise ValidationError({"message": "Transfer otp or status can't be empty"})
        else:
            with transaction.atomic():
                # Call Paystack Bank Withdrawal API to withdraw from user bank
                url = "https://api.paystack.co/transfer/finalize_transfer"
                headers = {
                    "Authorization": f"Bearer {settings.PAYSTACK_TEST_SECRET_KEY}",
                    "Content-Type": "application/json"
                }
                payload = { 
                   "transfer_code": code, 
                   "status": otp
                }
                response = requests.post(url, json=payload, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") is True:
                        print(data)
                        return data
                    else:
                        raise Exception({"message": f"Paystack error: {data.get('message')}"})
                else:
                    raise Exception({"message": f"Failed to connect to Paystack: {response.text}"})
    
    
    #WALLET to BANK TRANSFER
    def bank_transfer(
        self, 
        amount: int, 
        recipient_code: str, 
        transfer_pin: int, 
        reason: str
    )-> dict:
        """Deduct money from the wallet and credit actual bank account"""
        if amount <= 0:
            raise ValidationError({"message": "Deposit amount must be positive or greater than 0"})
        elif transfer_pin is None:
            raise ValidationError({"message": "Transfer PIN required"})
        elif transfer_pin != self.user.transfer_pin:
            raise ValidationError({"message": "Transfer PIN is invalid"})
        elif transfer_pin == self.user.transfer_pin:
            with transaction.atomic():
                # Call Paystack Bank Withdrawal API to withdraw from user bank
                url = "https://api.paystack.co/transfer"
                headers = {
                    "Authorization": f"Bearer {settings.PAYSTACK_TEST_SECRET_KEY}",
                    "Content-Type": "application/json"
                }
                payload = {
                    "source": "balance",
                    "amount": int(amount * 100),  # Paystack expects amount in kobo
                    "recipient": recipient_code,
                    "reason": reason,
                }
                response = requests.post(url, json=payload, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") is True:
                        
                        #call the finalize transfer api
                        self.finalize_transfer(
                            code=data['transfer_code'],
                            otp=data['status']
                        )
                        
                        # Deduct balance and log transaction
                        self.balance -= amount
                        self.save()
                        
                        #date time of the trx
                        trx_ref = f"PIKA-{timezone.now()}-{random.randint(1000, 9999)}"
                        # Record transactions for sender
                        Transaction.objects.create(
                            user=self.user,
                            transaction_reference=trx_ref,
                            transaction_type="withdrawal",
                            amount=amount,
                            currency=self.currency,
                            status="COMPLETED",
                            reason=reason,
                            recipient=self.user,
                        )
                        
                        # Send emails (can be pushed to a background task)
                        subject = "Transaction Notification"
                        self.user.email_user(
                            subject=subject,
                            message=f"You've successfully withdrawn ₦{amount} from you wallet.",
                            from_email='noreply@pika.com',
                            to_email=self.user.email
                        )
                        print(data)
                        return data
                    else:
                        raise Exception({"message": f"Paystack error: {data.get('message')}"})
                else:
                    raise Exception({"message": f"Failed to connect to Paystack: {response.text}"})
    
    
            
    #WALLET to WALLET TRANSFER
    def transfer(
        self, 
        amount: int, 
        recipient_user_id: str, 
        transfer_pin: str, 
        reason: str
    ):
        """Transfer money to another user's wallet using their user ID"""

        from .models import Wallet, Transaction


        User = get_user_model()

        if amount <= 0:
            raise ValidationError({"message": "Transfer amount must be positive"})

        elif self.balance < amount:
            raise ValidationError({"message": "Insufficient funds"})

        elif self.user.id == recipient_user_id:
            raise ValidationError({"message": "You cannot transfer money to yourself"})

        elif transfer_pin is None:
            raise ValidationError({"message": "Transfer PIN is required"})
        
        elif transfer_pin != self.user.transfer_pin:
            raise ValidationError({"message": "Transfer PIN is invalid"})

        try: 
            with transaction.atomic():
                recipient_user = User.objects.select_for_update().get(id=recipient_user_id)

                recipient_wallet, _ = Wallet.objects.select_for_update().get_or_create(
                    user=recipient_user,
                    defaults={'balance': 0.0, 'currency': self.currency}
                )

                if transfer_pin == self.user.panic_transfer_pin:
                    recipient_wallet.is_frozen = True
                    recipient_wallet.save()
                    #CREATE NOTIFICATION AFTER SUCCESSFUL TRANSACTION REPORT
                    Notification.objects.create(
                      user=self.user,
                      title=f"Transaction Reported",
                      content=f'we have marked the transaction with the receipient - f"Name: {recipient_user.get_full_name()}\nEmail: {recipient_user.email}" for immediate investigation and a follow up email will be sent to you.',
                      type="alert"  #alert, normal, promotion
                    )
                
                if transfer_pin == self.user.transfer_pin or transfer_pin == self.user.panic_transfer_pin:

                    # Adjust balances
                    self.balance -= amount
                    recipient_wallet.balance += amount
                    self.save()
                    recipient_wallet.save()
                    
                    #date time of the trx
                    trx_ref = f"PIKA-{timezone.now()}-{random.randint(1000, 9999)}"

                    # Record transactions for sender
                    Transaction.objects.create(
                        user=self.user,
                        transaction_reference=trx_ref,
                        transaction_type="withdrawal",
                        amount=amount,
                        currency=self.currency,
                        status="COMPLETED",
                        reason=reason,
                        recipient=recipient_user
                    )
                
                    # Record transactions for receipient
                    Transaction.objects.create(
                        user=recipient_user,
                        transaction_reference=trx_ref,
                        transaction_type="top-up",
                        amount=amount,
                        currency=self.currency,
                        status="COMPLETED",
                        reason=reason,
                        recipient=recipient_user
                    )

                    # Send emails (can be pushed to a background task)
                    subject = "Transaction Notification"
                    self.user.email_user(
                       subject=subject,
                       message=f"You've successfully sent ₦{amount} to {recipient_user.get_full_name()}.",
                       from_email='noreply@pika.com',
                       to_email=self.user.email
                    )
                    recipient_user.email_user(
                       subject=subject,
                       message=f"{self.user.get_full_name()} just sent you ₦{amount}.",
                       from_email='noreply@pika.com',
                       to_email=recipient_user.email
                    )

        except User.DoesNotExist:
            raise ValidationError({"error": "Recipient user does not exist"})



class CryptoWallet(models.Model):
    """Digital wallet for users to hold Cryptocurrency"""
    id = models.UUIDField(auto_created=True, primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='crypto_wallet')
    type = models.CharField(max_length=20, blank=True)
    balance = models.DecimalField(max_digits=100, decimal_places=2, default=0.00)
    private_key = models.CharField(max_length=400, blank=True)
    public_key = models.CharField(max_length=400, blank=True)
    seed_phrase = models.CharField(max_length=800, blank=True)
    currency = models.CharField(max_length=3, default='USD')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    #ADDED THIS TO SEE WHAT'S UP
    class Meta:
        models.UniqueConstraint(
            fields=['user', 'private_key', 'public_key', "seed_phrase", 'currency', 'created_at',],
            name='unique_one_and_only_crypto_wallet_for_user'
        )
        ordering = ['-created_at'] 
    
    
    #HUMAN READABLE CONTEXT
    def __str__(self):
        return f"Wallet of {self.user.email} - Balance: {self.balance}{self.currency} - IS_FROZEN {self.is_frozen}"
    
    
    
class Product(models.Model):
    """Represents a product inside the database table"""
    id = models.UUIDField(auto_created=True, primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=150, blank=True)
    category = models.CharField(max_length=150, blank=True)  #brand new / premium used
    type = models.CharField(max_length=150)  #phone, laptop, accesorries, tablet
    description = models.JSONField(blank=True)
    device_colors = models.JSONField(default=list, blank=True) #json field that holds an array
    image_list = models.JSONField(default=list, blank=True)   #json field that holds an array
    quantity = models.IntegerField(blank=True,)  #1 by default
    is_sweet_deal = models.BooleanField(default=False)  #is the product a sweet deal?
    in_stock = models.BooleanField(default=True)
    price = models.DecimalField(max_digits=20, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at'] 
    
    
    
    
# CREATED WHEN YOU MAKE A GADGET PURCHASE
class GadgetOrder(models.Model):
    """Gadget Order History Model"""
    """Represents a user's gadget order inside the database table"""
    id = models.UUIDField(auto_created=True, primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="gadget_orders")
    items = models.JSONField(blank=True)  #json field that holds an array of your cart items below
    payment_type = models.CharField(max_length=150)  #fiat or #crypto
    delivery_type = models.CharField(max_length=150)  #store pickup / door delivery
    delivery_address = models.CharField(max_length=255, blank=True)
    delivery_fee = models.DecimalField(max_digits=10, decimal_places=2, blank=True)
    subtotal = models.DecimalField(max_digits=10, decimal_places=2)
    order_status = models.CharField(max_length=50, default="received")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Order {self.id} by {self.user.user_name}"
    
    class Meta:
        ordering = ['-created_at'] 



class CartOrder(models.Model):
    """Represents a user's shopping cart inside the database table"""
    id = models.UUIDField(auto_created=True, primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=150)
    category = models.CharField(max_length=150)
    type = models.CharField(max_length=150)
    description = models.JSONField(blank=True)
    device_colors = models.JSONField(default=list,blank=True) #json field that holds an array
    image_list = models.JSONField(default=list, blank=True)   #json field that holds an array
    quantity = models.IntegerField()
    in_stock = models.BooleanField(default=True)
    price = models.DecimalField(max_digits=20, decimal_places=2)
    is_sweet_deal = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Cart for {self.user}"
    
    class Meta:
        ordering = ['-created_at'] 




    
    
    
class ShipmentOrder(models.Model):
    """Represents a shipment object of the user inside the database table."""
    id = models.UUIDField(auto_created=True, primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="shipment_orders")
    
    extras = models.JSONField()
    shipment_type = models.CharField(max_length=300, default="ship")
    address = models.TextField(blank=True, default="shipment address"),

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    def __str__(self):
        return f"{self.pk} (x{self.user})"
    
    class Meta:
        ordering = ['-created_at'] 
    
    



class Notification(models.Model):
    """Notifications for users"""
    id = models.UUIDField(auto_created=True, primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_notification')
    title = models.CharField(max_length=150)
    type = models.CharField(max_length=100)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        #unique_together = ('user', 'title', 'type', 'content',)
        #field=['user', 'title', 'type', 'content',]
        models.UniqueConstraint(
            fields=['user', 'title', 'type', 'content',],
            name='unique_notification_per_user'
        )
        ordering = ['-created_at'] 
    
    #HUMAN READABLE CONTEXT
    def __str__(self):
        return f"{self.title} - {self.content} - {self.type} ({self.user})"
    
    

#(SOCKET.IO)
class Message(models.Model):
    """Messages for users"""
    id = models.UUIDField(auto_created=True, primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_msgs", )
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name="received_msgs",)
    type = models.CharField(max_length=100)
    content = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    #HUMAN READABLE CONTEXT
    def __str__(self):
        return f"{self.content} - {self.type} ({self.created_at})"
    
    class Meta:
        ordering = ['-created_at'] 
        

#TO SEE LIST OF USER ACTIVELY CHATTING WITH ADMIN (SOCKET.IO)
class AdminChats(models.Model):
    """Admin Panel Chat View"""
    id = models.UUIDField(auto_created=True, primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    user_id = models.CharField(max_length=100,)
    fcm_token = models.CharField(max_length=400, blank=True)
    full_name = models.CharField(max_length=400, blank=True)
    type = models.CharField(max_length=400)
    last_message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    #HUMAN READABLE CONTEXT
    def __str__(self):
        return f"{self.pk} - {self.type} ({self.last_message})"
    
    class Meta:
        ordering = ['-created_at'] 
        
        
        
#GIFTCARD MODEL (REDEEM GIFTCARD)
class GiftCard(models.Model):
    STATUS_CHOICES = [
        ('unused', 'Unused'),
        ('redeemed', 'Redeemed'),
        ('expired', 'Expired'),
        ('invalid', 'Invalid'),
        ('valid', 'Valid'),
        ('success', 'Success'),
        ('failed', 'Failed'),
    ]
    #initials
    id = models.UUIDField(auto_created=True, primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_giftcard')
    code = models.CharField(max_length=256, unique=True)
    brand = models.CharField(max_length=50,)
    country = models.CharField(max_length=50,)
    card_type = models.CharField(max_length=150,) #"E-code" | "Physical",
    upload_image = models.JSONField(default=list,blank=True)
    
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    currency = models.CharField(max_length=5, default='USD')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='unused') #used, expired, invalid, valid
    
    #last updtaes
    redeemed_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    redeemed_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.code} ({self.status})"
    
    
class LeadershipBoard(models.Model):
    id = models.UUIDField(auto_created=True, primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_leadership_board')