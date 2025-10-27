from decimal import Decimal
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from rest_framework.authtoken.models import Token
from .models import CartOrder, CryptoWallet, GadgetOrder, GiftCard, Notification, Product, ShipmentOrder, User, BankDetail, Wallet, Transaction, Message




class BasicUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "id", 
            'user_name',
            'email', 
            'first_name', 
            'last_name', 
            'avatar',
            'phone_number',
            'phone_code',
            'reg_method', 
            'referral_code',
            "referral_count",
            'is_verified',
            
            'enable_notification',
    
            'kyc_status', 
            'kyc_document', 
            'fcm_token',
    
            'has_pin',
            'transfer_pin', 
            'panic_transfer_pin',
    
            'is_active',
            'is_staff',
            
            # Soft Delete
            'is_deleted', 
            'deleted_at',
    
            # Creation date
            'created_at', 
            'updated_at',
    
        )
        
    def validate(self, data: dict):
        """Validate user credentials (particularly username)"""
        user_name = data.get('user_name',)
        request = self.context.get('request')
        print(f'request data: {request.data}')
        user_object = User.objects.filter(
            user_name= user_name
        )
        if user_object.exists:
            raise serializers.ValidationError({"message": 'Username already exists in the system'})
        
        
class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration"""
    user_name = serializers.CharField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    phone_code = serializers.CharField()
    phone_number = serializers.CharField()
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    fcm_token = serializers.CharField()
    reg_method = serializers.CharField()

    class Meta:
        model = User
        fields = (
            "id", 
            'email', 
            'password', 
            'first_name', 
            'last_name', 
            'user_name', 
            "phone_code",
            "phone_number",
            'kyc_status', 
            'fcm_token', 
            'is_verified', 
            'reg_method', 
            'referral_code', 
            'is_active', 
            'created_at',
        )
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def create(self, validated_data: dict):
        """Create and return a new user with a hashed password"""
        first_name = validated_data['first_name']
        last_name = validated_data['last_name']
        email = validated_data['email']
         
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)  # 🔐 Hash the password
        
        #SORT GMAIL SMTP STUFF IN THE SETTINGS, then call this
        user.email_user(
            subject= "Welcome to Pika!", 
            message= f"Hey {first_name} {last_name},\nWe're delighted to have you onboard and we say big cheers to seamless transactions with us.", 
            from_email= "noreply@pika.com", 
            to_email= email
        )
        
        
        #FINALLY SAVED THE USER OBJECT TO DATABASE (SQLite)
        user.save()
        
        #CREATE NOTIFICATION OBJECT FOR THE USER
        Notification.objects.create(
            user=user,
            title=f"Welcome to Pika {first_name}!",
            content=f"Gear up as we take you on a journey to seamless trades, shopping and financial services.",
            type="normal"  #alert, normal, promotion
        )
        return user
    
    
class UserLoginSerializer(serializers.Serializer):
    
    """Serializer for user login"""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    fcm_token = serializers.CharField()
    
    class Meta:
        model = User
        fields = (
            "id", 
            'email', 
            'password', 
            'first_name', 
            'last_name', 
            'user_name', 
            'kyc_status', 
            'fcm_token', 
            'is_verified', 
            'reg_method', 
        )
    
    
    def validate(self, data: dict):
        """Validate user credentials"""
        email = data.get('email',)
        password = data.get('password',)
        request = self.context.get('request')
        
        print(f"Authenticating user: {email}")
        
        if email is None or password is None:
            raise serializers.ValidationError({"message": 'Email and password are required'})
        
        user = authenticate(
            request=request,
            email=email,
            password=password
        )
        
        if user is None:
            raise serializers.ValidationError({"message": "Invalid login credentials."})

        if not user.is_active:
            raise serializers.ValidationError({"message": "This account is inactive."})
        # Update last login time
        update_last_login(None, user)
        return user
    
    
    
class KycUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            'kyc_doc_name', 
            'kyc_document'
        )
        extra_kwargs = {
            'kyc_doc_name': {'required': True},
            'kyc_document': {'required': True}
        }



class TransferPinSerializer(serializers.Serializer):
    """Serializer for updating transfer pin"""
    #current_password = serializers.CharField(write_only=True, required=True)
    new_pin = serializers.CharField(max_length=6, min_length=4, write_only=True, required=True)
    
    def validate_current_pin(self, value):
        """Validate the transfer pin"""
        user = self.context['request'].user
        if user.transfer_pin != value:
            raise serializers.ValidationError({"message": 'Incorrect current transfer pin'})
        return value



class PanicPinSerializer(serializers.Serializer):
    """Serializer for updating panic pin"""
    #current_pin = serializers.CharField(max_length=6, min_length=4, write_only=True, required=False)
    new_pin = serializers.CharField(max_length=6, min_length=4, write_only=True, required=True)
    
    def validate_current_pin(self, value):
        """Validate the current panic pin"""
        user = self.context['request'].user
        if user.panic_transfer_pin != value:
            raise serializers.ValidationError({"message": 'Incorrect current panic pin'})
        return value


class BankDetailSerializer(serializers.ModelSerializer):
    #Required by the serializer (Client must pass these fields)
    bank_name = serializers.CharField()
    currency = serializers.CharField(default="NGN")
    type = serializers.CharField(default="nuban")
    account_name = serializers.CharField()
    account_number = serializers.CharField()
    bank_code = serializers.CharField()
    recipient_code = serializers.CharField()
    
    class Meta:
        model = BankDetail
        read_only_fields = ('id',)
        fields = (
            'id',
            'bank_name',
            'currency',
            'type',
            'account_name',
            'account_name',
            'bank_code',
            'recipient_code',
            'is_primary',
            'created_at',
            'updated_at',
        )
        
    def validate(self, data: dict):
        user = self.context['request'].user
        
        #check for duplicate bank details
        bank_detail_object = BankDetail.objects.filter(
            user=user,
            account_number=data.get("account_number"),
            account_name=data.get('account_name'),
            bank_name=data.get('bank_name'),
            bank_code=data.get('bank_code'),
            nuban=data.get('type')
        )
        
        if bank_detail_object.exists():
            raise serializers.ValidationError(detail={"message": "Bank detail already exists for this user"}, code=400)
        return data
        
        
class WalletSerializer(serializers.ModelSerializer):
    """Serializer for FIAT wallet"""
    class Meta:
        model = Wallet
        fields = (
            "id", 
            'balance', 
            'currency', 
            'is_frozen', 
            'pika_coin', 
            'bvn', 
            'created_at',
        )
        read_only_fields = fields 
        
        
    def validate_balance(self, value):
        if not isinstance(value, Decimal):
            raise serializers.ValidationError({"message": "Balance must be a decimal number."})
        if value < 0:
            raise serializers.ValidationError({"message":"Balance cannot be negative."})
        return value
    
    def validate(self, validated_data: dict):
        user = self.context['request'].user
        wallet_exists = Wallet.objects.filter(
            user=user,
            currency=validated_data.get('currency'),
        ).exists()

        if wallet_exists:
            raise serializers.ValidationError(
                {"message": "A fiat wallet already exists for this user."}
            )
        return validated_data
        
        
class CryptoWalletSerializer(serializers.ModelSerializer):
    
    """Serializer for CRYPTO wallet"""
    type = serializers.CharField(max_length=20,)
    balance = serializers.DecimalField(max_digits=100, decimal_places=2, default=Decimal('0.00'))
    private_key = serializers.CharField(max_length=400,)
    public_key = serializers.CharField(max_length=400,)
    seed_phrase = serializers.CharField(max_length=800,)
    currency = serializers.CharField(max_length=3, default='USD')
    
    
    class Meta:
        model = CryptoWallet
        fields = ('id', 'balance', 'type', 'currency', 'private_key', 'public_key', 'seed_phrase', 'created_at')
        read_only_fields = ('id', 'type', 'currency', 'private_key', 'public_key', 'seed_phrase', 'created_at')
        
    
    #create a crypto wallet for the user
    '''def create(self, validated_data):
        user = self.context['request'].user
        validated_data['user'] = user
        wallet = CryptoWallet.objects.create(**validated_data)
        return wallet'''
        
        
    def validate_balance(self, value):
        if not isinstance(value, Decimal):
            raise serializers.ValidationError({"message": "Balance must be a decimal number."})
        if value < 0:
            raise serializers.ValidationError({"message":"Balance cannot be negative."})
        return value
    
    def validate(self, validated_data: dict):
        user = self.context['request'].user
        wallet_exists = CryptoWallet.objects.filter(
            user=user,
            type=validated_data.get('type'),
            currency=validated_data.get('currency'),
        ).exists()

        if wallet_exists:
            raise serializers.ValidationError(
                {"message": "A crypto wallet of this type already exists for this user."}
            )
        return validated_data


    
    
class TransactionSerializer(serializers.ModelSerializer):
    
    """Serializer for Transaction"""
    class Meta:
        model = Transaction
        fields = (
            "id", 
            'status', 
            'transaction_type', 
            'transaction_reference',
            'amount', 
            'reason', 
            'user',
            'recipient', 
            'crypto_name',
            'crypto_wallet_address',
            'is_reported', 
            'report_reason',
            'created_at',
            
        )
        read_only_fields = fields
        
    
    
class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = (
            'id', 
            'name', 
            'category', #brand new, premium used
            'type', #phone, ipad, acessory
            'description', 
            'device_colors', 
            'image_list', 
            'in_stock',
            'quantity',
            'price',
            'is_sweet_deal',
            'created_at',
            'updated_at'
        )
    
    #create product
    '''def create(self, validated_data: dict):
        return Product.objects.create(**validated_data)

    def update(self, instance, validated_data: dict):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance'''
        
        
        
#DEPOSIT FROM BANK TO WALLET
class DepositSerializer(serializers.ModelSerializer):
    """Serializer for deposit operations"""
    amount = serializers.DecimalField(max_digits=12, decimal_places=2,)
    reason = serializers.CharField(required=False, allow_blank=True)
    
    class Meta:
        model = Transaction
        fields = [
            'amount', 
            'reason', 
        ]
        
        
    def validate_amount(self, value: int):
        """Validate the deposit amount"""
        if value <= 0:
            raise serializers.ValidationError({"message":'Amount must be greter than 0'})
        return value



#FETCH RECIPIENT CODE SERIALIZER
class RecipientCodeSerializer(serializers.Serializer):
    """Serializer for fetching transfer receipient code by Paystack"""
    bank_code = serializers.CharField(max_length=5, required=True,)
    account_number = serializers.CharField(max_length=10, write_only=True, required=True,)
    account_name = serializers.CharField(max_length=300, required=True)
    
    '''class Meta:
        model = Wallet
        fields = (
            'currency', 
            'balance', 
            'user', 
        )'''






#WALLET TO WALLET TRANSFER
class TransferSerializer(serializers.ModelSerializer):
    """Serializer for transfer operations"""
    amount = serializers.DecimalField(max_digits=12, decimal_places=2,)
    transfer_pin = serializers.CharField(write_only=True)
    reason = serializers.CharField(required=False, allow_blank=True)
    
    class Meta:
        model = Transaction
        fields = ['amount', 'transfer_pin', 'reason']

    '''def save(self, **kwargs):
        user = self.context['request'].user
        wallet = user.wallet
        wallet.transfer(
            amount=self.validated_data['amount'],
            recipient_user_id=self.validated_data['recipient_user_id'],
            transfer_pin=self.validated_data['transfer_pin'],
            reason=self.validated_data.get('reason', "")
        )
        return {"status": "success"}'''
    



#WALLET TO BANK TRANSFER
class BankTransferSerializer(serializers.ModelSerializer):
    recipient_code = serializers.CharField(write_only=True)
    transfer_pin = serializers.CharField(write_only=True)
    reason = serializers.CharField(required=False, allow_blank=True)
    #transaction_type = serializers.CharField(write_only=True)
    
    class Meta:
        model = Transaction
        fields = ['amount', 'recipient_code', 'transfer_pin', 'reason']

    def create(self, validated_data):
        validated_data.pop('recipient_code', None)
        validated_data.pop('transfer_pin', None)
        validated_data.pop('reason', None)
        return super().create(validated_data)
    


class ReportTransactionSerializer(serializers.Serializer):
    """Serializer for reporting a transaction"""
    reason = serializers.CharField()
    
    def validate_reason(self, value: str) -> str:
        """Validate the report reason"""
        if not value.strip():
            raise serializers.ValidationError({"message": 'Reason cannot be empty'})
        return value


#FOR SENDING EMAILS
class EmailSerializer(serializers.Serializer):
    """Serializer for sending emails"""
    from_email = serializers.EmailField()
    to_email = serializers.EmailField()
    subject = serializers.CharField()
    message = serializers.CharField()
    
    '''def validate_to_email(self, value: str) -> str:
        """Ensure the receiver email is valid"""
        if value == self.initial_data.get("from_email"):
            raise serializers.ValidationError("Sender and receiver email cannot be the same.")
        return value'''
    
    def validate_subject(self, value: str) -> str:
        """Validate the email subject"""
        if not value.strip():
            raise serializers.ValidationError({"message": 'Subject cannot be empty'})
        return value
    
    def validate_message(self, value: str) -> str:
        """Validate the email message"""
        if not value.strip():
            raise serializers.ValidationError({"message": 'Message cannot be empty'})
        return value
    
    

#FOR NOTIFICATION  
class NotificationSerializer(serializers.ModelSerializer):
    """Serializer for notifications"""

    class Meta:
        model = Notification
        fields = (
            'id', 
            'title', 
            'content', 
            'type', 
            'created_at', 
            'updated_at',
        )
        read_only_fields = ('id',)

    def validate(self, data: dict):
        """Validate notification details"""
        user = self.context['request'].user

        # Check for duplicate bank detail
        notification_detail = Notification.objects.filter(
            user=user,
            title=data.get('title'),
            content=data.get('content'),
            type=data.get('type'),
        )
        
        if notification_detail.exists():
            raise serializers.ValidationError({ 
               "message": "This notification object already exists for this user."
              },
              code=400
            )

        return data
    
    
    
#FOR ONE-TO-ONE MESSAGES
class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = "__all__"
        
        
#GADGET ORDER SERIALIZER
class GadgetOrderSerializer(serializers.ModelSerializer):
    
    # Required Fields
    items = serializers.JSONField()  #items in your cart
    payment_type = serializers.CharField()  #fiat or #crypto
    delivery_type = serializers.CharField()  #store pickup / door delivery
    delivery_address = serializers.CharField()
    delivery_fee = serializers.DecimalField(max_digits=10, decimal_places=2,)
    subtotal = serializers.DecimalField(max_digits=10, decimal_places=2)
    order_status = serializers.CharField(max_length=50, default="received")
    
    
    class Meta:
        model = GadgetOrder
        fields = "__all__"
        
    def validate(self, data: dict):
        """Validate Gadget orders entering the system to make sure there is no duplicate"""
        user = self.context['request'].user

        # Check for duplicate gadget order
        gadget_order = GadgetOrder.objects.filter(
            user=user,
            items=data.get('items'),
            payment_type=data.get('payment_type'),
            subtotal=data.get('subtotal'),
        )
        
        if gadget_order.exists():
            raise serializers.ValidationError({ 
               "message": "This gadget order object already exists for this user."
              },
              code=400
            )

        return data
    
#CART ORDER SERIALIZER
class CartOrderSerializer(serializers.ModelSerializer):
    # Required Fields
    name = serializers.CharField(max_length=150,)  #gadget name
    category = serializers.CharField(max_length=150, )  #brand new / premium used
    type = serializers.CharField(max_length=150)  #phone, laptop, accesorries, tablet
    description = serializers.JSONField()  #proper json field
    
    device_colors = serializers.ListField(
        child=serializers.CharField()
    ) 
    #json field that holds an array
    image_list = serializers.ListField(
        child=serializers.CharField()
    ) 
    
    quantity = serializers.IntegerField()  #1 by default
    in_stock = serializers.BooleanField(default=True)
    price = serializers.DecimalField(max_digits=20, decimal_places=2)
    
    
    class Meta:
        model = CartOrder
        fields = "__all__"
        
    def validate(self, data: dict):
        """Validate Cart items or orders entering the system to make sure there is no duplicate"""
        user = self.context['request'].user

        # Check for duplicate cart item
        cart_item = CartOrder.objects.filter(
            user=user,
            name=data.get('name'),
            category=data.get('category'),
        )
        
        if cart_item.exists():
            raise serializers.ValidationError({ 
               "message": "This cart item object already exists for this user."
              },
              code=400
            )

        return data
    
    
#SHIPMENT ORDER SERIALIZER
class ShipmentOrderSerializer(serializers.ModelSerializer):
    # Required Fields
    #EXTRAS IS A JSON FIELD
    shipment_type = serializers.CharField(max_length=150)  #shipment_type
    address = serializers.CharField()  # shipment address
    
    class Meta:
        model = ShipmentOrder
        fields = "__all__"
        
        

#GIFTCARD REDEMPTION SERIALIZER
'''class RedeemGiftCardSerializer(serializers.ModelSerializer):
    code = serializers.CharField()
    amount = serializers.DecimalField(max_digits=10, decimal_places=2,)
    currency = serializers.CharField()  #"USD",
    brand = serializers.CharField()
    card_type = serializers.CharField() #"E-code" | "Physical",
    country = serializers.CharField()  #"US"
    upload_image = serializers.ListField(
        child=serializers.CharField()  #list or array of images
    )
    
    class Meta:
        model = GiftCard
        fields = "__all__"''' 
        
        
class RedeemGiftCardSerializer(serializers.ModelSerializer):
    class Meta:
        model = GiftCard
        fields = ["code", "amount", "currency", "brand", "card_type", "country", "upload_image"]
        # Don't include user in required fields
        extra_kwargs = {"user": {"read_only": True}}

