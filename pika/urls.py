# pika/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework.authtoken import views as drf_auth_views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from pika import views
# Import your ViewSets
from pika.views import (
    BankDetailViewSet,
    CartOrderViewSet,
    CryptoWalletViewSet,
    FiatWalletViewSet,
    GadgetOrderViewSet,
    ProductViewSet,
    ShipmentOrderViewSet,
    UserViewSet,
)


# Initialize DRF router
router = DefaultRouter()
router.register(r'products', ProductViewSet, basename='products')
router.register(r'users', UserViewSet, basename="users")
router.register(r'banks', BankDetailViewSet, basename="banks")
router.register(r'fiat-wallet', FiatWalletViewSet, basename="fiat-wallet")
router.register(r'crypto-wallet', CryptoWalletViewSet, basename="crypto-wallet")
router.register(r'gadget-orders', GadgetOrderViewSet, basename='gadget-orders')
router.register(r'cart-items', CartOrderViewSet, basename='cart-items')
router.register(r'shipment-orders', ShipmentOrderViewSet, basename="shipment-orders")




urlpatterns = [
    
    # Token Authentication (DRF Browsable API)
    path('api/token-auth/', drf_auth_views.obtain_auth_token),

    # JWT Authentication
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Authentication APIs
    path('api/auth/register/', views.UserRegistrationView.as_view(), name='register'),
    path('api/auth/login/', views.UserLoginView.as_view(), name='login'),
    path('api/auth/logout/', views.UserLogoutView.as_view(), name='logout'),
    path('api/auth/password-reset/', views.PasswordResetView.as_view(), name='password-reset'),
    path('api/auth/password-reset/confirm/', views.ConfirmPasswordView.as_view(), name='confirm-password-reset'),
    path("api/auth/update-password/", views.ChangePasswordView.as_view(), name="update-account-password"),
    path('api/auth/users/delete/', views.SoftDeleteUserView.as_view(), name='soft-delete-user'),
    
    # KYC (Mutipart Form Data API)
    path('api/users/update-kyc/', views.UpdateKycView.as_view(), name='update-kyc'),
    
    # Paystack Native APIs
    path('api/fetch-commercial-banks/', views.FetchCommercialBanksView.as_view(), name='fetch-commercial-banks'),
    path('api/resolve-account/', views.ResolveAccountView.as_view(), name='resolve-account'),
    
    # Transfer Pin APIs
    path('api/wallet/transfer-pin/', views.TransferPinView.as_view(), name='transfer-pin'),
    path('api/wallet/panic-pin/', views.PanicPinView.as_view(), name='panic-pin'),
    
    # Transactions  ..
    path('api/wallet/fetch-transfer-recipient/', views.RecipientView.as_view(), name='fetch-bank-transfer-recipient'),
    path('api/wallet/deposit/', views.DepositView.as_view(), name='wallet-deposit'),
    path('api/wallet/transfer/', views.TransferView.as_view(), name='wallet-transfer'),
    path('api/wallet/bank-transfer/', views.BankTransferView.as_view(), name='bank-transfer'),
    path('api/transactions/<str:transaction_id>/report/', views.ReportTransactionView.as_view(), name='report-transaction'),
    path('api/transactions/', views.TransactionListView.as_view(), name='transaction-list'),
    path('api/transactions/<str:pk>/', views.TransactionListView.as_view(), name='transaction-object'),
    
    # Giftcard Transactions (Redemption and Sale) (POST REQUESTS)
    path('api/giftcards/redeem/', views.GiftCardProcessorView.as_view(), name='redeem-giftcard'),
    path('api/giftcards/purchase/', views.GiftCardBuyProcessorView.as_view(), name="buy-giftcard"),
    path('api/giftcards/redeem/webhook/', views.GiftCardVerificationWebhook.as_view(), name='redeem-giftcard-webhook'),
    path('api/giftcards/purchase/webhook/', views.GiftCardPurchaseVerificationWebhook.as_view(), name='purchase-giftcard-webhook'),
    
    # User Rank/Leaderboard api
    path('api/users/leaderboard/', views.LeadershipBoardView.as_view(), name='leaderboard'),
    
    # Email Sending APIs
    path('api/send-email/', views.SendEmailView.as_view(), name='send-email'),
    
    # User Notifications
    path('api/notifications/', views.NotificationListCreateView.as_view(), name='notifications-list-create'), #GET #POST
    path('api/notifications/<str:pk>/', views.NotificationUpdateDestroyView.as_view(), name='notifications-update-delete'), #PUT #PATCH #DELETE
    
    # Include router-generated routes
    path('api/', include(router.urls)),
    
    # Chat Messages
    path('api/all-messages/', views.AllMessagesView.as_view(), name='all-messages'),
]
