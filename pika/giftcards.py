# app/services.py
from decimal import Decimal
import requests
import os



class GiftCardProviderService:

    BASE_URL = "https://api.giftcardprovider.com"
    API_KEY: str = os.getenv("API_KEY", "none")
    
    
    """
    Example service to verify gift card with an external provider.
    """
    @classmethod
    def verify_card(cls, code: str) -> dict:
        try:
            response = requests.post(
                f"{cls.BASE_URL}/verify",
                headers={"Authorization": f"Bearer {cls.API_KEY}"},
                json={"code": code},
                timeout=10
            )

            if response.status_code != 200:
                return {"valid": False, "reason": "Provider error"}

            data = response.json()
            print(data)
            # e.g. {"valid": True, "amount": 100, "currency": "USD", "status": "unused"}
            return data

        except requests.RequestException as e:
            return {"valid": False, "reason": str(e)}
        
        
    """
    Handles exchange rate and brand-specific logic.
    """
    #@staticmethod
    @classmethod
    def get_rate_for_brand(cls, brand: str, from_currency: str, to_currency: str) -> Decimal | None:
        """
        Returns the rate for converting a given brand's value from one currency to another.
        Example:
            Amazon (USD → NGN): 1300
            Steam  (USD → NGN): 1100
        """
        try:
            # Try to find an active rate for the given brand and currency pair
            response = requests.post(
                f"{cls.BASE_URL}/get-rates",
                headers={"Authorization": f"Bearer {cls.API_KEY}"},
                json={
                    "brand": brand,
                    "from_currency": from_currency,
                    "to_currency": to_currency
                },
                timeout=10
            )

            if response.status_code != 200:
                return {"valid": False, "reason": "Provider error"}

            data = response.json()
            print(data)
            # e.g. {"valid": True, "amount": 100, "currency": "USD", "status": "unused"}
            return Decimal(data["rate"])

        except Exception as e:
            # Log this error (important in production)
            print(f"[Rate Lookup Error]: {e}")
            return None
