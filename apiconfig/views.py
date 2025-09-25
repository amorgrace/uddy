from django.shortcuts import render
from rest_framework import viewsets, permissions
from .utils import update_order_status
from .models import Product, Cart, CartItem, Order, OrderItem, Payment
from .serializers import *
from .pagination import ProductPagination
from django.http import JsonResponse
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from decimal import Decimal
from rest_framework.permissions import IsAuthenticated, AllowAny 
import requests, json
from drf_yasg import openapi
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from drf_yasg.utils import swagger_auto_schema
from django.db.models import Count
from rest_framework.generics import ListAPIView
from drf_yasg import openapi
import uuid
from django.utils.decorators import method_decorator
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
import logging

logger = logging.getLogger(__name__)
User = get_user_model()
ACCESS_MAX_AGE  = int(settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds())
REFRESH_MAX_AGE = int(settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds())


class CookieTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        base_response = super().post(request, *args, **kwargs)

        if base_response.status_code != 200:
            return base_response

        data = base_response.data
        user_agent = request.META.get("HTTP_USER_AGENT", "")

        # Mobile → return tokens in response body (to store in localStorage/secure storage)
        if any(x in user_agent for x in ("Mobile", "iPhone", "Android")):
            return Response({
                "access": data["access"],
                "refresh": data["refresh"],
                "detail": "Tokens provided for mobile use",
            })

        # Desktop/Web → set HttpOnly cookies
        response = Response({"detail": "Login successful"})
        response.set_cookie(
            "access", data["access"],
            httponly=True, secure=True, samesite="None", path="/",
            max_age=ACCESS_MAX_AGE
        )
        response.set_cookie(
            "refresh", data["refresh"],
            httponly=True, secure=True, samesite="None", path="/",
            max_age=REFRESH_MAX_AGE
        )
        return response
    

class CookieTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        user_agent = request.META.get("HTTP_USER_AGENT", "")

        # ---- Mobile clients ----
        if any(x in user_agent for x in ("Mobile", "iPhone", "Android")):
            # Standard SimpleJWT behaviour
            return super().post(request, *args, **kwargs)

        # ---- Web clients ----
        refresh_cookie = request.COOKIES.get("refresh")
        if not refresh_cookie:
            return Response({"detail": "Refresh cookie missing"}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            new_access  = RefreshToken(refresh_cookie).access_token
            new_refresh = str(RefreshToken(refresh_cookie))
        except Exception:
            return Response({"detail": "Invalid refresh token"}, status=status.HTTP_401_UNAUTHORIZED)

        response = Response({"detail": "Token refreshed"})
        response.set_cookie(
            "access", str(new_access),
            httponly=True, secure=True, samesite="None", path="/",
            max_age=ACCESS_MAX_AGE,
        )
        response.set_cookie(
            "refresh", new_refresh,
            httponly=True, secure=True, samesite="None", path="/",
            max_age=REFRESH_MAX_AGE,
        )
        return response
    

class CookieLogoutView(APIView):
    def post(self, request):
        user_agent = request.META.get("HTTP_USER_AGENT", "")

        # Mobile clients using header tokens don’t need cookie cleanup
        if any(x in user_agent for x in ("Mobile", "iPhone", "Android")):
            return Response({"detail": "Logged out (mobile token client)"},
                            status=status.HTTP_200_OK)

        refresh_cookie = request.COOKIES.get("refresh")
        if refresh_cookie:
            try:
                RefreshToken(refresh_cookie).blacklist()
            except Exception as exc:
                logger.warning("Logout blacklist failed: %s", exc)

        response = Response({"detail": "Successfully logged out!"})
        response.delete_cookie("access", path="/")
        response.delete_cookie("refresh", path="/")
        return response
class UserCreateView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserCreateSerializer
    permission_classes = [permissions.AllowAny]

    def perform_create(self, serializer):
        serializer.save(password=make_password(serializer.validated_data["password"]))

class GetUserView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        if not user or not user.is_authenticated:
            return Response(
                {"detail": "User not found or not authenticated"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all().order_by('-created_at')
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    pagination_class = ProductPagination


class CategorySummaryView(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        data = (
            Product.objects.values("category")
            .annotate(total_products=Count("id"))
            .order_by("category")
        )
        return Response(data)
    
class ProductByCategoryView(ListAPIView):
    serializer_class = ProductSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        category = self.kwargs['category']
        return Product.objects.filter(category__iexact=category)
    

# -------- CART --------
class CartView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(responses={200: CartSerializer()})
    def get(self, request):
        cart, _ = Cart.objects.get_or_create(user=request.user)
        return Response(CartSerializer(cart).data)

    @swagger_auto_schema(request_body=CartAddSerializer, responses={201: CartSerializer()})
    def post(self, request):
        serializer = CartAddSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        product_id = serializer.validated_data["product_id"]
        quantity = serializer.validated_data["quantity"]

        product = get_object_or_404(Product, id=product_id)
        cart, _ = Cart.objects.get_or_create(user=request.user)

        cart_item, created = CartItem.objects.get_or_create(cart=cart, product=product)
        cart_item.quantity = cart_item.quantity + quantity if not created else quantity
        cart_item.save()

        return Response(CartSerializer(cart).data, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(request_body=CartAddSerializer, responses={200: CartSerializer()})
    def delete(self, request):
        serializer = CartAddSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        product_id = serializer.validated_data["product_id"]

        cart = Cart.objects.filter(user=request.user).order_by("-created_at").first()
        if not cart:
            return Response({}, status=status.HTTP_200_OK)

        CartItem.objects.filter(cart=cart, product_id=product_id).delete()

        if not cart.items.exists():
            cart.delete()
            return Response({"detail": "Cart deleted"}, status=status.HTTP_204_NO_CONTENT)

        return Response(CartSerializer(cart).data, status=status.HTTP_200_OK)
    
    def patch(self, request):
        serializer = CartAddSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        product_id = serializer.validated_data["product_id"]
        quantity   = serializer.validated_data["quantity"]

        cart = Cart.objects.filter(user=request.user).order_by("-created_at").first()
        if not cart:
            return Response({"detail": "No cart"}, status=status.HTTP_404_NOT_FOUND)

        item = CartItem.objects.filter(cart=cart, product_id=product_id).first()
        if not item:
            return Response({"detail": "Item not found"}, status=status.HTTP_404_NOT_FOUND)

        item.quantity = quantity
        item.save(update_fields=["quantity"])
        return Response(CartSerializer(cart).data, status=status.HTTP_200_OK)





# -------- CHECKOUT --------
class CheckoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        cart, _ = Cart.objects.get_or_create(user=request.user)
        if not cart.items.exists():
            return Response({"error": "Cart is empty"}, status=400)

        total_amount = Decimal(cart.total_amount)
        order = Order.objects.create(
            user=request.user,
            total_amount=total_amount,
            reference=str(uuid.uuid4())
        )

        for item in cart.items.all():
            OrderItem.objects.create(
                order=order,
                product=item.product,
                quantity=item.quantity,
                price=item.product.price
            )

        cart.items.all().delete()

        base_url = settings.KORA_BASE_URL.strip().rstrip("/")
        url = f"{base_url}/charges/initialize"

        headers = {
            "Authorization": f"Bearer {settings.KORA_SECRET_KEY}",
            "Content-Type": "application/json",
        }

        redirect = "https://uddy-rho.vercel.app/payment-status"

        payload = {
            "amount": str(order.total_amount),
            "currency": "NGN",
            "customer": {"email": request.user.email},
            "reference": order.reference,
            "redirect_url": redirect
        }

        try:
            r = requests.post(url, json=payload, headers=headers)
            response_data = r.json()
        except Exception as e:
            return Response({"error": "Request failed", "details": str(e)}, status=500)

        if not response_data.get("status"):
            return Response(
                {"error": "Payment initialization failed", "details": response_data},
                status=400,
            )

        Payment.objects.create(
            order=order,
            amount=order.total_amount,
            transaction_id=response_data.get("data", {}).get("id"),
            status="pending",
        )

        return Response({
            "checkout_url": response_data.get("data", {}).get("checkout_url"),
            "order_id": order.id,
            "reference": order.reference,
        })


class VerifyPaymentView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, reference):
        # Call Kora's verify API first
        resp = requests.get(
            f"{settings.KORA_BASE_URL}/charges/{reference}",
            headers={"Authorization": f"Bearer {settings.KORA_SECRET_KEY}"},
            timeout=10
        )
        result = resp.json()
        kora_status = result["data"]["status"]
        update_order_status(reference, kora_status)
        return Response(result)


class OrderListView(generics.ListAPIView):
    serializer_class = OrderSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Order.objects.filter(user=self.request.user)


class OrderDetailView(generics.RetrieveAPIView):
    serializer_class = OrderSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Order.objects.filter(user=self.request.user)


# -------- WEBHOOK --------
@csrf_exempt
def kora_webhook(request):
    payload = json.loads(request.body)
    data = payload.get("data", payload)  # handle wrapper if any
    update_order_status(
        reference=data.get("reference"),
        kora_status=data.get("status"),
    )
    return JsonResponse({"status": "ok"})
