from django.shortcuts import render
from rest_framework import viewsets, permissions
from .utils import update_order_status
from .models import Product, Cart, CartItem, Order, OrderItem, Payment
from .serializers import (
    CartSerializer,
    CartAddSerializer,
    OrderSerializer,
    ProductSerializer,

)
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

class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == status.HTTP_200_OK:
            data = response.data
            access_token = data.get("access")
            refresh_token = data.get("refresh")

            # Remove tokens from response body if you want
            # response.data.pop("access", None)
            # response.data.pop("refresh", None)

            response.set_cookie(
                key="access",
                value=access_token,
                httponly=True,
                secure=True,     
                samesite="None",
                max_age=300,
            )
            response.set_cookie(
                key="refresh",
                value=refresh_token,
                httponly=True,
                secure=True,
                samesite="None",
                max_age=86400,
            )
        return response

class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get("refresh")

        if not refresh_token:
            return Response({"detail": "Refresh token not found in cookies"}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            token = RefreshToken(refresh_token)
            access_token = str(token.access_token)

            response = Response({"detail": "Token refreshed"}, status=status.HTTP_200_OK)

            response.set_cookie(
                key="access",
                value=access_token,
                httponly=True,
                secure=True,
                samesite="Lax",
                max_age=300,  
            )
            return response

        except Exception:
            return Response({"detail": "Invalid refresh token"}, status=status.HTTP_401_UNAUTHORIZED)


class CustomTokenLogoutView(APIView):
    def post(self, request, *args, **kwargs):
        response = Response({"detail": "Logged out successfully"}, status=status.HTTP_200_OK)

        response.delete_cookie("access")
        response.delete_cookie("refresh")

        return response

class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all().order_by('-created_at')
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]


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

    @swagger_auto_schema(
        responses={200: CartSerializer()}
    )
    def get(self, request):
        cart, _ = Cart.objects.get_or_create(user=request.user)
        serializer = CartSerializer(cart)
        return Response(serializer.data)

    @swagger_auto_schema(
        request_body=CartAddSerializer,
        responses={201: CartSerializer()}
    )
    def post(self, request):
        serializer = CartAddSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        product_id = serializer.validated_data["product_id"]
        quantity = serializer.validated_data["quantity"]

        product = get_object_or_404(Product, id=product_id)
        cart, _ = Cart.objects.get_or_create(user=request.user)

        cart_item, created = CartItem.objects.get_or_create(cart=cart, product=product)
        if created:
            cart_item.quantity = quantity
        else:
            cart_item.quantity += quantity
        cart_item.save()

        cart_serializer = CartSerializer(cart)
        return Response(cart_serializer.data, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(
        request_body=CartAddSerializer,   # 👈 same input as POST
        responses={200: CartSerializer()}
    )
    def delete(self, request):
        serializer = CartAddSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        product_id = serializer.validated_data["product_id"]

        cart = get_object_or_404(Cart, user=request.user)
        cart_item = CartItem.objects.filter(cart=cart, product_id=product_id).first()

        if not cart_item:
            return Response({"error": "Item not found in cart"}, status=status.HTTP_404_NOT_FOUND)

        cart_item.delete()
        cart_serializer = CartSerializer(cart)
        return Response(cart_serializer.data, status=status.HTTP_200_OK)



# -------- CHECKOUT --------
class CheckoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        cart, _ = Cart.objects.get_or_create(user=request.user)
        if not cart.items.exists():
            return Response({"error": "Cart is empty"}, status=400)

        total_amount = Decimal(cart.total_amount())
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


        # Clean base URL to avoid trailing slashes/newlines
        base_url = settings.KORA_BASE_URL.strip().rstrip("/")
        url = f"{base_url}/charges/initialize"

        headers = {
            "Authorization": f"Bearer {settings.KORA_SECRET_KEY}",
            "Content-Type": "application/json",
        }

        if settings.DEBUG:
            redirect = "http://localhost:5173/payment-status"
        else:
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


# class VerifyPaymentView(APIView):
#     def get(self, request, reference):
#         try:
#             headers = {
#                 "Authorization": f"Bearer {settings.KORA_SECRET_KEY}",
#                 "Content-Type": "application/json"
#             }

#             response = requests.get(
#                 f"{settings.KORA_BASE_URL}/charges/{reference}",
#                 headers=headers
#             )
#             res_data = response.json()

#             if response.status_code != 200 or not res_data.get("status"):
#                 return Response(
#                     {"error": "Payment verification failed", "details": res_data},
#                     status=status.HTTP_400_BAD_REQUEST
#                 )

#             payment_status = res_data["data"]["status"]  # e.g. "success", "failed", "pending"

#             try:
#                 order = Order.objects.get(reference=reference)
#                 order.status = payment_status
#                 order.save()
#             except Order.DoesNotExist:
#                 pass

#             return Response({"status": payment_status, "reference": reference, "details": res_data})

#         except Exception as e:
#             return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




# -------- ORDERS --------
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
# @csrf_exempt
# def kora_webhook(request):
#     data = json.loads(request.body)
#     reference = data.get("reference")
#     status = data.get("status")

#     try:
#         order = Order.objects.get(reference=reference)
#     except Order.DoesNotExist:
#         return JsonResponse({"error": "Order not found"}, status=404)

#     payment = order.payment

#     if status == "success":
#         order.status = "paid"
#         payment.status = "confirmed"
#     elif status == "pending":
#         order.status = "pending"
#         payment.status = "pending"
#     else:
#         order.status = "failed"
#         payment.status = "failed"

#     order.save()
#     payment.save()

#     return JsonResponse({"status": "ok"})

