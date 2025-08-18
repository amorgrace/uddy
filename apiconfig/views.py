from django.shortcuts import render
from rest_framework import viewsets, permissions
from .models import Product, Order, OrderItem
from .serializers import (
    CheckoutPreviewSerializer,
    ProductSerializers,
    CheckoutInitiateSerializer,
    CheckoutConfirmSerializer,
    OrderReadSerializer,
)
from django.http import HttpResponse
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from decimal import Decimal
from rest_framework.permissions import IsAuthenticated
import json
import stripe
from drf_yasg import openapi
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from drf_yasg.utils import swagger_auto_schema




stripe.api_key = settings.STRIPE_SECRET_KEY


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
                samesite="Lax",
                max_age=300,
            )
            response.set_cookie(
                key="refresh",
                value=refresh_token,
                httponly=True,
                secure=True,
                samesite="Lax",
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
    serializer_class = ProductSerializers
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]


def _compute_cart_totals_and_snapshot(cart):
    """
    Given a validated cart (list of {product_id, quantity}), fetch products,
    verify stock, and return (items_preview, total_decimal, products_map).
    """
    items_preview = []
    total = Decimal("0.00")
    products_map = {}

    for item in cart:
        product = get_object_or_404(Product, id=item["product_id"])
        qty = int(item["quantity"])
        if qty > product.stock:
            raise ValueError(f"Insufficient stock for '{product.title}'. Available: {product.stock}")

        subtotal = product.price * qty
        total += subtotal
        items_preview.append({
            "product": {"id": product.id, "title": product.title, "price": product.price},
            "quantity": qty,
            "subtotal": subtotal
        })
        products_map[product.id] = (product, qty)

    return items_preview, total, products_map


class CheckoutPreviewView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        request_body=CheckoutPreviewSerializer,
        responses={200: openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "items": openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_OBJECT)),
                "total": openapi.Schema(type=openapi.TYPE_STRING),
                "currency": openapi.Schema(type=openapi.TYPE_STRING, default="usd"),
            }
        )}
    )
    def post(self, request):
        serializer = CheckoutPreviewSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            items_preview, total, _ = _compute_cart_totals_and_snapshot(serializer.validated_data["cart"])
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            "items": items_preview,
            "total": str(total),
            "currency": "usd"
        }, status=status.HTTP_200_OK)


class CheckoutInitiateView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        request_body=CheckoutInitiateSerializer,
        responses={201: openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "order": openapi.Schema(type=openapi.TYPE_OBJECT),
                "client_secret": openapi.Schema(type=openapi.TYPE_STRING),
            }
        )}
    )
    def post(self, request):
        serializer = CheckoutInitiateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        cart = serializer.validated_data["cart"]

        # Recompute totals from DB prices (source of truth)
        try:
            items_preview, total, products_map = _compute_cart_totals_and_snapshot(cart)
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # Create PaymentIntent (amount in smallest currency unit)
        amount_cents = int((total * 100).quantize(Decimal("1")))
        intent = stripe.PaymentIntent.create(
            amount=amount_cents,
            currency="usd",
            metadata={
                "user_id": str(request.user.id),
                # We also store the order id after we create it (below) for webhook lookup
            }
        )

        # Create pending order with snapshot line items
        order = Order.objects.create(
            user=request.user,
            total_price=total,
            stripe_payment_intent=intent.id,
            status=Order.Status.PENDING,
        )
        for product_id, (product, qty) in products_map.items():
            OrderItem.objects.create(
                order=order,
                product=product,
                quantity=qty,
                price_at_purchase=product.price
            )

        # Update PaymentIntent metadata with order id (handy in webhooks)
        stripe.PaymentIntent.modify(intent.id, metadata={"user_id": str(request.user.id), "order_id": str(order.id)})

        return Response({
            "order": OrderReadSerializer(order).data,
            "client_secret": intent.client_secret,
        }, status=status.HTTP_201_CREATED)


class CheckoutConfirmView(APIView):
    """
    Poll/confirm endpoint the frontend can call AFTER Stripe confirms the payment with client_secret.
    Webhook remains the source of truth; this endpoint just re-checks intent status.
    """
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        request_body=CheckoutConfirmSerializer,
        responses={
            200: openapi.Schema(type=openapi.TYPE_OBJECT),
            400: "Payment not completed",
            404: "Order not found"
        }
    )
    def post(self, request):
        serializer = CheckoutConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        order = get_object_or_404(Order, id=serializer.validated_data["order_id"], user=request.user)

        # Retrieve from Stripe
        intent = stripe.PaymentIntent.retrieve(order.stripe_payment_intent)

        if intent.status == "succeeded":
            # Idempotent: only update once
            if order.status != Order.Status.PAID:
                # Reduce stock (defensive: ensure stock >= qty)
                for item in order.items.select_related("product"):
                    if item.product.stock >= item.quantity:
                        item.product.stock -= item.quantity
                        item.product.save()
                order.status = Order.Status.PAID
                order.save()

            return Response({"message": "Payment confirmed", "order": OrderReadSerializer(order).data}, status=200)

        elif intent.status in ("requires_payment_method", "requires_confirmation", "requires_action", "processing"):
            return Response({"message": f"Payment not completed. Intent status: {intent.status}"}, status=400)

        else:
            # failed/canceled/etc.
            if order.status != Order.Status.PAID:
                order.status = Order.Status.FAILED
                order.save()
            return Response({"message": f"Payment failed (status: {intent.status})"}, status=400)


# --- Stripe Webhook (Authoritative payment confirmation) ---
@csrf_exempt
def stripe_webhook(request):
    """
    Add this endpoint to Stripe Dashboard > Developers > Webhooks.
    Signing secret in settings. Allows Stripe (unauthenticated) to notify us.
    """
    payload = request.body
    sig_header = request.META.get("HTTP_STRIPE_SIGNATURE", "")
    webhook_secret = getattr(settings, "STRIPE_WEBHOOK_SECRET", None)

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except (ValueError, stripe.error.SignatureVerificationError):
        return HttpResponse(status=400)

    if event["type"] == "payment_intent.succeeded":
        intent = event["data"]["object"]
        order_id = intent.get("metadata", {}).get("order_id")
        if order_id:
            try:
                order = Order.objects.select_related("user").prefetch_related("items__product").get(id=order_id)
            except Order.DoesNotExist:
                return HttpResponse(status=200)  # nothing to do

            # Idempotent update
            if order.status != Order.Status.PAID:
                # Reduce stock safely
                for item in order.items.select_related("product"):
                    if item.product.stock >= item.quantity:
                        item.product.stock -= item.quantity
                        item.product.save()
                order.status = Order.Status.PAID
                order.save()

    elif event["type"] in ("payment_intent.payment_failed", "payment_intent.canceled"):
        intent = event["data"]["object"]
        order_id = intent.get("metadata", {}).get("order_id")
        if order_id:
            try:
                order = Order.objects.get(id=order_id)
            except Order.DoesNotExist:
                return HttpResponse(status=200)
            if order.status != Order.Status.PAID:
                order.status = Order.Status.FAILED
                order.save()

    return HttpResponse(status=200)