from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import ProductViewSet, CustomTokenObtainPairView, CustomTokenRefreshView, CustomTokenLogoutView, CheckoutPreviewView, CheckoutConfirmView, stripe_webhook, CheckoutInitiateView, CategorySummaryView, ProductByCategoryView

router = DefaultRouter()

urlpatterns = [
    path("auth/jwt/create/", CustomTokenObtainPairView.as_view(), name="jwt-create"),
    path("auth/jwt/refresh/", CustomTokenRefreshView.as_view(), name="jwt-refresh"),
    path("auth/jwt/logout/", CustomTokenLogoutView.as_view(), name="jwt-logout"),

    path("categories/", CategorySummaryView.as_view(), name="category-summary"),
    path("categories/<str:category>/", ProductByCategoryView.as_view(), name="products-by-category"),


    path("checkout/preview/",   CheckoutPreviewView.as_view(),   name="checkout-preview"),
    path("checkout/initiate/",  CheckoutInitiateView.as_view(),  name="checkout-initiate"),
    path("checkout/confirm/",   CheckoutConfirmView.as_view(),   name="checkout-confirm"),
    path("stripe/webhook/",     stripe_webhook,                  name="stripe-webhook"),
    
]

router.register(r'products', ProductViewSet, basename='product')
urlpatterns += router.urls


# preview → confirm → payment → payment success callback → order complete page - this is the cart to payment flow

# Backend flow

# Preview step (GET /checkout/preview/)

# Frontend fetches product details, totals, shipping, etc.

# No database writes yet — purely read-only.

# Initiate payment & create order (POST /checkout/initiate/)

# Backend:

# Validates cart

# Creates an order with status="pending"

# Generates a payment session (Stripe, PayPal, etc.)

# Returns payment_url or client secret to frontend.

# Payment (User pays via gateway)

# Payment provider sends webhook → Backend updates order to status="confirmed".

# Or, after successful client-side payment, frontend calls /checkout/confirm/ to finalize.

# Confirmation page (GET /checkout/confirm/?order_id=123)

# Displays order success message, order summary, etc.

# Example

# Frontend flow:

# GET /checkout/preview/ → show summary

# POST /checkout/initiate/ with cart → get payment_url

# Redirect user to payment_url

# After success → redirect to /checkout/confirm/

# Backend:

# /checkout/initiate/ creates the pending order + starts payment.

# Payment webhook (or frontend confirm) updates status to confirmed.








# 1️⃣ /checkout/preview/ (CheckoutPreviewView)

# Purpose: Show the user a summary of their cart before payment.

# Data: Cart items, total cost, shipping info (if any).

# Action: The frontend just displays the data and has a "Proceed to Payment" button that calls /checkout/initiate/.

# 2️⃣ /checkout/initiate/ (CheckoutInitiateView)

# Purpose: Start the payment process.

# What happens here:

# Validate the cart and user info again (prices, stock availability).

# Create a temporary Order record in the DB with status="pending".

# Call the payment gateway API (Paystack, Stripe, etc.) to get a payment link or client secret.

# Return that payment data to the frontend.

# Frontend: Redirect the user to the payment page (gateway’s hosted page or your payment form).

# 3️⃣ /checkout/confirm/ (CheckoutConfirmView)

# Purpose: Verify payment after the user completes payment on the gateway.

# What happens here:

# Payment gateway sends a webhook or the frontend calls this endpoint after payment.

# Check payment status via gateway API.

# If successful, mark the order status="paid" and reduce stock.

# Return order confirmation details.

# Frontend: Show a Thank You / Order Confirmation page only after payment verification.

# This way:

# The user never reaches /checkout/confirm/ without actually paying.

# Payment failures don’t create "paid" orders.

# You have a clean distinction between preview → initiate → confirm.