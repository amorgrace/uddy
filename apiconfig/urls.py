from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import (
    ProductViewSet, 
    CookieTokenObtainPairView, 
    CookieTokenRefreshView, 
    CookieLogoutView, 
    CategorySummaryView, 
    ProductByCategoryView, 
    CartView, 
    CheckoutView,
    VerifyPaymentView,
    kora_webhook
)
router = DefaultRouter()

urlpatterns = [
    path("auth/jwt/create/", CookieTokenObtainPairView.as_view(), name="jwt-create"),
    path("auth/jwt/refresh/", CookieTokenRefreshView.as_view(), name="jwt-refresh"),
    path("auth/jwt/logout/", CookieLogoutView.as_view(), name="jwt-logout"),

    path("categories/", CategorySummaryView.as_view(), name="category-summary"),
    path("categories/<str:category>/", ProductByCategoryView.as_view(), name="products-by-category"),

    path('cart/', CartView.as_view(), name='cart'),
    path('checkout/', CheckoutView.as_view(), name='checkout'),
    path("webhook/kora/", kora_webhook, name="kora-webhook"),
    path("verify-payment/<str:reference>/", VerifyPaymentView.as_view(), name="verify-payment")
    
]

router.register(r'products', ProductViewSet, basename='product')
urlpatterns += router.urls

{
  "email": "akan@gmail.com",
  "password": "amorgrace35"
}