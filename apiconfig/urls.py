from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import (
    ProductViewSet, 
    CustomTokenObtainPairView, 
    CustomTokenRefreshView, 
    CustomTokenLogoutView, 
    CategorySummaryView, 
    ProductByCategoryView, 
    CartView, 
    CheckoutView,
    kora_webhook
)
router = DefaultRouter()

urlpatterns = [
    path("auth/jwt/create/", CustomTokenObtainPairView.as_view(), name="jwt-create"),
    path("auth/jwt/refresh/", CustomTokenRefreshView.as_view(), name="jwt-refresh"),
    path("auth/jwt/logout/", CustomTokenLogoutView.as_view(), name="jwt-logout"),

    path("categories/", CategorySummaryView.as_view(), name="category-summary"),
    path("categories/<str:category>/", ProductByCategoryView.as_view(), name="products-by-category"),

    path('cart/', CartView.as_view(), name='cart'),
    path('checkout/', CheckoutView.as_view(), name='checkout'),
    path("webhook/kora/", kora_webhook, name="kora-webhook"),
    
]

router.register(r'products', ProductViewSet, basename='product')
urlpatterns += router.urls

{
  "email": "akan@gmail.com",
  "password": "amorgrace35"
}