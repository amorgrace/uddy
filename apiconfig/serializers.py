from djoser.serializers import UserCreateSerializer as BaseUserCreateSerializer
from djoser.serializers import UserSerializer as BaseUserSerializer
from django.contrib.auth import get_user_model
from rest_framework import serializers
from django.utils.timesince import timesince
from .models import Product, Order, OrderItem

User = get_user_model()

class UserCreateSerializer(BaseUserCreateSerializer):
    confirm_password = serializers.CharField(write_only=True)
    class Meta:
        model = User
        fields = (
          'username','fullname', 'email', 'phone_number', 'country', 'password', 'confirm_password'
        )
    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "passwords do not match!"})
        attrs.pop('confirm_password')
        return attrs
    
class UserSerializer(BaseUserSerializer):
    class Meta(BaseUserSerializer.Meta):
        model = User
        fields = ('id', 'email', 'username', 'fullname', 'country', 'phone_number')
        
class ProductSerializers(serializers.ModelSerializer):
    time_ago = serializers.SerializerMethodField()
    
    class Meta:
        model = Product
        fields = ['id', 'title', 'category', 'price', 'image_url', 'created_at', 'time_ago']
    
    def get_time_ago(self, obj):
        return f"{timesince(obj.created_at)} ago"
    
# ---- Write (input) serializers ----
class CartItemInputSerializer(serializers.Serializer):
    product_id = serializers.IntegerField(min_value=1)
    quantity = serializers.IntegerField(min_value=1)


class CheckoutPreviewSerializer(serializers.Serializer):
    cart = serializers.ListField(
        child=CartItemInputSerializer()
    )


class CheckoutInitiateSerializer(serializers.Serializer):
    cart = serializers.ListField(
        child=CartItemInputSerializer()
    )


class CheckoutConfirmSerializer(serializers.Serializer):
    order_id = serializers.IntegerField(min_value=1)


# ---- Read (output) serializers ----
class ProductMiniSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ["id", "title", "price"]


class OrderItemReadSerializer(serializers.ModelSerializer):
    product = ProductMiniSerializer()

    class Meta:
        model = OrderItem
        fields = ["product", "quantity", "price_at_purchase"]


class OrderReadSerializer(serializers.ModelSerializer):
    items = OrderItemReadSerializer(many=True)

    class Meta:
        model = Order
        fields = ["id", "status", "total_price", "stripe_payment_intent", "created_at", "items"]