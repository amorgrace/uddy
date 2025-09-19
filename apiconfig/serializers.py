from djoser.serializers import UserCreateSerializer as BaseUserCreateSerializer
from djoser.serializers import UserSerializer as BaseUserSerializer
from django.contrib.auth import get_user_model
from rest_framework import serializers
from django.utils.timesince import timesince
from .models import Product, Cart, CartItem, Order, OrderItem, Payment

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

class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ["id", "title", "category", "price", "stock", "image_url", "created_at"]


class CartItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    total_price = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)

    class Meta:
        model = CartItem
        fields = ["id", "product", "quantity", "price", "total_price"]

    def to_representation(self, instance):
        # Ensure total_price always uses the property
        ret = super().to_representation(instance)
        ret["total_price"] = instance.total_price
        return ret


class CartSerializer(serializers.ModelSerializer):
    items = CartItemSerializer(many=True, read_only=True)
    total_amount = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)

    class Meta:
        model = Cart
        fields = ["id", "user", "items", "total_amount", "created_at"]

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        ret["total_amount"] = instance.total_amount
        return ret


class CartAddSerializer(serializers.Serializer):
    product_id = serializers.IntegerField()
    quantity = serializers.IntegerField(min_value=1, default=1)

class OrderItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)

    class Meta:
        model = OrderItem
        fields = ["id", "product", "quantity", "price", "total_price"]


class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)

    class Meta:
        model = Order
        fields = ["id", "user", "total_amount", "status", "reference", "items", "created_at"]


class PaymentSerializer(serializers.ModelSerializer):
    order = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Payment
        fields = ["id", "order", "provider", "amount", "status", "transaction_id", "created_at"]
