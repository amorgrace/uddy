from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings


class User(AbstractUser):
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    fullname = models.CharField(max_length=200)
    country = models.CharField(max_length=200)
    email = models.EmailField(max_length=200, unique=True,)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

class Product(models.Model):

    CATEGORY_CHOICE = [
        ('cloths', 'Cloths'),
        ('bags', 'Bags'),
        ('footwears', 'Footwears'),
        ('assessories', 'Assessories'),
    ]
    # user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    category = models.CharField(max_length=200, choices=CATEGORY_CHOICE)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    stock = models.PositiveIntegerField(default=0)
    image_url = models.URLField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

class Order(models.Model):
    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        PAID = "PAID", "Paid"
        FAILED = "FAILED", "Failed"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="orders")
    total_price = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.PENDING)
    stripe_payment_intent = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Order #{self.id} — {self.user} — {self.status}"
    
    
class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="items")
    product = models.ForeignKey(Product, on_delete=models.PROTECT)
    quantity = models.PositiveIntegerField()
    price_at_purchase = models.DecimalField(max_digits=10, decimal_places=2)

    def subtotal(self):
        return self.price_at_purchase * self.quantity