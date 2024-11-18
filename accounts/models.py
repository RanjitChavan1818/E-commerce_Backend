from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models

class CustomUser(AbstractUser):
    middle_name = models.CharField(max_length=30, blank=True, null=True)
    date_of_birth = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=10, choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')],null=True, blank=True)
    contact_number = models.CharField(max_length=15, null=True, blank=True)
    hobbies = models.TextField(blank=True, null=True)
    address = models.TextField(null=True, blank=True)
    document_upload = models.FileField(upload_to='documents/', null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    language = models.CharField(max_length=20, blank=True, null=True)
    is_owner = models.BooleanField(default=False)
    # Adding related_name to avoid clashes
    groups = models.ManyToManyField(Group, related_name='customuser_set', blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name='customuser_set', blank=True)

    def _str_(self):
        return self.username


# OTP Model
class OTP(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    otp_code = models.IntegerField()
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def _str_(self):
        return f"OTP for {self.user.username} - Code: {self.otp_code}"

from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class Product(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    image = models.ImageField(upload_to='products/', null=True, blank=True)


    # # image = models.ImageField(upload_to='products/')
    # Add the image field for the product image
    

    def _str_(self):
        return self.name

class Cart(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='cart')
    created_at = models.DateTimeField(auto_now_add=True)

    def _str_(self):
        return f"Cart of {self.user.username}"

class CartItem(models.Model):
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)

    def _str_(self):
        return f"{self.quantity} x {self.product.name} in {self.cart.user.username}'s cart"

    @property
    def total_price(self):
        return self.quantity * self.product.price

class PurchaseHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='purchase_history')
    product = models.ForeignKey(Product, on_delete=models.SET_NULL, null=True)
    quantity = models.PositiveIntegerField()
    purchased_at = models.DateTimeField(auto_now_add=True)

    def _str_(self):
        return f"{self.user.username} purchased {self.quantity} of {self.product.name}"