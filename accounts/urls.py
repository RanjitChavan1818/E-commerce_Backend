# Updated urls.py
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from . import views
from .views import (UserRegistrationView, VerifyOTPView, LoginView, logout_view, dashboard_view, profile_view, settings_view,
ProductListView, AddToCartView, RemoveFromCartView, CartListView, PurchaseView, PurchaseHistoryView, AddProductView, GetProductView,
ProductUpdateView, ProductDeleteView
)

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='user-registration'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', logout_view, name='logout'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('profile/', profile_view, name='profile'),
    path('settings/', settings_view, name='settings'),
    path('add-product/', AddProductView.as_view(), name='add-product'),
    path('get-product/<int:product_id>/', GetProductView.as_view(), name='get-product'),
    path('check-superuser-status/', views.check_superuser_status, name='check_superuser_status'),
    path('products/', ProductListView.as_view(), name='product-list'),
    path('cart/', CartListView.as_view(), name='cart-list'),
    path('cart/add/', AddToCartView.as_view(), name='add-to-cart'),
    path('cart/remove/<int:pk>/', RemoveFromCartView.as_view(), name='remove-from-cart'),
    path('purchase/', PurchaseView.as_view(), name='purchase'),
    path('purchase/history/', PurchaseHistoryView.as_view(), name='purchase-history'),
    path('product/update/<int:product_id>/', ProductUpdateView.as_view(), name='product-update'),
    path('product/delete/<int:product_id>/', ProductDeleteView.as_view(), name='product-delete'),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)