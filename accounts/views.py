from django.shortcuts import render
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from rest_framework import generics, status
from rest_framework.response import Response
from django.core.mail import send_mail
import random
from .models import CustomUser, OTP
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

# User Registration View
class UserRegistrationView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()

    def create(self, request, *args, **kwargs):
        # Extract user data from request
        username = request.data.get('username')
        password = request.data.get('password')
        email = request.data.get('email')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        middle_name = request.data.get('middle_name')
        date_of_birth = request.data.get('date_of_birth')
        gender = request.data.get('gender')
        contact_number = request.data.get('contact_number')
        hobbies = request.data.get('hobbies')
        address = request.data.get('address')
        language = request.data.get('language')

        # Create the user instance
        user = CustomUser(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            middle_name=middle_name,
            date_of_birth=date_of_birth,
            gender=gender,
            contact_number=contact_number,
            hobbies=hobbies,
            address=address,
            language=language,
        )
        user.set_password(password)  # Hash the password
        user.save()  # Save the user instance

        # Generate and send OTP
        otp_code = random.randint(100000, 999999)
        OTP.objects.create(user=user, otp_code=otp_code)
        send_mail(
            'Your OTP Code',
            f'Your OTP code is {otp_code}',
            'vaibhavsurvase674@gmail.com',  # Replace with your actual email
            [user.email],
            fail_silently=False,
        )

        # Return the user ID and a success message
        return Response({
            'id': user.id,  # User ID
            'message': 'User registered successfully. OTP sent to email.'
        }, status=status.HTTP_201_CREATED)


# OTP Verification View
class VerifyOTPView(APIView):
    def post(self, request, *args, **kwargs):
        otp_code = request.data.get('otp_code')
        user_id = request.data.get('user_id')

        try:
            otp = OTP.objects.get(user_id=user_id, otp_code=otp_code)
            if not otp.is_verified:
                otp.is_verified = True
                otp.save()
                return Response({"message": "OTP verified successfully."}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "OTP is already verified."}, status=status.HTTP_400_BAD_REQUEST)
        except OTP.DoesNotExist:
            return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)


# User Login View
class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        print(f"Attempting to log in with username: {username}")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access = str(refresh.access_token)

            return Response({
                'message': 'Login successful!',
                'refresh': str(refresh),
                'access': access,
            }, status=status.HTTP_200_OK)
        else:
            print("Authentication failed: Invalid credentials.")
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


# User Logout View
def logout_view(request):
    logout(request)
    return JsonResponse({'message': 'Logout successful'}, status=200)


# Home/Dashboard View
@login_required
def dashboard_view(request):
    return render(request, 'dashboard.html')


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import CustomUser

@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def profile_view(request):
    user = request.user
    
    if request.method == 'GET':
        # Return the user's profile data
        user_data = {
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'contact_number': user.contact_number,
            'hobbies': user.hobbies,
            'address': user.address,
        }
        return Response(user_data)

    elif request.method == 'PUT':
        # Update user's profile
        data = request.data
        user.first_name = data.get('first_name', user.first_name)
        user.last_name = data.get('last_name', user.last_name)
        user.contact_number = data.get('contact_number', user.contact_number)
        user.hobbies = data.get('hobbies', user.hobbies)
        user.address = data.get('address', user.address)
        user.save()

        return Response({"success": "Profile updated successfully"})



# User Settings View
@login_required
def settings_view(request):
    context = {
        'user': request.user,
    }
    return render(request, 'settings.html', context)


from django.shortcuts import render
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from rest_framework import generics, status
from rest_framework.response import Response
from django.core.mail import send_mail
import random
from .models import CustomUser, OTP
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

# Password Reset Request View
class PasswordResetRequestView(APIView):
    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        
        try:
            user = CustomUser.objects.get(username=username, email=email)
            # Generate and send OTP
            otp_code = random.randint(100000, 999999)
            # Create or update OTP object, resetting is_verified to False
            OTP.objects.update_or_create(user=user, defaults={'otp_code': otp_code, 'is_verified': False})
            send_mail(
                'Your OTP Code',
                f'Your OTP code is {otp_code}',
                'vaibhavsurvase674@gmail.com',  # Replace with your actual email
                [user.email],
                fail_silently=False,
            )
            return Response({'message': 'OTP sent to your email.'}, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Password Reset View
class PasswordResetView(APIView):
    def post(self, request):
        username = request.data.get('username')
        otp_code = request.data.get('otp_code')
        new_password = request.data.get('new_password')
        
        try:
            # Fetch the user based on the username
            user = CustomUser.objects.get(username=username)
            # Check for the OTP and make sure it's not verified yet
            otp = OTP.objects.get(user=user, otp_code=otp_code, is_verified=False)

            # Mark OTP as verified
            otp.is_verified = True
            otp.save()

            # Update the user's password
            user.set_password(new_password)  # Hash the new password
            user.save()

            # Optionally delete OTP after it's verified and used
            otp.delete()

            return Response({'message': 'Password reset successful.'}, status=status.HTTP_200_OK)
                
        except OTP.DoesNotExist:
            return Response({'error': 'Invalid or unverified OTP.'}, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

from django.http import HttpResponse
from django.contrib.auth.models import User
from django.views import View
from django.shortcuts import get_object_or_404
from .models import Product, Cart, PurchaseHistory
from PIL import Image, ImageDraw, ImageFont
import io

# List all products (without serializers)
class ProductListView(View):
    def get(self, request):
        products = Product.objects.all()
        product_list = []
        for product in products:
            product_list.append({
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'price': product.price,
                'image': product.image.url if product.image else None
            })
        return JsonResponse(product_list, safe=False)

# Add product to cart (without serializers)
class AddToCartView(View):
    def post(self, request):
        user = request.user
        product_id = request.POST.get('product_id')
        quantity = request.POST.get('quantity', 1)
        product = get_object_or_404(Product, id=product_id)
        
        # Create or update cart item
        cart_item, created = Cart.objects.get_or_create(user=user, product=product)
        cart_item.quantity = quantity
        cart_item.save()
        return JsonResponse({'message': 'Product added to cart.'})

# Remove product from cart (without serializers)
class RemoveFromCartView(View):
    def delete(self, request, pk):
        user = request.user
        cart_item = get_object_or_404(Cart, id=pk, user=user)
        cart_item.delete()
        return JsonResponse({'message': 'Product removed from cart.'})

# List cart items (without serializers)
class CartListView(View):
    def get(self, request):
        user = request.user
        cart_items = Cart.objects.filter(user=user)
        cart_list = []
        for item in cart_items:
            cart_list.append({
                'id': item.id,
                'product': {
                    'id': item.product.id,
                    'name': item.product.name,
                    'price': item.product.price
                },
                'quantity': item.quantity
            })
        return JsonResponse(cart_list, safe=False)

# Handle purchase and generate PDF receipt (without serializers)
class PurchaseView(View):
    def post(self, request):
        user = request.user
        cart_items = Cart.objects.filter(user=user)
        total_price = sum(item.product.price * item.quantity for item in cart_items)

        # Save purchase history
        for item in cart_items:
            PurchaseHistory.objects.create(user=user, product=item.product, quantity=item.quantity)
        
        # Clear cart after purchase
        cart_items.delete()

        # Generate an image receipt
        img = Image.new('RGB', (800, 600), color=(255, 255, 255))  # Create a blank white image
        d = ImageDraw.Draw(img)

        # Load a font
        try:
            font = ImageFont.truetype("arial.ttf", 20)  # You can use any font available on your system
        except IOError:
            font = ImageFont.load_default()  # Fallback to default font if not available

        # Write product details on the image
        d.text((10, 10), "Purchase Receipt", fill=(0, 0, 0), font=font)
        y_offset = 50
        for item in cart_items:
            product_info = f"{item.product.name} - Quantity: {item.quantity} - Price: ₹{item.product.price}"
            d.text((10, y_offset), product_info, fill=(0, 0, 0), font=font)
            y_offset += 30

        # Write the total price on the image
        d.text((10, y_offset + 20), f"Total Price: ₹{total_price}", fill=(0, 0, 0), font=font)

        # Convert the image to bytes and return it as a response
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='PNG')
        img_byte_arr.seek(0)

        response = HttpResponse(img_byte_arr, content_type='image/png')
        response['Content-Disposition'] = 'attachment; filename="receipt.png"'
        return response


# List purchase history (without serializers)
class PurchaseHistoryView(View):
    def get(self, request):
        user = request.user
        purchases = PurchaseHistory.objects.filter(user=user)
        history_list = []
        for purchase in purchases:
            history_list.append({
                'id': purchase.id,
                'product': {
                    'id': purchase.product.id,
                    'name': purchase.product.name
                },
                'quantity': purchase.quantity,
                'purchase_date': purchase.purchase_date.strftime('%Y-%m-%d %H:%M:%S')
            })
        return JsonResponse(history_list, safe=False)


# views.py
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def check_superuser_status(request):
    is_superuser = request.user.is_superuser
    return Response({'is_superuser': is_superuser})


# views.py
from django.shortcuts import render
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from .models import Product

# class AddProductView(APIView):
#     permission_classes = [IsAuthenticated]  # Only authenticated users can add a product

#     def post(self, request, *args, **kwargs):
#         # Ensure the user is a superuser (admin)
#         if not request.user.is_superuser:
#             return JsonResponse({'error': 'You do not have permission to add a product.'}, status=403)

#         # Extract product data from the request
#         product_name = request.data.get('name')
#         description = request.data.get('description')
#         price = request.data.get('price')
#         image = request.data.get('image')  # Assuming the image comes as base64 or file field

#         # Validate the input data
#         if not product_name or not price or not description:
#             return JsonResponse({'error': 'Missing required fields.'}, status=400)

#         try:
#             price = float(price)
#         except ValueError:
#             return JsonResponse({'error': 'Invalid price format.'}, status=400)

#         # Create the product
#         product = Product.objects.create(
#             name=product_name,
#             description=description,
#             price=price,
#             image=image
#         )

#         # Return success response with product data
#         return JsonResponse({
#             'message': 'Product added successfully!',
#             'product': {
#                 'id': product.id,
#                 'name': product.name,
#                 'description': product.description,
#                 'price': product.price,
#                 'image': product.image.url if product.image else None
#             }
#         }, status=201)

from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from .models import Product
from django.core.files.storage import default_storage
import os

# class AddProductView(APIView):
#     permission_classes = [IsAuthenticated]  # Only authenticated users can add a product

#     def post(self, request, *args, **kwargs):
#         # Ensure the user is a superuser (admin)
#         if not request.user.is_superuser:
#             return JsonResponse({'error': 'You do not have permission to add a product.'}, status=403)

#         # Extract product data from the request
#         product_name = request.data.get('name')
#         description = request.data.get('description')
#         price = request.data.get('price')
#         image = request.FILES.get('image')  # Using FILES to get the image as a file

#         # Validate the input data
#         if not product_name or not price or not description:
#             return JsonResponse({'error': 'Missing required fields.'}, status=400)

#         # Validate the price
#         try:
#             price = float(price)
#         except ValueError:
#             return JsonResponse({'error': 'Invalid price format.'}, status=400)

#         # Handle the image file
#         image_path = None
#         if image:
#             # Save the image to the media folder (default_storage will handle this)
#             image_path = f"products/{image.name}"
#             file_path = default_storage.save(image_path, image)  # Save the file using default storage

#         # Create the product
#         product = Product.objects.create(
#             name=product_name,
#             description=description,
#             price=price,
#             image=image_path  # Store only the image path
#         )

#         # Return success response with product data
#         return JsonResponse({
#             'message': 'Product added successfully!',
#             'product': {
#                 'id': product.id,
#                 'name': product.name,
#                 'description': product.description,
#                 'price': product.price,
#                 'image': product.image if product.image else None  # Image path is returned
#             }
#         }, status=201)
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.core.files.storage import default_storage
from django.conf import settings
from .models import Product
from django.core.exceptions import ValidationError

class AddProductView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        # Extract product data
        product_name = request.data.get('name')
        description = request.data.get('description')
        price = request.data.get('price')
        image = request.FILES.get('image')

        # Validate input
        if not product_name or not price or not description:
            return JsonResponse({'error': 'Missing required fields.'}, status=400)

        # Validate price
        try:
            price = float(price)
            if price <= 0:
                return JsonResponse({'error': 'Price must be a positive number.'}, status=400)
        except ValueError:
            return JsonResponse({'error': 'Invalid price format.'}, status=400)

        # Handle the image file
        image_path = None
        if image:
            try:
                image_path = f"products/{image.name}"
                default_storage.save(image_path, image)
            except Exception as e:
                return JsonResponse({'error': f'Error saving image: {str(e)}'}, status=500)

        # Create the product
        try:
            product = Product.objects.create(
                name=product_name,
                description=description,
                price=price,
                image=image_path
            )
        except ValidationError as e:
            return JsonResponse({'error': f'Error creating product: {str(e)}'}, status=400)

        # Return response
        image_url = request.build_absolute_uri(f'{settings.MEDIA_URL}{product.image}') if product.image else None

        return JsonResponse({
            'message': 'Product added successfully!',
            'product': {
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'price': product.price,
                'image': image_url
            }
        }, status=201)


# views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Product

# class GetProductView(APIView):
#     permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access product info

#     def get(self, request, *args, **kwargs):
#         # Fetch product ID from URL
#         product_id = kwargs.get('product_id')
        
#         try:
#             product = Product.objects.get(id=product_id)  # Get the product by ID
#         except Product.DoesNotExist:
#             return Response({'error': 'Product not found'}, status=404)
        
#         # Serialize product data manually (if you're not using serializers)
#         product_data = {
#             'id': product.id,
#             'name': product.name,
#             'description': product.description,
#             'price': product.price,
#             'image': product.image.url if product.image else None,
#         }

#         return Response({'product': product_data})

from django.conf import settings
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from .models import Product

class GetProductView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        # Fetch product ID from URL
        product_id = kwargs.get('product_id')

        try:
            # Get the product by ID
            product = Product.objects.get(id=product_id)
        except Product.DoesNotExist:
            return Response({'error': 'Product not found'}, status=404)

        # Construct the absolute image URL
        image_url = f'{settings.MEDIA_URL}+str{product.image}' if product.image else None


        # Prepare product data
        product_data = {
            'id': product.id,
            'name': product.name,
            'description': product.description,
            'price': product.price,
            'image': image_url,  # Full image URL for the frontend
        }

        return Response({'product': product_data}, status=200)


from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated
from .models import Product

class ProductUpdateView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def put(self, request, product_id):
        """
        Handle product update by passing product id in the URL.
        """
        product = get_object_or_404(Product, id=product_id)
        
        # Validate and get product data from request
        name = request.data.get('name', None)
        description = request.data.get('description', None)
        price = request.data.get('price', None)
        
        if not name or not description or not price:
            return Response({'error': 'Name, description, and price are required.'}, status=400)
        
        # Update product details
        product.name = name
        product.description = description
        product.price = price
        
        # Check if an image was uploaded and update it
        if 'image' in request.FILES:
            product.image = request.FILES['image']
        
        product.save()

        return Response({
            'message': 'Product updated successfully.',
            'product': {
                'name': product.name,
                'description': product.description,
                'price': product.price,
                'image': product.image.url if product.image else None
            }
        })


from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import Product

class ProductDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, product_id):
        """
        Handle product deletion by passing product id in the URL.
        """
        # Fetch the product by product_id passed in the URL
        product = get_object_or_404(Product, id=product_id)
        product.delete()
        
        return Response({
            'message': 'Product deleted successfully.'
        }, status=status.HTTP_204_NO_CONTENT)