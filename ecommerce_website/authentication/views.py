from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from authentication.models import OTP
from authentication.utils import generate_otp, send_otp_to_users
from datetime import datetime, timedelta
from django.utils.timezone import now, make_aware, is_naive


# Create Account or Signup View
def signup_view(request):
    error = ""
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        
        # Check if the username or email already exists
        if User.objects.filter(username=username).exists():
            error = 'Username already exists. Please choose a different one.'
            return render(request, 'signup.html', {'error': error})
        if User.objects.filter(email=email).exists():
            error = 'Email already exists. Please use a different email.'
            return render(request, 'signup.html', {'error': error})

        # Generate OTP and user detail and save it temporarily in the session
        otp_code = generate_otp()
        request.session['temp_user_data'] = {
            'username': username,
            'email': email,
            'password': password,
            'otp_code': otp_code,
            'otp_timestamp': datetime.now().isoformat()  # Save the timestamp
        }

        # Send OTP to user's email
        title = 'Welcome to Maaiz.com - Verify Your Account'
        message = f"""
        Dear {username},

        Thank you for signing up for Maaiz.com!

        To complete your registration, please verify your email address by entering the OTP (One-Time Password) provided below on the verification page:

        OTP Code: {otp_code}

        This OTP is valid for the next 2 minutes. If you did not initiate this request, please disregard this email.

        Best regards,
        Maaiz.com Support Team
        """
        send_otp_to_users(title, message, email)  # Use the utility function

        # Redirect to OTP verification page
        return redirect('verify_otp')
    return render(request, 'signup.html')


def verify_otp_view(request):
    # Retrieve temporary user data from session
    temp_user_data = request.session.get('temp_user_data')

    if not temp_user_data:
        return redirect('signup')  # Redirect to signup if no session data exists

    otp_timestamp = temp_user_data['otp_timestamp']
    otp_timestamp = datetime.fromisoformat(otp_timestamp)

    # Ensure `otp_timestamp` is timezone-aware
    if is_naive(otp_timestamp):
        otp_timestamp = make_aware(otp_timestamp)

    # Calculate remaining time
    remaining_time = max(0, (otp_timestamp + timedelta(minutes=2) - now()).total_seconds())

    if request.method == 'POST':
        if 'resend_otp' in request.POST:
            # Generate and send a new OTP
            new_otp = generate_otp()
            temp_user_data['otp_code'] = new_otp
            temp_user_data['otp_timestamp'] = now().isoformat()
            request.session['temp_user_data'] = temp_user_data  # Update session data

            # Send the OTP via email
            email = temp_user_data['email']
            title = "Your New OTP Code"
            message = f"Your new OTP code is {new_otp}. It is valid for 2 minutes."
            send_otp_to_users(title, message, email)

            return render(request, 'verify_otp.html', {
                'info': 'A new OTP has been sent to your email.',
                'remaining_time': 120,  # Reset timer to 2 minutes
                'show_resend': False
            })

        # Combine OTP inputs into a single string
        otp_code = (
            request.POST.get('otp1', '') +
            request.POST.get('otp2', '') +
            request.POST.get('otp3', '') +
            request.POST.get('otp4', '') +
            request.POST.get('otp5', '') +
            request.POST.get('otp6', '')
        )

        # Handle OTP expiration
        if remaining_time <= 0:
            return render(request, 'verify_otp.html', {
                'error': 'OTP expired. Please resend a new OTP.',
                'remaining_time': 0,
                'show_resend': True  # Show the "Resend OTP" button
            })

        # Handle invalid OTP
        if otp_code != temp_user_data['otp_code']:
            return render(request, 'verify_otp.html', {
                'error': 'Invalid OTP. Please try again.',
                'remaining_time': int(remaining_time),
            })

        # OTP verification successful
        user = User.objects.create_user(
            username=temp_user_data['username'],
            email=temp_user_data['email'],
            password=temp_user_data['password']
        )
        OTP.objects.create(user=user, otp_code=temp_user_data['otp_code'])
        del request.session['temp_user_data']  # Clear session data
        return redirect('login')

    # Render the OTP verification page with timer
    return render(request, 'verify_otp.html', {
        'remaining_time': int(remaining_time),
        'show_resend': remaining_time == 0  # Show "Resend OTP" button if time is up
    })


# Login View
def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')  # Redirect to home page after login
        else:
            error = 'Invalid credentials'
            return render(request, 'login.html', {'error': error})
    return render(request, 'login.html')


# Forget Password View
def forget_password_view(request):
    if request.method == 'POST':
        email = request.POST['email']
        
        # Check if the email exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return render(request, 'forget_password.html', {'error': 'Email not found'})
        
        # Generate OTP and save it
        otp_code = generate_otp()
        otp_timestamp = datetime.now().isoformat()  # Save timestamp in ISO format

        OTP.objects.update_or_create(
            user=user,
            defaults={'otp_code': otp_code, 'created_at': otp_timestamp}  # Save timestamp
        )
        
        # Send OTP to user's email
        title = 'Password Reset OTP for Maaiz.com'
        message = f"""
        Dear {user.username},

        We received a request to reset your password for your account at Maaiz.com.

        Please enter the OTP below to proceed with password reset:

        OTP Code: {otp_code}

        This OTP is valid for the next 2 minutes. If you did not request this, please ignore this email.

        Best regards,
        Maaiz.com Support Team
        """
        send_otp_to_users(title, message, email)  # Use the utility function

        # Store user ID and OTP timestamp in session and redirect to OTP verification page
        request.session['reset_user_data'] = {
            'user_id': user.id,
            'otp_timestamp': otp_timestamp
        }
        return redirect('verify_reset_otp')
    return render(request, 'forget_password.html')


# OTP Verification for Password Reset
def verify_reset_otp_view(request):
    # Retrieve user data from session
    reset_user_data = request.session.get('reset_user_data')
    if not reset_user_data:
        return redirect('forget_password')  # Redirect if session data is missing

    user_id = reset_user_data['user_id']
    otp_timestamp = datetime.fromisoformat(reset_user_data['otp_timestamp'])

    # Ensure OTP timestamp is timezone-aware
    if is_naive(otp_timestamp):
        otp_timestamp = make_aware(otp_timestamp)

    # Calculate remaining time
    remaining_time = max(0, (otp_timestamp + timedelta(minutes=2) - now()).total_seconds())

    if request.method == 'POST':
        if 'resend_otp' in request.POST:
            # Generate and send a new OTP
            new_otp = generate_otp()
            reset_user_data['otp_timestamp'] = now().isoformat()
            request.session['reset_user_data'] = reset_user_data  # Update session data

            # Update OTP in database
            user = User.objects.get(id=user_id)
            OTP.objects.update_or_create(user=user, defaults={'otp_code': new_otp})

            # Send OTP via email
            title = 'Password Reset OTP for Maaiz.com'
            message = f"""
            Dear {user.username},

            Your new OTP code is {new_otp}. It is valid for 2 minutes.

            Best regards,
            Maaiz.com Support Team
            """
            send_otp_to_users(title, message, user.email)

            return render(request, 'verify_otp.html', {
                'info': 'A new OTP has been sent to your email.',
                'remaining_time': 120,  # Reset timer to 2 minutes
                'show_resend': False
            })

        # Combine OTP inputs into a single string
        otp_code = (
            request.POST.get('otp1', '') +
            request.POST.get('otp2', '') +
            request.POST.get('otp3', '') +
            request.POST.get('otp4', '') +
            request.POST.get('otp5', '') +
            request.POST.get('otp6', '')
        )

        # Handle OTP expiration
        if remaining_time <= 0:
            return render(request, 'verify_otp.html', {
                'error': 'OTP expired. Please resend a new OTP.',
                'remaining_time': 0,
                'show_resend': True  # Show "Resend OTP" button
            })

        # Handle invalid OTP
        try:
            otp = OTP.objects.get(user_id=user_id, otp_code=otp_code)
            otp.delete()  # OTP matched, delete it
            request.session['reset_user_id'] = user_id  # Set reset_user_id in session
            del request.session['reset_user_data']  # Clear other session data
            return redirect('change_password')  # Redirect to password reset page
        except OTP.DoesNotExist:
            return render(request, 'verify_otp.html', {
                'error': 'Invalid OTP. Please try again.',
                'remaining_time': int(remaining_time),
            })

    # Render the OTP verification page with timer
    return render(request, 'verify_otp.html', {
        'remaining_time': int(remaining_time),
        'show_resend': remaining_time == 0  # Show "Resend OTP" button if time is up
    })


# Password Reset View
def change_password_view(request):
    error = ""
    success = ""
    user_id = request.session.get('reset_user_id')
    if not user_id:  # If reset_user_id is not in session
        return redirect('forget_password')  # Redirect to forget password page

    if request.method == 'POST':
        new_password = request.POST['password']
        confirm_password = request.POST['confirmpassword']
        
        if new_password != confirm_password:
            # If passwords do not match, return an error message
            error = 'Passwords do not match.'
            return render(request, 'change_password.html', {'error': error})
        try:
            # Update user password
            user = User.objects.get(id=user_id)
            user.set_password(new_password)
            user.save()
            
            # Clear session and redirect to login
            del request.session['reset_user_id']

            # Show success message in the template
            success = "Password Reset Successfully!"
        except User.DoesNotExist:
            error = "User does not exist. Please try again."
        
    return render(request, 'change_password.html', {'success': success, 'error': error})


# Logout View
def logout_view(request):
    logout(request)
    return redirect("/")