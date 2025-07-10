import os
import re
import atexit
from functools import wraps
import pytz
from datetime import datetime, timedelta, timezone

import requests
import razorpay
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash
import firebase_admin
from firebase_admin import credentials, firestore, auth
from apscheduler.schedulers.background import BackgroundScheduler

# --- 1. INITIALIZATION & SETUP ---

# Load environment variables from the .env file
load_dotenv()

# Initialize the Flask application
app = Flask(__name__)
# Set a secret key for session management, essential for security
app.secret_key = os.urandom(24)

# Initialize Firebase Admin SDK using service account credentials
try:
    if not firebase_admin._apps:
        cred = credentials.Certificate("firebase-creds.json")
        firebase_admin.initialize_app(cred)
except Exception as e:
    print(f"Error initializing Firebase Admin SDK: {e}")

# Initialize Firestore client to interact with the database
db = firestore.client()

# Get API keys from environment variabless
SPOONACULAR_API_KEY = os.getenv("SPOONACULAR_API_KEY")


razorpay_client = razorpay.Client(
    auth=(os.getenv("RAZORPAY_KEY_ID"), os.getenv("RAZORPAY_KEY_SECRET"))
)


# --- 2. CONTEXT PROCESSOR ---

# This function injects variables into all templates automatically.
# Here, it provides Firebase frontend config for client-side JavaScript.
@app.context_processor
def inject_firebase_config():
    firebase_config = {
        'apiKey': os.getenv("API_KEY"),
        'authDomain': os.getenv("AUTH_DOMAIN"),
        'projectId': os.getenv("PROJECT_ID"),
        'storageBucket': os.getenv("STORAGE_BUCKET"),
        'messagingSenderId': os.getenv("MESSAGING_SENDER_ID"),
        'appId': os.getenv("APP_ID")
    }
    return dict(firebase_config=firebase_config)


# --- 3. BACKGROUND SCHEDULER ---

# This background job runs periodically to check for products that are about to expire.
def check_expiring_products_job():
    with app.app_context():  # Use app context to access application-level data
        now = datetime.now(timezone.utc)
        notification_threshold = now + timedelta(days=4)
        users_ref = db.collection('users').stream()
        for user in users_ref:
            user_id = user.id
            purchased_products_ref = db.collection('users').document(
                user_id).collection('purchased_products')

            # Query for products expiring within the next 4 days that haven't been notified yet
            expiring_soon_query = purchased_products_ref.where(
                'expiry_date', '<=', notification_threshold
            ).where(
                'expiry_date', '>', now
            ).where(
                'notified_before_4_days', '==', False
            )
            for item_doc in expiring_soon_query.stream():
                item_data = item_doc.to_dict()
                item_ref = item_doc.reference
                product_name = item_data.get('product_name', 'a product')
                expiry_date_dt = item_data['expiry_date']

                # Create a notification for the user in their notifications sub-collection
                user_notifications_ref = db.collection('users').document(
                    user_id).collection('notifications')
                message = f"Heads up! Your product '{product_name}' is expiring on {expiry_date_dt.strftime('%d %b, %Y')}."
                user_notifications_ref.add({
                    'message': message,
                    'created_at': firestore.SERVER_TIMESTAMP,
                    'read': False
                })

                # Create a notification for the user in their notifications sub-collection
                item_ref.update({'notified_before_4_days': True})
                print(
                    f"Notification sent for '{product_name}' to user '{user_id}'.")


# Initialize and start the scheduler to run the job every 24 hours.
# The condition `if os.environ.get('WERKZEUG_RUN_MAIN')` prevents the job from running twice in debug mode.
if os.environ.get('WERKZEUG_RUN_MAIN') or not app.debug:
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(func=check_expiring_products_job,
                      trigger="interval", hours=24)
    scheduler.start()
    # Ensure the scheduler is shut down when the app exits
    atexit.register(lambda: scheduler.shutdown())


# --- 4. DECORATORS FOR ACCESS CONTROL (RBAC) ---

# Decorator to ensure a user has admin or super-admin privileges
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        try:
            # Check the user's role directly from Firestore for security
            user_doc = db.collection('users').document(
                session['user_id']).get()
            if user_doc.exists:
                user_role = user_doc.to_dict().get('role')
                if user_role in ['admin', 'super-admin']:
                    return f(*args, **kwargs)
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('home'))
        except Exception as e:
            flash('An error occurred while checking permissions.', 'danger')
            return redirect(url_for('home'))
    return decorated_function


# Decorator to ensure a user has super-admin privileges
def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_role') != 'super-admin':
            flash('Only super-admins can access this page.', 'danger')
            return redirect(url_for('admin_dashboard'))
        return f(*args, **kwargs)
    return decorated_function


# --- 5. CORE & AUTHENTICATION ROUTES ---

# Homepage: Fetches and displays all products in descending order of creation time
@app.route('/')
def home():
    products_ref = db.collection('products').order_by(
        'created_at', direction=firestore.Query.DESCENDING).stream()
    products_list = []
    for prod in products_ref:
        product_data = prod.to_dict()
        product_data['id'] = prod.id
        products_list.append(product_data)
    return render_template('index.html', products=products_list)


# Handles user registration (GET for displaying the form, POST for processing it)
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            # Create a new user in Firebase Authentication
            user = auth.create_user(email=email, password=password)
            # Create a corresponding user document in Firestore with a default 'user' role
            db.collection('users').document(user.uid).set({
                'email': user.email,
                'created_at': firestore.SERVER_TIMESTAMP,
                'role': 'user'
            })
            flash(
                f'Account created successfully for {user.email}! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error creating account: {e}', 'danger')
            return redirect(url_for('signup'))
    return render_template('signup.html')


# Renders the login page
@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')


# This route securely verifies the Firebase ID token from the frontend and creates a server-side session
@app.route('/session_login', methods=['POST'])
def session_login():
    try:
        id_token = request.form['idToken']
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        user = auth.get_user(uid)
        user_doc = db.collection('users').document(uid).get()
        user_role = 'user'
        if user_doc.exists:
            user_role = user_doc.to_dict().get('role', 'user')
        session['user_id'] = user.uid
        session['user_email'] = user.email
        session['user_role'] = user_role
        return jsonify({'status': 'success', 'message': 'Logged in successfully!'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 401


# Clears the user's session to log them out
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('home'))


# Renders the "forgot password" page
@app.route('/forgot_password', methods=['GET'])
def forgot_password():
    return render_template('forgot_password.html')


# --- 6. USER-SPECIFIC FEATURE ROUTES ---

# Renders the user's personal dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to view your dashboard.', 'danger')
        return redirect(url_for('login', next=url_for('dashboard')))

    user_id = session['user_id']
    purchased_items = []
    now = datetime.now(timezone.utc)

    thirty_days_ago = now - timedelta(days=30)

    purchased_products_stream = db.collection('users').document(user_id).collection('purchased_products') \
                                  .where('purchase_date', '>=', thirty_days_ago) \
                                  .order_by('purchase_date', direction=firestore.Query.DESCENDING) \
                                  .stream()

    for doc in purchased_products_stream:
        item_data = doc.to_dict()

        product_id = item_data.get('product_id')
        if product_id:
            product_doc = db.collection('products').document(product_id).get()
            if product_doc.exists:
                item_data['product_image_url'] = product_doc.to_dict().get(
                    'image_url')

        expiry_date = item_data.get('expiry_date')
        purchase_date = item_data.get('purchase_date')

        if expiry_date and purchase_date and isinstance(expiry_date, datetime) and isinstance(purchase_date, datetime):
            expiry_date = expiry_date.replace(tzinfo=timezone.utc)
            purchase_date = purchase_date.replace(tzinfo=timezone.utc)

            total_shelf_life = (expiry_date - purchase_date).days
            days_remaining = (expiry_date - now).days

            if total_shelf_life > 0:
                percentage_remaining = max(
                    0, (days_remaining / total_shelf_life) * 100)
            else:
                percentage_remaining = 0

            item_data['days_remaining'] = days_remaining
            item_data['percentage_remaining'] = round(percentage_remaining)
            item_data['total_shelf_life'] = total_shelf_life

            if days_remaining < 0:
                item_data['status'] = 'expired'
            elif 0 <= days_remaining <= 4:
                item_data['status'] = 'expiring_soon'
            else:
                item_data['status'] = 'safe'
        else:
            item_data['status'] = 'no_expiry_info'

        purchased_items.append(item_data)

    return render_template('dashboard.html', purchased_items=purchased_items)


# Renders the user's order history page
@app.route('/order_history')
def order_history():
    if 'user_id' not in session:
        flash('Please log in to view your order history.', 'danger')
        return redirect(url_for('login', next=url_for('order_history')))

    user_id = session['user_id']
    orders_ref = db.collection('orders').where('user_id', '==', user_id).order_by(
        'created_at', direction=firestore.Query.DESCENDING).stream()

    local_tz = pytz.timezone('Asia/Kolkata')

    orders_list = []
    for order in orders_ref:
        order_data = order.to_dict()
        order_data['id'] = order.id

        if 'items' in order_data:
            order_data['order_items'] = order_data.pop('items')

        if 'created_at' in order_data and order_data['created_at']:
            utc_time = order_data['created_at']
            utc_time = utc_time.replace(tzinfo=pytz.utc)
            local_time = utc_time.astimezone(local_tz)
            order_data['created_at'] = local_time

        orders_list.append(order_data)

    return render_template('order_history.html', orders=orders_list)


# Renders the user's notifications page
@app.route('/notifications')
def view_notifications():
    if 'user_id' not in session:
        flash('Please log in to view notifications.', 'danger')
        return redirect(url_for('login'))
    user_id = session['user_id']
    notifications_ref = db.collection('users').document(user_id).collection(
        'notifications').order_by('created_at', direction=firestore.Query.DESCENDING).stream()
    notifications_list = []
    for notif in notifications_ref:
        notif_data = notif.to_dict()
        notif_data['id'] = notif.id
        notifications_list.append(notif_data)
    return render_template('notifications.html', notifications=notifications_list)


# --- 7. E-COMMERCE & PAYMENT ROUTES ---

# Handles product search requests
@app.route('/search')
def search():
    query = request.args.get('query', '').strip()
    if not query:
        return redirect(url_for('home'))
    search_results = []
    search_terms = query.lower().split()
    if not search_terms:
        return render_template('search_results.html', products=[], query=query)
    try:
        products_ref = db.collection('products').where(
            'keywords', 'array_contains', search_terms[0]).stream()
        for prod in products_ref:
            product_data = prod.to_dict()
            product_data['id'] = prod.id
            search_results.append(product_data)
    except Exception as e:
        print(f"Search error: {e}")
        flash("An error occurred during search. Please check the logs.", "danger")
        return render_template('search_results.html', products=[], query=query)
    return render_template('search_results.html', products=search_results, query=query)


# Adds a selected product to the user's cart (stored in the session)
@app.route('/add_to_cart/<string:product_id>', methods=['POST'])
def add_to_cart(product_id):
    cart = session.get('cart', {})
    quantity = int(request.form.get('quantity', 1))
    product_doc = db.collection('products').document(product_id).get()
    if not product_doc.exists:
        flash('Product not found!', 'danger')
        return redirect(request.referrer or url_for('home'))
    product_data = product_doc.to_dict()
    if product_id in cart:
        cart[product_id]['quantity'] += quantity
    else:
        cart[product_id] = {'name': product_data['name'],
                            'price': product_data['price'], 'quantity': quantity}
    session['cart'] = cart
    flash(f"Added '{product_data['name']}' to cart!", 'success')
    return redirect(request.referrer or url_for('home'))


# Displays the shopping cart page
@app.route('/cart')
def view_cart():
    cart = session.get('cart', {})
    cart_items = {}
    total_price = 0

    for product_id, item_data in cart.items():
        product_doc = db.collection('products').document(product_id).get()
        new_item = item_data.copy()

        if product_doc.exists:
            product_data = product_doc.to_dict()
            new_item['price'] = product_data.get(
                'price', item_data['price'])  # Use fresh price
            new_item['image_url'] = product_data.get('image_url')
        else:
            new_item['image_url'] = None

        cart_items[product_id] = new_item
        total_price += new_item['price'] * new_item['quantity']

    return render_template('cart.html', cart_items=cart_items, total_price=total_price)


# Removes a specific item from the cart
@app.route('/remove_from_cart/<string:product_id>', methods=['POST'])
def remove_from_cart(product_id):
    cart = session.get('cart', {})
    if product_id in cart:
        removed_item_name = cart.pop(product_id)['name']
        session['cart'] = cart
        flash(f"Removed '{removed_item_name}' from cart.", 'info')
    return redirect(url_for('view_cart'))


# Updates the quantity of an item in the cart
@app.route('/update_cart/<string:product_id>', methods=['POST'])
def update_cart(product_id):
    cart = session.get('cart', {})
    quantity = int(request.form.get('quantity', 1))
    if product_id in cart:
        if quantity > 0:
            cart[product_id]['quantity'] = quantity
            flash(
                f"Updated quantity for '{cart[product_id]['name']}'.", 'success')
        else:
            del cart[product_id]
            flash(f"Removed product from cart.", 'info')
        session['cart'] = cart
    return redirect(url_for('view_cart'))


@app.route('/api/update_cart/<string:product_id>', methods=['POST'])
def api_update_cart(product_id):
    # Check if user is logged in
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'User not logged in'}), 401

    cart = session.get('cart', {})

    # Get the new quantity from the request JSON
    data = request.json
    new_quantity = int(data.get('quantity', 1))

    if product_id in cart:
        if new_quantity > 0:
            cart[product_id]['quantity'] = new_quantity
        else:
            # If quantity is 0 or less, remove the item
            del cart[product_id]

        session['cart'] = cart

        # Recalculate totals to send back to the frontend
        item_subtotal = cart.get(product_id, {}).get('price', 0) * new_quantity
        total_price = sum(item['price'] * item['quantity']
                          for item in cart.values())
        cart_item_count = len(cart)

        return jsonify({
            'status': 'success',
            'message': 'Cart updated successfully',
            'new_subtotal': f'₹{item_subtotal:.2f}',
            'new_total': f'₹{total_price:.2f}',
            'cart_item_count': cart_item_count
        })

    return jsonify({'status': 'error', 'message': 'Product not found in cart'}), 404

# Initiates the payment process


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    # 1. Verify user is logged in and cart is not empty
    # 2. Calculate total amount in paise (as required by Razorpay)
    # 3. Create an order with Razorpay to get an `order_id`
    # 4. Create a preliminary order document in Firestore with 'pending_payment' status
    # 5. Render the checkout page and pass the necessary details to the frontend
    if 'user_id' not in session:
        flash('Please log in to proceed to checkout.', 'danger')
        return redirect(url_for('login', next=url_for('view_cart')))

    cart = session.get('cart', {})
    if not cart:
        flash('Your cart is empty!', 'warning')
        return redirect(url_for('view_cart'))

    total_price = sum(item['price'] * item['quantity']
                      for item in cart.values())

    amount_in_paise = int(total_price * 100)

    order_data = {
        "amount": amount_in_paise,
        "currency": "INR",
        "receipt": f"order_rcptid_{datetime.now().timestamp()}"
    }

    try:
        razorpay_order = razorpay_client.order.create(data=order_data)
    except Exception as e:
        flash(f"Error creating Razorpay order: {e}", "danger")
        return redirect(url_for('view_cart'))

    order_id_firestore = db.collection('orders').add({
        'user_id': session['user_id'],
        'items': cart,
        'total_price': total_price,
        'status': 'pending_payment',
        'razorpay_order_id': razorpay_order['id'],
        'created_at': firestore.SERVER_TIMESTAMP
    })[1].id

    return render_template(
        'checkout.html',
        razorpay_order=razorpay_order,
        key_id=os.getenv("RAZORPAY_KEY_ID"),
        firestore_order_id=order_id_firestore
    )

# Handles the post-payment verification callback from Razorpay


@app.route('/payment_verification', methods=['POST'])
def payment_verification():
    # 1. Receive payment details (payment_id, order_id, signature) from the frontend
    # 2. Securely verify the payment signature to ensure authenticity
    # 3. If verification is successful, update the order status to 'completed'
    # 4. Add purchased items to the user's personal shelf-life tracking collection
    # 5. Clear the user's cart from the session
    # 6. Send a success response to the frontend for redirection
    data = request.json
    razorpay_order_id = data.get('razorpay_order_id')
    razorpay_payment_id = data.get('razorpay_payment_id')
    razorpay_signature = data.get('razorpay_signature')
    firestore_order_id = data.get('firestore_order_id')

    try:
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_signature': razorpay_signature
        })
    except Exception as e:
        db.collection('orders').document(firestore_order_id).update(
            {'status': 'payment_failed', 'failure_reason': 'Signature Mismatch'})
        return jsonify({'status': 'error', 'message': 'Payment verification failed!'}), 400

    order_ref = db.collection('orders').document(firestore_order_id)
    order_doc = order_ref.get()

    if not order_doc.exists:
        return jsonify({'status': 'error', 'message': 'Order not found!'}), 404

    cart = order_doc.to_dict().get('items', {})
    user_id = order_doc.to_dict().get('user_id')
    purchase_time = datetime.now(timezone.utc)
    user_products_col = db.collection('users').document(
        user_id).collection('purchased_products')

    for product_id, item in cart.items():
        product_doc = db.collection('products').document(product_id).get()
        if product_doc.exists:
            product_data = product_doc.to_dict()
            if 'shelf_life_days' in product_data:
                shelf_life = timedelta(
                    days=int(product_data['shelf_life_days']))
                expiry_date = purchase_time + shelf_life
                user_products_col.add({
                    'product_id': product_id,
                    'product_name': product_data.get('name'),
                    'purchase_date': purchase_time,
                    'expiry_date': expiry_date,
                    'quantity': item['quantity'],
                    'notified_before_4_days': False
                })

    order_ref.update({
        'status': 'completed',
        'razorpay_payment_id': razorpay_payment_id,
        'paid_at': firestore.SERVER_TIMESTAMP
    })

    session.pop('cart', None)

    flash('Your order has been placed successfully!', 'success')
    return jsonify({'status': 'success', 'redirect_url': url_for('home')})


# --- 8. ADMIN & SUPER-ADMIN ROUTES ---

# Renders the main admin dashboard for product management
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    products_ref = db.collection('products').order_by(
        'created_at', direction=firestore.Query.DESCENDING).stream()
    products_list = []
    for prod in products_ref:
        product_data = prod.to_dict()
        product_data['id'] = prod.id
        products_list.append(product_data)
    return render_template('admin_dashboard.html', products=products_list)


# Handles adding a new product
@app.route('/add_product', methods=['GET', 'POST'])
@admin_required
def add_product():
    if request.method == 'POST':
        product_name = request.form['name']
        product_price = request.form['price']
        product_description = request.form.get('description', '')
        product_image_url = request.form.get('image_url', '')
        shelf_life_days = request.form.get('shelf_life_days')

        if not (product_name and product_price):
            flash("Product Name and Price are required.", "danger")
            return render_template('admin_add_product.html', current_data=request.form)

        clean_name = re.sub(r'[^\w\s]', '', product_name.lower())
        keywords = list(set(clean_name.split()))

        product_data = {
            'name': product_name,
            'name_lower': product_name.lower(),
            'keywords': keywords,
            'price': float(product_price),
            'description': product_description,
            'image_url': product_image_url,
            'added_by': session.get('user_id'),
            'created_at': firestore.SERVER_TIMESTAMP
        }

        if shelf_life_days and shelf_life_days.isdigit():
            product_data['shelf_life_days'] = int(shelf_life_days)

        db.collection('products').add(product_data)
        flash('Product added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_add_product.html')


# Handles editing an existing product
@app.route('/admin/product/edit/<string:product_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_product(product_id):
    product_ref = db.collection('products').document(product_id)
    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        description = request.form.get('description', '')
        image_url = request.form.get('image_url', '')
        shelf_life_days = request.form.get('shelf_life_days')

        clean_name = re.sub(r'[^\w\s]', '', name.lower())
        keywords = list(set(clean_name.split()))

        update_data = {
            'name': name,
            'name_lower': name.lower(),
            'keywords': keywords,
            'price': float(price),
            'description': description,
            'image_url': image_url,
            'updated_at': firestore.SERVER_TIMESTAMP
        }

        if shelf_life_days and shelf_life_days.isdigit():
            update_data['shelf_life_days'] = int(shelf_life_days)
        else:
            update_data['shelf_life_days'] = firestore.DELETE_FIELD

        product_ref.update(update_data)
        flash('Product updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    product_data = product_ref.get().to_dict()
    return render_template('admin_edit_product.html', product=product_data, product_id=product_id)


# Handles deleting a product
@app.route('/admin/product/delete/<string:product_id>', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    try:
        db.collection('products').document(product_id).delete()
        flash('Product deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting product: {e}', 'danger')
    return redirect(url_for('admin_dashboard'))


# Renders the user management page (Super-Admin only)
@app.route('/admin/users')
@admin_required
@super_admin_required
def manage_users():
    users_list = []
    for user in auth.list_users().iterate_all():
        user_doc = db.collection('users').document(user.uid).get()
        user_role = 'user'
        if user_doc.exists:
            user_role = user_doc.to_dict().get('role', 'user')

        setattr(user, 'role', user_role)

        users_list.append(user)

    return render_template('manage_users.html', users_list=users_list)


# Promotes a user to the 'admin' role (Super-Admin only)
@app.route('/admin/promote/<string:user_id>', methods=['POST'])
@admin_required
@super_admin_required
def promote_to_admin(user_id):
    try:
        db.collection('users').document(user_id).update({'role': 'admin'})
        flash('User has been promoted to Admin.', 'success')
    except Exception as e:
        flash(f'Error promoting user: {e}', 'danger')
    return redirect(url_for('manage_users'))


# Demotes an admin back to the 'user' role (Super-Admin only)
@app.route('/admin/demote/<string:user_id>', methods=['POST'])
@admin_required
@super_admin_required
def demote_to_user(user_id):
    try:
        db.collection('users').document(user_id).update({'role': 'user'})
        flash('Admin has been demoted to User.', 'success')
    except Exception as e:
        flash(f'Error demoting user: {e}', 'danger')
    return redirect(url_for('manage_users'))


# --- 9. EXTERNAL API ROUTES ---

# Fetches recipe suggestions from Spoonacular API based on purchased items
@app.route('/suggest_recipes')
def suggest_recipes():
    if 'user_id' not in session:
        return jsonify({'error': 'Please log in to get recipe suggestions.'}), 401

    user_id = session['user_id']
    ingredients_list = []

    now = datetime.now(timezone.utc)
    thirty_days_ago = now - timedelta(days=30)

    purchased_products_stream = db.collection('users').document(user_id).collection('purchased_products') \
                                  .where('purchase_date', '>=', thirty_days_ago) \
                                  .stream()

    for doc in purchased_products_stream:
        item_data = doc.to_dict()
        if 'product_name' in item_data:
            main_ingredient = item_data['product_name'].split(
                ' - ')[0].split(',')[0]
            ingredients_list.append(main_ingredient)

    if not ingredients_list:
        return jsonify({'error': 'You have no recent products to get suggestions for.'}), 400

    unique_ingredients = list(set(ingredients_list))[:5]
    ingredients_str = ",".join(unique_ingredients)

    api_url = "https://api.spoonacular.com/recipes/findByIngredients"
    params = {'ingredients': ingredients_str, 'number': 5,
              'ranking': 2, 'apiKey': SPOONACULAR_API_KEY}

    try:
        response = requests.get(api_url, params=params)
        response.raise_for_status()
        recipes = response.json()
        return jsonify(recipes)
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Could not fetch recipes at this time.'}), 500


# --- 10. MAIN APP RUNNER ---

# This block ensures the app runs only when the script is executed directly
if __name__ == '__main__':
    # `debug=True` enables auto-reloading and provides a debugger for development
    app.run(debug=True)
