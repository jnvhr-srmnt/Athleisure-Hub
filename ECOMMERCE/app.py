from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import mysql.connector
import os
from flask_mail import Mail, Message
import random
from datetime import datetime, timedelta
import pytz, logging
from authlib.integrations.flask_client import OAuth
from functools import wraps

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'athleisurehub1119@gmail.com'
app.config['MAIL_PASSWORD'] = 'vcfl qxig nkkk soxi'

GOOGLE_CLIENT_ID = os.getenv ("154323454753-evniobeokneh29lh5jsam4q780sls9v1.apps.googleusercontent.com")
GOOGLE_CLIENT_SECRET = os.getenv("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")


app.config['GOOGLE_CLIENT_ID'] = "154323454753-evniobeokneh29lh5jsam4q780sls9v1.apps.googleusercontent.com"
app.config['GOOGLE_CLIENT_SECRET'] = "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"

app.config['FACEBOOK_ID'] = "your_facebook_app_id"
app.config['FACEBOOK_SECRET'] = "your_facebook_app_secret"

oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
)

# Configure Facebook OAuth
facebook = oauth.register(
    name='facebook',
    client_id='your_facebook_app_id',
    client_secret='your_facebook_app_secret',
    access_token_url='https://graph.facebook.com/oauth/access_token',
    access_token_params=None,
    authorize_url='https://www.facebook.com/dialog/oauth',
    authorize_params=None,
    api_base_url='https://graph.facebook.com/',
    client_kwargs={'scope': 'email'},
)

mail = Mail(app)

timezone = pytz.timezone('UTC')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

#  Database connection
def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        port = 3306,
        user='root',
        password='',
        database='db_test'
    )

@app.route('/')
def home():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        # Fetch the 5 most recently added products
        cursor.execute("SELECT * FROM products ORDER BY id DESC LIMIT 5")
        latest_products = cursor.fetchall()
    except mysql.connector.Error as err:
        print("Error fetching products: {}".format(err))
        flash('Could not retrieve products. Please try again later.', 'danger')
        latest_products = []
    finally:
        cursor.close()
        conn.close()
    return render_template('home.html', latest_products=latest_products)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin login route
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT * FROM users 
                WHERE username = %s AND role = 'admin'
            """, (username,))
            
            admin_user = cursor.fetchone()

            if admin_user and check_password_hash(admin_user['password'], password):
                session['user_id'] = admin_user['id']
                session['username'] = admin_user['username']
                session['role'] = 'admin'
                session['admin_login_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                flash('Welcome to the Admin Dashboard!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid admin credentials.', 'danger')
                
        except mysql.connector.Error as err:
            print(f"Database error: {err}")
            flash('An error occurred. Please try again later.', 'danger')
            
        finally:
            cursor.close()
            conn.close()

    return render_template('admin_login.html')

# Admin logout route
@app.route('/admin/logout')
@admin_required
def admin_logout():
    session.clear()
    flash('You have been logged out of the admin panel.', 'info')
    return redirect(url_for('admin_login'))

# Admin dashboard route
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Fetch summary data
        cursor.execute("SELECT COUNT(*) as user_count FROM users WHERE role != 'admin'")
        user_count = cursor.fetchone()['user_count']

        cursor.execute("SELECT COUNT(*) as product_count FROM products")
        product_count = cursor.fetchone()['product_count']

        cursor.execute("SELECT COUNT(*) as pending_count FROM seller_requests")
        pending_count = cursor.fetchone()['pending_count']

        # Fetch recent activities (example)
        cursor.execute("""
            SELECT 'New User' as type, username, created_at as date
            FROM users
            WHERE role != 'admin'
            ORDER BY created_at DESC
            LIMIT 5
        """)
        recent_activities = cursor.fetchall()

    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        flash('An error occurred while fetching dashboard data.', 'danger')
        user_count = product_count = pending_count = 0
        recent_activities = []

    finally:
        cursor.close()
        conn.close()

    return render_template('admin_dashboard.html',
                           user_count=user_count,
                           product_count=product_count,
                           pending_count=pending_count,
                           recent_activities=recent_activities)

# Admin user management route
@app.route('/admin_users')
def admin_users():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Fetch all users
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()

        # Fetch addresses for each user
        for user in users:
            cursor.execute("SELECT id, address_line1 FROM addresses WHERE user_id = %s", (user['id'],))
            user['addresses'] = cursor.fetchall()  # This will now include the 'id' field

    except mysql.connector.Error as err:
        flash(f'Error: {err}', 'danger')
        users = []  # In case of error, set users to an empty list
    finally:
        cursor.close()
        conn.close()

    return render_template('admin_users.html', users=users)

@app.route('/admin/user/delete/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def delete_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        try:
            # First delete associated seller requests
            cursor.execute("DELETE FROM seller_requests WHERE user_id = %s", (user_id,))
            
            action = request.form.get('action')
            if action == 'transfer':
                admin_id = request.form.get('admin_id')
                # Transfer products to the selected admin
                cursor.execute("UPDATE products SET seller_id = %s WHERE seller_id = %s", (admin_id, user_id))
            elif action == 'delete':
                # Delete associated products
                cursor.execute("DELETE FROM products WHERE seller_id = %s", (user_id,))

            # Finally delete the user
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()

            flash('User and associated data handled successfully', 'success')
            return redirect(url_for('admin_users'))
            
        except mysql.connector.Error as err:
            conn.rollback()
            flash(f'Error deleting user: {str(err)}', 'danger')
            return redirect(url_for('admin_users'))

    # GET request: show confirmation page
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    cursor.execute("SELECT COUNT(*) as product_count FROM products WHERE seller_id = %s", (user_id,))
    product_count = cursor.fetchone()['product_count']

    cursor.execute("SELECT id, username FROM users WHERE role = 'admin' AND id != %s", (user_id,))
    admins = cursor.fetchall()

    cursor.close()
    conn.close()

    if user is None:
        flash('User not found', 'error')
        return redirect(url_for('admin_users'))

    return render_template('confirm_delete_user.html', user=user, product_count=product_count, admins=admins)
@app.route('/admin/toggle_seller/<int:user_id>', methods=['POST'])
def toggle_seller(user_id):
    if 'user_id' not in session:
        flash('You must be logged in to perform this action.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Check if the current user is an admin
    cursor.execute("SELECT role FROM users WHERE id = %s", (session['user_id'],))
    current_user = cursor.fetchone()
    if current_user['role'] != 'admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('home'))

    try:
        # Get the current seller status
        cursor.execute("SELECT role FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        new_role = 'user' if user['role'] == 'seller' else 'seller'
        
        # Toggle the seller status
        cursor.execute("UPDATE users SET role = %s WHERE id = %s", (new_role, user_id))
        conn.commit()
        
        flash(f"User's seller status has been {'removed' if new_role == 'user' else 'granted'}.", 'success')
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        flash('An error occurred while updating user status.', 'danger')
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_users'))

@app.route('/admin/products')
def admin_products():
    if 'user_id' not in session:
        flash('Please login first.', 'danger')
        return redirect(url_for('login'))
    
    # Check if user is admin
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT role FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    
    if not user or user['role'] != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))

    # Get all products
    cursor.execute("""
        SELECT p.*, u.username as seller_name 
        FROM products p 
        JOIN users u ON p.seller_id = u.id 
        ORDER BY p.id DESC
    """)
    products = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('admin_products.html', products=products)
def add_product(name, description, price, seller_id, image_url):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO products (name, description, price, seller_id, image_url, created_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
        """, (name, description, price, seller_id, image_url))
        conn.commit()
        return cursor.lastrowid
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        conn.rollback()
        return None
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/seller-requests/<int:request_id>/action', methods=['POST'])
def admin_handle_seller_request(request_id):
    if 'user_id' not in session:
        flash('Please login first.', 'danger')
        return redirect(url_for('login'))

    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Verify admin status
        cursor.execute("SELECT role FROM users WHERE id = %s", (session['user_id'],))
        user = cursor.fetchone()

        if not user or user['role'] != 'admin':
            flash('You do not have permission to perform this action.', 'danger')
            return redirect(url_for('home'))

        action = request.form.get('action')
        if action not in ['approve', 'reject']:
            flash('Invalid action.', 'danger')
            return redirect(url_for('admin_seller_requests'))

        # Get the seller request
        cursor.execute("""
            SELECT sr.*, u.email 
            FROM seller_requests sr
            JOIN users u ON sr.user_id = u.id
            WHERE sr.id = %s AND sr.status = 'pending'
        """, (request_id,))
        seller_request = cursor.fetchone()

        if not seller_request:
            flash('Invalid seller request or request already processed.', 'warning')
            return redirect(url_for('admin_seller_requests'))

        if action == 'approve':
            # Update seller request status and user role
            cursor.execute("""
                UPDATE seller_requests 
                SET status = 'approved'
                WHERE id = %s
            """, (request_id,))
            
            cursor.execute("""
                UPDATE users 
                SET role = 'seller' 
                WHERE id = %s
            """, (seller_request['user_id'],))
            
            flash('Seller request approved successfully.', 'success')

        else:  # reject
            cursor.execute("""
                UPDATE seller_requests 
                SET status = 'rejected'
                WHERE id = %s
            """, (request_id,))
            
            flash('Seller request rejected successfully.', 'success')

        conn.commit()

    except mysql.connector.Error as err:
        logger.error(f"MySQL Error: {err}")
        flash(f'An error occurred while processing the request: {err}', 'danger')
        if conn:
            conn.rollback()
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        flash('An unexpected error occurred while processing the request.', 'danger')
        if conn:
            conn.rollback()
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return redirect(url_for('admin_seller_requests'))

@app.route('/admin/edit_user/<int:user_id>', methods=['GET','POST'])
def edit_user(user_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('home'))

    username = request.form['username']
    email = request.form['email']
    role = request.form['role']

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("UPDATE users SET username = %s, email = %s, role = %s WHERE id = %s",
                       (username, email, role, user_id))
        conn.commit()
        flash('User updated successfully!', 'success')
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        flash('An error occurred while updating the user.', 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_users'))

@app.route('/admin/edit_product/<int:id>', methods=['GET', 'POST'])
def admin_edit_product(id):
    if 'user_id' not in session:
        flash('You must be logged in as an admin to edit products.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Check if the user is an admin
    cursor.execute("SELECT role FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    if user['role'] != 'admin':
        flash('You must be an admin to edit any product.', 'danger')
        return redirect(url_for('products'))

    cursor.execute("SELECT * FROM products WHERE id = %s", (id,))
    product = cursor.fetchone()

    if product is None:
        flash('Product not found.', 'danger')
        return redirect(url_for('admin_products'))  # Changed to redirect to admin products page

    # Fetch user addresses for the product (assuming there is a relationship)
    cursor.execute("SELECT * FROM addresses WHERE user_id = %s", (product['user_id'],))
    user_addresses = cursor.fetchall()

    if request.method == 'POST':
        # Update product details
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']

        # Handle file upload
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                image_url = f'/static/uploads/{filename}'
            else:
                image_url = product['image_url']
        else:
            image_url = product['image_url']

        try:
            cursor.execute("UPDATE products SET name = %s, description = %s, price = %s, image_url = %s WHERE id = %s",
                           (name, description, price, image_url, id))
            conn.commit()
            flash('Product updated successfully.', 'success')
        except Exception as e:
            flash('Failed to update product.', 'danger')
            print(e)

        # Update addresses if any address form is submitted
        for address in user_addresses:
            address_id = address['id']
            address_line1 = request.form.get(f'address_line1_{address_id}')
            is_default = request.form.get(f'is_default_{address_id}') == 'on'

            if address_line1:  # Only update if the address line is provided
                try:
                    cursor.execute("UPDATE addresses SET address_line1 = %s, is_default = %s WHERE id = %s",
                                   (address_line1, is_default, address_id))
                    conn.commit()
                except Exception as e:
                    flash('Failed to update address.', 'danger')
                    print(e)

        return redirect(url_for('admin_products'))  # Changed to redirect to admin products page

    cursor.close()
    conn.close()
    return render_template('admin_edit_product.html', product=product, user_addresses=user_addresses)

@app.route('/admin/delete_product/<int:id>', methods=['GET', 'POST'])
def admin_delete_product(id):
    if 'user_id' not in session:
        flash('You must be logged in as an admin to delete products.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Check if the user is an admin
    cursor.execute("SELECT role FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    if user['role'] != 'admin':
        flash('You must be an admin to delete any product.', 'danger')
        return redirect(url_for('products'))

    cursor.execute("SELECT * FROM products WHERE id = %s", (id,))
    product = cursor.fetchone()

    if product is None:
        flash('Product not found.', 'danger')
        return redirect(url_for('admin_products'))

    if request.method == 'POST':
        try:
            cursor.execute("DELETE FROM products WHERE id = %s", (id,))
            conn.commit()
            flash('Product deleted successfully.', 'success')
            return redirect(url_for('admin_products'))
        except Exception as e:
            flash('Failed to delete product.', 'danger')
            print(e)

    cursor.close()
    conn.close()
    return render_template('delete_product_confirmation.html', product=product)

@app.route('/admin/seller-requests')
def admin_seller_requests():
    if 'user_id' not in session:
        flash('Please login first.', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Check if user is admin
    cursor.execute("SELECT role FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    
    if not user or user['role'] != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))

    # Get all seller requests
    cursor.execute("""
        SELECT sr.id, sr.status, sr.created_at, u.username, u.email
        FROM seller_requests sr
        JOIN users u ON sr.user_id = u.id
        ORDER BY sr.created_at DESC
    """)
    seller_requests = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('admin_seller_requests.html', seller_requests=seller_requests)

# Admin action to approve or reject seller request
@app.route('/admin/seller_requests/<int:request_id>/<action>')
@admin_required
def admin_seller_request_action(request_id, action):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        if action == 'approve':
            cursor.execute("UPDATE users SET role = 'seller' WHERE id = (SELECT user_id FROM seller_requests WHERE id = %s)", (request_id,))
            cursor.execute("DELETE FROM seller_requests WHERE id = %s", (request_id,))
            flash('Seller request approved successfully.', 'success')
        elif action == 'reject':
            cursor.execute("DELETE FROM seller_requests WHERE id = %s", (request_id,))
            flash('Seller request rejected.', 'info')
        else:
            flash('Invalid action.', 'danger')

        conn.commit()
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        conn.rollback()
        flash('An error occurred while processing the request.', 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_seller_requests'))

@app.route('/request_seller_status', methods=['GET', 'POST'])
def request_seller_status():
    if 'user_id' not in session:
        flash('Please login first. ', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Check user role
    cursor.execute("SELECT role FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    if user['role'] == 'admin':
        # Admins do not need to have an address
        if request.method == 'POST':
            try:
                # Check if user already has a pending request
                cursor.execute("""
                    SELECT * FROM seller_requests 
                    WHERE user_id = %s AND status = 'pending'
                """, (user_id,))

                existing_request = cursor.fetchone()

                if existing_request:
                    flash('You already have a pending seller request. ', 'warning')
                else:
                    # Create new seller request
                    cursor.execute("""
                        INSERT INTO seller_requests (user_id, status, created_at) 
                        VALUES (%s, 'pending', NOW())
                    """, (user_id,))
                    conn.commit()
                    flash('Your seller request has been submitted. ', 'success')

            except mysql.connector.Error as err:
                print(f"Database error: {err}")
                flash('An error occurred while processing your request. ', 'danger')

    else:
        # For buyers and sellers, check if they have any addresses
        cursor.execute("SELECT * FROM addresses WHERE user_id = %s", (user_id,))
        addresses = cursor.fetchall()

        if not addresses:
            flash('You must add an address before requesting seller status. ', 'warning')
            return redirect(url_for('manage_addresses'))  # Redirect to address management page

        if request.method == 'POST':
            try:
                # Check if user already has a pending request
                cursor.execute("""
                    SELECT * FROM seller_requests 
                    WHERE user_id = %s AND status = 'pending'
                """, (user_id,))

                existing_request = cursor.fetchone()

                if existing_request:
                    flash('You already have a pending seller request. ', 'warning')
                else:
                    # Create new seller request
                    cursor.execute("""
                        INSERT INTO seller_requests (user_id, status, created_at) 
                        VALUES (%s, 'pending', NOW())
                    """, (user_id,))
                    conn.commit()
                    flash('Your seller request has been submitted. ', 'success')

            except mysql.connector.Error as err:
                print(f"Database error: {err}")
                flash('An error occurred while processing your request. ', 'danger')

    cursor.close()
    conn.close()

    return render_template('request_seller_status.html')  # Render the request seller status template
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch user information
    cursor.execute("SELECT username, email, contact_number FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()

    # Fetch user's products
    cursor.execute("SELECT id, name, price, image_url FROM products WHERE seller_id = %s", (session['user_id'],))
    products = cursor.fetchall()

    # Fetch user's addresses where is_default is true
    # Fetch user's default address
    cursor.execute("SELECT id, address_line1 FROM addresses WHERE user_id = %s AND is_default = TRUE", (session['user_id'],))
    default_address = cursor.fetchone()

    # Fetch all addresses for the user
    cursor.execute("SELECT id, address_line1 FROM addresses WHERE user_id = %s", (session['user_id'],))
    addresses = cursor.fetchall()

    # Pass both default_address and addresses to the template
    return render_template('profile.html', user=user, products=products, default_address=default_address, addresses=addresses)
@app.route('/edit_profile')
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch user information
    cursor.execute("SELECT username, email, contact_number FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template('edit_profile.html', user=user)

@app.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    if request.method == 'GET':
        if 'user_id' not in session:
            flash('You must be logged in to update your profile.', 'danger')
            return redirect(url_for('login'))

        # Render the update profile form
        return render_template('update_profile.html', user=session)  # Pass the user info if needed

    if request.method == 'POST':
        if 'user_id' not in session:
            flash('You must be logged in to update your profile.', 'danger')
            return redirect(url_for('login'))

        username = request.form.get('username')
        email = request.form.get('email')
        contact_number = request.form.get('contact_number')

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # Update user information
            cursor.execute("UPDATE users SET username = %s, email = %s, contact_number = %s WHERE id = %s",
                           (username, email, contact_number, session['user_id']))

            conn.commit()
            flash('Profile updated successfully!', 'success')
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            flash('An error occurred while updating your profile.', 'danger')
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

        return redirect(url_for('profile'))

@app.route('/manage_addresses', methods=['GET', 'POST'])
def manage_addresses():
    if request.method == 'POST':
        # Get form data
        address_line1 = request.form.get('address_line1')
        is_default = request.form.get('is_default') == 'on'
        user_id = session.get('user_id')  # Assuming you have user_id in session

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # Insert new address into the database
            cursor.execute("""
                INSERT INTO addresses (user_id, address_line1, is_default)
                VALUES (%s, %s, %s)
            """, (user_id, address_line1, is_default))

            conn.commit()
            flash('Address added successfully!', 'success')
            return redirect(url_for('manage_addresses'))
        except mysql.connector.Error as err:
            flash(f'Error: {err}', 'danger')
        finally:
            cursor.close()
            conn.close()

    # Fetch existing addresses from the database
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM addresses WHERE user_id = %s", (user_id,))
    addresses = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('manage_addresses.html', addresses=addresses)

@app.route('/add_address/<int:user_id>', methods=['POST'])
def add_addresses(user_id):
    addresses = request.form.getlist('addresses')  # Get a list of addresses from the form
    conn = get_db_connection()  # Get a database connection
    cursor = conn.cursor(dictionary=True)  # Use a cursor to execute queries

    user_found = False

    try:
        # Fetch the user to ensure they exist
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if user:
            user_found = True
            if not addresses:
                flash('No addresses provided!', 'warning')  # Handle empty address list
                return redirect(url_for('admin_users'))

            for address in addresses:
                # Logic to add each address to the user's address list
                cursor.execute("INSERT INTO addresses (user_id, address_line1) VALUES (%s, %s)", 
                               (user_id, address))

            conn.commit()  # Commit the changes to the database
            flash('Addresses added successfully!', 'success')
        else:
            flash('User  not found!', 'danger')
    except Exception as e:
        conn.rollback()  # Rollback in case of error
        flash(f'An error occurred while adding addresses: {str(e)}', 'danger')
    finally:
        cursor.close()  # Close the cursor
        conn.close()  # Close the database connection

    return redirect(url_for('admin_users'))  # Redirect to the user management page

@app.route('/delete_address/<int:address_id>', methods=['POST'])
def delete_address(address_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM addresses WHERE id = %s", (address_id,))
        conn.commit()
        flash('Address deleted successfully!', 'success')
    except mysql.connector.Error as err:
        flash(f'Error: {err}', 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('profile'))

@app.route('/set_default_address/<int:address_id>', methods=['POST'])
def set_default_address(address_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Reset all addresses to not default
        cursor.execute("UPDATE addresses SET is_default = FALSE WHERE user_id = (SELECT user_id FROM addresses WHERE id = %s)", (address_id,))
        # Set the selected address as default
        cursor.execute("UPDATE addresses SET is_default = TRUE WHERE id = %s", (address_id,))
        conn.commit()
        flash('Default address updated!', 'success')
    except mysql.connector.Error as err:
        flash(f'Error: {err}', 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('profile'))



def send_verification_email(email, code):
    msg = Message("Verify Your Email",
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[email])
    msg.body = f"Your verification code is: {code}. This code will expire in 1 hour."
    msg.html = f"""
    <h1>Welcome to Our Platform!</h1>
    <p>Your verification code is: <strong>{code}</strong></p>
    <p>This code will expire in 1 hour.</p>
    <p>If you didn't register for our platform, please ignore this email.</p>
    """
    mail.send(msg)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if username or email already exists
        cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Username or email already exists!', 'danger')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return render_template('register.html')

        if 'terms' not in request.form:
            flash('You must agree to the Terms and Conditions!', 'danger')
            return render_template('register.html')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        verification_code = str(random.randint(100000, 999999))
        expiration_time = datetime.now() + timedelta(hours=1)

        # Store registration data in session instead of database
        session['temp_registration'] = {
            'username': username,
            'email': email,
            'hashed_password': hashed_password,
            'verification_code': verification_code,
            'expiration_time': expiration_time
        }

        try:
            send_verification_email(email, verification_code)
            flash('Please check your email for the verification code.', 'success')
            return redirect(url_for('verify_email'))
        except Exception as e:
            print(f"Error sending email: {e}")
            flash('An error occurred during registration. Please try again later.', 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('register.html')

@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    if 'temp_registration' not in session:
        flash('Please register first.', 'warning')
        return redirect(url_for('register'))

    if request.method == 'POST':
        code = request.form['verification_code']
        temp_reg = session['temp_registration']

        if timezone.localize(datetime.now()) <= temp_reg['expiration_time']:
            if code == temp_reg['verification_code']:
                conn = get_db_connection()
                cursor = conn.cursor()

                try:
                    cursor.execute(
                        "INSERT INTO users (username, email, password, is_verified) VALUES (%s, %s, %s, %s)",
                        (temp_reg['username'], temp_reg['email'], temp_reg['hashed_password'], True)
                    )
                    conn.commit()
                    session.pop('temp_registration', None)
                    flash('Your email has been verified. You can now log in.', 'success')
                    return redirect(url_for('login'))
                except mysql.connector.Error as err:
                    print(f"Database error: {err}")
                    flash('An error occurred during registration. Please try again later.', 'danger')
                finally:
                    cursor.close()
                    conn.close()
            else:
                flash('Invalid verification code.', 'danger')
        else:
            session.pop('temp_registration', None)
            flash('Verification code has expired. Please register again.', 'danger')
            return redirect(url_for('register'))

    return render_template('verify_email.html')

@app.route('/resend_verification', methods=['GET', 'POST'])
def resend_verification():
    if 'temp_registration' not in session:
        flash('Please register first.', 'warning')
        return redirect(url_for('register'))

    if request.method == 'POST':
        temp_reg = session['temp_registration']
        new_code = str(random.randint(100000, 999999))
        new_expiration = datetime.now() + timedelta(hours=1)

        temp_reg['verification_code'] = new_code
        temp_reg['expiration_time'] = new_expiration
        session['temp_registration'] = temp_reg

        try:
            send_verification_email(temp_reg['email'], new_code)
            flash('A new verification code has been sent to your email.', 'success')
        except Exception as e:
            print(f"Error sending email: {e}")
            flash('An error occurred while sending the verification code. Please try again later.', 'danger')

        return redirect(url_for('verify_email'))

    return render_template('resend_verification.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Fetch user by username
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user:
            # Check if the password is correct
            if check_password_hash(user['password'], password):
                if user['is_verified']:
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']  # Store user role in session
                    flash('Login Successful!', 'success')
                    return redirect(url_for('home'))
                else:
                    flash('Please verify your email before logging in.', 'warning')
            else:
                flash('Invalid password!', 'danger')
        else:
            flash('Invalid username!', 'danger')

        cursor.close()
        conn.close()

    return render_template('login.html')



@app.route('/login/google')
def google_login():
    try:
        # Store the next URL in session if it exists
        if 'next' in request.args:
            session['next'] = request.args['next']
        
        # Redirect URI for Google OAuth
        redirect_uri = url_for('google_authorized', _external=True)
        print("Redirecting to Google for authorization...")  # Debug statement
        return oauth.google.authorize_redirect(redirect_uri)
    except Exception as e:
        print(f"Error initiating Google login: {e}")  # Debug statement
        flash('Failed to initiate Google login. Please try again.', 'danger')
        return redirect(url_for('login'))

@app.route('/login/google/authorized')
def google_authorized():
    print("Entered google_authorized route")
    try:
        # Get the token and user info from Google
        token = oauth.google.authorize_access_token()
        print("Access token received:", token)  # Debug statement
        
        # Fetch user info from Google
        resp = oauth.google.get('userinfo')
        user_info = resp.json()
        print("User  info fetched from Google:", user_info)  # Debug statement

        # Check if the email is available
        email = user_info.get('email')
        if not email:
            flash('Could not retrieve email from Google.', 'danger')
            return redirect(url_for('login'))

        # Use email prefix as username
        username = email.split('@')[0]

        # Establish a database connection
        conn = get_db_connection()
        if not conn:
            flash('Database connection error.', 'danger')
            return redirect(url_for('login'))

        cursor = conn.cursor(dictionary=True)

        try:
            # Check if the user already exists
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if not user:
                # If user does not exist, create a new user
                cursor.execute("""
                    INSERT INTO users (username, email, password, is_verified, role)
                    VALUES (%s, %s, %s, TRUE, 'user')
                """, (username, email, 'google_oauth'))  # Using a placeholder password
                conn.commit()

                # Fetch the newly created user
                cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                user = cursor.fetchone()

            # Set session data
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['email'] = user['email']

            flash(f'Successfully logged in as {username}!', 'success')

            # Redirect to the home page or the next page
            next_page = session.pop('next', None)
            return redirect(next_page if next_page else url_for('home'))

        except Exception as e:
            conn.rollback()
            print(f"Database error during login: {e}")  # Debug statement
            flash('An error occurred during login. Please try again.', 'danger')
            return redirect(url_for('login'))

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error during Google authorization: {e}")  # Debug statement
        flash('Failed to complete Google login. Please try again.', 'danger')
        return redirect(url_for('login'))

# Add this helper function to check if user is logged in
def is_logged_in():
    return 'user_id' in session

# Logout route
@app.route('/logout')
def logout():
    # Clear the user's session
    session.clear()
    
    # If using Google OAuth, you may want to revoke the token
    if 'google_token' in session:
        try:
            token = session['google_token']
            oauth.google.revoke_token(token)
        except:
            # If revoking fails, we'll just log them out locally
            pass

    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))  # or wherever you want to redirect after logout
    
@app.route('/login/facebook')
def facebook_login():
    return facebook.authorize(callback=url_for('facebook_authorized', _external=True))

@app.route('/login/facebook/authorized')
def facebook_authorized():
    resp = facebook.authorized_response()
    if resp is None or resp.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )
    session['facebook_token'] = (resp['access_token'], '')
    me = facebook.get('/me?fields=id,name,email')
    return create_or_login_oauth_user('facebook', me.data['email'], me.data['name'])

def create_or_login_oauth_user(provider, email, name):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Check if user exists
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            # User exists, log them in
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f'Logged in successfully via {provider}!', 'success')
        else:
            # Create new user
            username = email.split('@')[0]  # Use email prefix as username
            hashed_password = generate_password_hash(str(random.getrandbits(128)))
            
            cursor.execute(
                "INSERT INTO users (username, email, password, is_verified) VALUES (%s, %s, %s, %s)",
                (username, email, hashed_password, True)
            )
            conn.commit()
            
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            new_user = cursor.fetchone()
            
            session['user_id'] = new_user['id']
            session['username'] = username
            flash(f'Account created and logged in via {provider}!', 'success')

        return redirect(url_for('home'))

    except Exception as e:
        print(f"Database error: {str(e)}")
        flash('An error occurred during authentication.', 'danger')
        return redirect(url_for('login'))

    finally:
        cursor.close()
        conn.close()

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/password_reset', methods=['GET', 'POST'])
def password_reset():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            # Generate a password reset token (using a random code for simplicity)
            reset_token = str(random.randint(100000, 999999))
            expiration_time = datetime.now() + timedelta(hours=1)  # Optional: you can keep this or remove it

            # Store the token and its expiration in the database
            cursor.execute("UPDATE users SET reset_token = %s, reset_token_expiration = %s WHERE email = %s",
                           (reset_token, expiration_time, email))
            conn.commit()

            # Send reset email
            reset_link = url_for('password_reset_confirm', token=reset_token, _external=True)
            send_password_reset_email(email, reset_link)

            flash('A password reset link has been sent to your email.', 'success')
        else:
            flash('Email address not found.', 'danger')

        cursor.close()
        conn.close()
        return redirect(url_for('login'))

    return render_template('password_reset.html')
def send_password_reset_email(email, reset_link):
    msg = Message("Password Reset Request",
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[email])
    msg.body = f"To reset your password, click the link below:\n{reset_link}"
    msg.html = f"""
    <h1>Password Reset Request</h1>
    <p>To reset your password, click the link below:</p>
    <p><a href="{reset_link}">Reset Password</a></p>
    """
    mail.send(msg)

@app.route('/password_reset_confirm/<token>', methods=['GET', 'POST'])
def password_reset_confirm(token):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE reset_token = %s", (token,))
    user = cursor.fetchone()

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password == confirm_password:
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
            cursor.execute("UPDATE users SET password = %s, reset_token = NULL, reset_token_expiration = NULL WHERE id = %s",
                           (hashed_password, user['id']))
            conn.commit()
            flash('Your password has been reset successfully. You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Passwords do not match!', 'danger')

    cursor.close()
    conn.close()

    if user:  # Optional: You can check for expiration if you want
        return render_template('password_reset_confirm.html', token=token)
    else:
        flash('This password reset token is invalid or has expired.', 'danger')
        return redirect(url_for('password_reset'))
    
# Route to list products
@app.route('/products')
def products():
    products = []
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM products WHERE is_archived = FALSE")
        products = cursor.fetchall()
    except mysql.connector.Error as err:
        print("Error fetching products: {}".format(err))
        flash('Could not retrieve products. Please try again later.', 'danger')
    finally:
        cursor.close()
        conn.close()
    return render_template('products.html', products=products)

# Route to add a new product
@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    if 'user_id' not in session:
        flash('You must be logged in to add a product.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']
        stock = request.form['stock']
        category_id = request.form['category_id']
        seller_id = session['user_id']

        # if stock is None:
        #     flash('Stock is required.', 'danger')
        #     return redirect(request.url)
        
        stock = request.form.get('stock')  
        
        # Handle file upload
        if 'image' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['image']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            image_url = f'/static/uploads/{filename}'
        else:
            flash('Invalid file type', 'danger')
            return redirect(request.url)

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO products (name, description, price, stock, category_id, seller_id, image_url) VALUES (%s, %s, %s, %s, %s, %s, %s)", 
                           (name, description, price, stock, category_id, seller_id, image_url))
            conn.commit()
            flash('Product added successfully!', 'success')
            return redirect(url_for('products'))
        except mysql.connector.Error as err:
            flash('Error: ' + str(err), 'danger')
        finally:
            cursor.close()
            conn.close()

    # Fetch categories for the dropdown
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM categories")
    categories = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('add_product.html', categories=categories)

# Route to update a product
@app.route('/update_product/<int:id>', methods=['GET', 'POST'])
def update_product(id):
    if 'user_id' not in session:
        flash('You must be logged in to edit a product.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE id = %s", (id,))
    product = cursor.fetchone()

    if product is None:
        flash('Product not found.', 'danger')
        return redirect(url_for('products'))

    if product['seller_id'] != session['user_id']:
        flash('You do not have permission to edit this product.', 'danger')
        return redirect(url_for('products'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']
        stock = request.form['stock']
        category_id = request.form['category_id']
        
        if stock is None:
            flash('Stock is required.', 'danger')
            return redirect(request.url)
        # Handle file upload
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                image_url = f'/static/uploads/{filename}'
            else:
                image_url = product['image_url']  # Keep the existing image if no new file is uploaded
        else:
            image_url = product['image_url']

        try:
            cursor.execute("UPDATE products SET name = %s, description = %s, price = %s, stock = %s, category_id = %s, image_url = %s WHERE id = %s", 
                           (name, description, price, stock, category_id, image_url, id))
            conn.commit()
            flash('Product updated successfully!', 'success')
            return redirect(url_for('products'))
        except mysql.connector.Error as err:
            flash('Error: ' + str(err), 'danger')
        finally:
            cursor.close()
            conn.close()

    # Fetch categories for the dropdown
    cursor.execute("SELECT * FROM categories")
    categories = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('update_product.html', product=product, categories=categories)

# Route to archive a product
@app.route('/archive_product/<int:id>', methods=['POST'])
def archive_product(id):
    if 'user_id' not in session:
        flash('You must be logged in to archive a product.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("UPDATE products SET is_archived = TRUE WHERE id = %s AND seller_id = %s", (id, session['user_id']))
        conn.commit()
        flash('Product archived successfully!', 'success')
    except mysql.connector.Error as err:
        flash('Error: ' + str(err), 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('products'))

# Route to manage inventory
@app.route('/inventory')
def inventory():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE seller_id = %s", (session['user_id'],))
    products = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('inventory.html', products=products)

# Route to view product details
@app.route('/view_product/<int:id>')
def view_product(id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Join products with categories to get category name
    cursor.execute("""
        SELECT 
            p.*, 
            c.name AS category_name 
        FROM 
            products p
        JOIN 
            categories c ON p.category_id = c.id
        WHERE 
            p.id = %s
    """, (id,))
    
    product = cursor.fetchone()
    
    # Get related products in the same category
    if product:
        cursor.execute("""
            SELECT 
                id, name, price, image_url 
            FROM 
                products 
            WHERE 
                category_id = %s AND id != %s 
            LIMIT 4
        """, (product['category_id'], id))
        related_products = cursor.fetchall()
    else:
        related_products = []
    
    cursor.close()
    conn.close()

    if product is None:
        flash('Product not found.', 'danger')
        return redirect(url_for('products'))

    return render_template(
        'view_product.html', 
        product=product, 
        related_products=related_products
    )

# Optional: Add a method to get more sophisticated related products
def get_related_products(category_id, current_product_id, limit=4):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # More advanced related product selection 
    # (e.g., by price range, popularity, etc.)
    cursor.execute("""
        SELECT 
            id, name, price, image_url 
        FROM 
            products 
        WHERE 
            category_id = %s 
            AND id != %s 
        ORDER BY 
            RAND()  # Random selection
        LIMIT %s
    """, (category_id, current_product_id, limit))
    
    related_products = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return related_products

# Route to delete a product
@app.route('/delete_product/<int:id>', methods=['GET', 'POST'])
def delete_product(id):
    if 'user_id' not in session:
        flash('You must be logged in to delete a product.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM products WHERE id = %s", (id,))
        product = cursor.fetchone()

        if product is None:
            flash('Product not found.', 'danger')
            return redirect(url_for('products'))

        if product['seller_id'] != session['user_id']:
            flash('You do not have permission to delete this product.', 'danger')
            return redirect(url_for('products'))

        if request.method == 'POST':
            cursor.execute("DELETE FROM products WHERE id = %s", (id,))
            conn.commit()
            flash('Product deleted successfully!', 'success')
            return redirect(url_for('products'))
        else:
            return render_template('delete_product.html', product=product)

    except mysql.connector.Error as err:
        flash('Error: ' + str(err), 'danger')
        return redirect(url_for('products'))

    finally:
        cursor.close()
        conn.close()

# Route to list categories
@app.route('/categories')
def categories():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM categories")
    categories = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('categories.html', categories=categories)

# Route to add a new category
@app.route('/add_category', methods=['POST'])
def add_category():
    if 'user_id' not in session:
        flash('You must be logged in to add a category.', 'danger')
        return redirect(url_for('login'))

    name = request.form['name']
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO categories (name) VALUES (%s)", (name,))
        conn.commit()
        flash('Category added successfully!', 'success')
    except mysql.connector.Error as err:
        flash('Error: ' + str(err), 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('categories'))

# Route to delete a category
@app.route('/delete_category/<int:id>', methods=['POST'])
def delete_category(id):
    if 'user_id' not in session:
        flash('You must be logged in to delete a category.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM categories WHERE id = %s", (id,))
        conn.commit()
        flash('Category deleted successfully!', 'success')
    except mysql.connector.Error as err:
        flash('Error: ' + str(err), 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('categories'))

# Function to check allowed file types for uploads
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

@app.before_request
def init_cart():
    if 'cart' not in session:
        session['cart'] = []

# Product Search Functionality
@app.route('/products/search', methods=['GET'])
def search():
    query = request.args.get('query', '')
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        # SQL query to search for products by name or category
        cursor.execute("""
            SELECT p.*, c.name AS category_name 
            FROM products p 
            JOIN categories c ON p.category_id = c.id 
            WHERE p.name LIKE %s OR c.name LIKE %s
        """, ('%' + query + '%', '%' + query + '%'))
        products = cursor.fetchall()
    except mysql.connector.Error as err:
        flash('Error fetching search results.', 'danger')
        products = []
    finally:
        cursor.close()
        conn.close()
    return render_template('search_results.html', products=products, query=query)

@app.route('/products/filter', methods=['GET'])
def filter_products():
    # Get filtering and sorting parameters from the request
    min_price = request.args.get('min_price', type=float)
    max_price = request.args.get('max_price', type=float)
    sort_by = request.args.get('sort_by', default='name')  # Default sorting by name
    order = request.args.get('order', default='asc')  # Default order ascending

    # Build the SQL query based on filters and sorting
    query = "SELECT * FROM products WHERE 1=1"
    filters = []

    if min_price is not None:
        query += " AND price >= %s"
        filters.append(min_price)
    if max_price is not None:
        query += " AND price <= %s"
        filters.append(max_price)

    if sort_by in ['price', 'popularity', 'ratings', 'name']:  # Add more fields as needed
        query += f" ORDER BY {sort_by} {order.upper()}"

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(query, tuple(filters))
        products = cursor.fetchall()
    except mysql.connector.Error as err:
        flash('Error fetching products.', 'danger')
        products = []
    finally:
        cursor.close()
        conn.close()
    
    return render_template('products.html', products=products)

@app.before_request
def init_cart():
    """Initialize the shopping cart in the session if it doesn't exist."""
    session.setdefault('cart', [])

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    """Add a product to the shopping cart."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()
    
    if product:
        # Check if the product is already in the cart
        for item in session['cart']:
            if item['id'] == product['id']:
                item['quantity'] += 1  # Increment quantity if already in cart
                break
        else:
            # Add new product to cart
            session['cart'].append({
                'id': product['id'],
                'name': product['name'],
                'price': product['price'],
                'quantity': 1
            })
        flash('Product added to cart!', 'success')
    else:
        flash('Product not found!', 'danger')

    cursor.close()
    conn.close()
    return redirect(url_for('view_cart'))

@app.route('/remove_from_cart/<int:product_id>', methods=['POST'])
def remove_from_cart(product_id):
    """Remove a product from the shopping cart completely."""
    session['cart'] = [item for item in session['cart'] if item['id'] != product_id]
    flash('Product removed from cart!', 'success')
    return redirect(url_for('view_cart'))

@app.route('/decrement_quantity/<int:product_id>', methods=['POST'])
def decrement_quantity(product_id):
    """Decrement the quantity of a product in the shopping cart."""
    for item in session['cart']:
        if item['id'] == product_id:
            if item['quantity'] > 1:
                item['quantity'] -= 1  # Decrease quantity
                flash('Product quantity decreased!', 'success')
            else:
                # If quantity is 1, remove the product from the cart
                session['cart'].remove(item)
                flash('Product removed from cart!', 'success')
            break
    else:
        flash('Product not found in cart!', 'danger')

    return redirect(url_for('view_cart'))

@app.route('/cart', methods=['GET'])
def view_cart():
    """Display the shopping cart."""
    total_price = 0.0
    for item in session['cart']:
        try:
            price = float(item['price'])  # Convert price to float
            quantity = int(item['quantity'])  # Convert quantity to int
            total_price += price * quantity  # Calculate total price
        except (ValueError, TypeError):
            continue  # Skip this item if there's an error

    return render_template('cart.html', cart_items=session['cart'], total_price=total_price)

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    """Process the checkout."""
    if request.method == 'POST':
        # Handle the checkout logic here (e.g., payment processing)
        session.pop('cart', None)  # Clear the cart after checkout
        flash('Your order has been processed successfully!', 'success')
        return redirect(url_for('checkout_confirmation'))  # Redirect to confirmation page

    cart_items = session.get('cart', [])
    total_price = 0.0  # Initialize total price

    for item in cart_items:
        try:
            price = float(item['price'])  # Convert price to float
            quantity = int(item['quantity'])  # Convert quantity to int
            total_price += price * quantity  # Calculate total price
        except (ValueError, TypeError):
            continue  # Skip this item if there's an error

    return render_template('checkout.html', cart_items=cart_items, total_price=total_price)

@app.route('/checkout_confirmation')
def checkout_confirmation():
    """Display the order confirmation page."""
    return render_template ('checkout_confirmation.html')


if __name__ == '__main__':
    app.run(debug=True)