import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///requests.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 *1024* 1024  # 16MB max-limit
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'default-secret-key'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'admin_login'

class RequestModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(500), nullable=False)
    requester = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default='pending')
    attachment = db.Column(db.String(255))
    admin_reply = db.Column(db.String(500))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/request', methods=['GET', 'POST'])
def request_page():
    if request.method == 'POST':
        message = request.form['message']
        requester = request.form['requester']

        new_request = RequestModel(message=message, requester=requester)

        if 'attachment' in request.files:
            file = request.files['attachment']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                new_request.attachment = filename

        db.session.add(new_request)
        db.session.commit()
        return redirect(url_for('request_char'))
    return render_template('request.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def request_char():
    requests = RequestModel.query.order_by(RequestModel.id.desc()).all()
    return render_template('request_char.html', requests=requests)

@app.route('/approved')
def approved_requests():
    approved_requests = RequestModel.query.filter_by(status='approved').order_by(RequestModel.id.desc()).all()
    return render_template('approved_requests.html', requests=approved_requests)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_requests'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('admin_requests'))
        else:
            flash('Invalid username or password')
    return render_template('admin_login.html')

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('request_char'))

@app.route('/admin/requests')
@login_required
def admin_requests():
    requests = RequestModel.query.order_by(RequestModel.id.desc()).all()
    return render_template('admin_requests.html', requests=requests)

@app.route('/request/<int:id>/<action>')
@login_required
def update_request(id, action):
    req = RequestModel.query.get_or_404(id)
    if action == 'approve':
        req.status = 'approved'
    elif action == 'deny':
        req.status = 'denied'
    db.session.commit()
    return redirect(url_for('admin_requests'))

@app.route('/request/<int:id>/reply', methods=['POST'])
@login_required
def admin_reply(id):
    req = RequestModel.query.get_or_404(id)
    reply = request.form['reply']
    req.admin_reply = reply
    db.session.commit()
    return redirect(url_for('admin_requests'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create an admin user if it doesn't exist
        admin_username = os.environ.get('ADMIN_USERNAME') or 'admin'
        admin_password = os.environ.get('ADMIN_PASSWORD') or 'default_password'
        if not User.query.filter_by(username=admin_username).first():
            admin = User(username=admin_username)
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()
    app.run(host='0.0.0.0', port=5000, debug=True)
