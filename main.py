from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
import smtplib
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import ForeignKey
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ChangePasswordForm
from flask_migrate import Migrate
from flask_gravatar import Gravatar
import secrets
import bleach
import datetime
from functools import wraps

# CONSTANT VARIABLES
user_email = "user@email.com"
user_password = "very-secure-user-password"


# CREATE SECRET TOKEN FOR FLASK WTFORMS AND FLASK SERVER
secret = secrets.token_hex(16)
app = Flask(__name__)
app.config['SECRET_KEY'] = secret
ckeditor = CKEditor(app)
Bootstrap(app)

# CREATE AND CONNECT TO DATABASE
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# CODE BELOW IS NEEDED ONLY TO MIGRATE DATABASES WHEN CREATING DATABASE RELATIONSHIPS. IT'S CALLED ONLY ONCE
# migrate = Migrate(app, db)
# mapper_registry = registry()

# CREATE GRAVATAR OBJECT FOR ASSIGNING RANDOM AVATARS TO USERS IN THE COMMENT SECTION
gravatar = Gravatar(
    app,
    size=100,
    rating='g',
    default='retro',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None
)


# CONFIGURE DATABASE TABLES AND CREATE DEPENDENCIES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"  # This tells the database what to name the table. If not specified, it'll default to the class name
    id = db.Column(db.Integer, primary_key=True)

    # Creates ForeignKey, 'users.id'. The 'users' refers to the table of name User
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # (Child r/ship to User) Create reference to the User Object, the 'posts' refers to the posts property in the User class
    author = db.relationship('User', back_populates='posts')

    # Parent relationship to Comment
    comments = relationship('Comment', back_populates='parent_post')

    def __repr__(self):
        return f'<Blog: {self.title}>'


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    # This will act like a list of BlogPost objects attached to each user
    # The 'author' refers to the author property in the BlogPost class.
    # (Parent relationship to Blogpost)
    posts = db.relationship('BlogPost', back_populates='author')

    # Comment_author refers to the comment_author property in the Comment class
    # (Parent relationship to Comment)
    comments = db.relationship('Comment', back_populates='comment_author')

    def __repr__(self):
        return f'{self.name}'


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)

    # Child relationship to User Table
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = db.relationship('User', back_populates='comments')

    # Child relationship to BlogPost table
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = db.relationship('BlogPost', back_populates='comments')
    text = db.Column(db.Text, nullable=False)


# CODE BELOW NEEDS TO BE RUN ONCE TO INITIALIZE AND CREATE THE DATABASE
# if __name__ == '__main__':
#     with app.app_context():
#         db.create_all()


# AN ADMIN DECORATOR FUNCTION
def admin_only(function):
    """Allows only a user with admin property to access decorated function"""
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or (current_user.is_authenticated and current_user.id != 1):
            abort(403)
        return function(*args, **kwargs)

    return decorated_function


# FLASK VARIABLE THAT CAN BE USED ACROSS ALL PAGES
@app.context_processor
def update_current_year():
    """Ensures the 'year' at the footer remains up to date always"""
    return {'current_year': datetime.datetime.now().year}


# DEFINE ALL WEBSITE PAGES AND THEIR LOGIC
@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists! Login instead', 'error')
            return redirect(url_for('login'))
        else:  # Encrypt password
            encrypted_password = generate_password_hash(
                password=form.password.data,
                method='pbkdf2:sha256',
                salt_length=8
            )

            new_user = User(
                email=form.email.data,
                password=encrypted_password,
                name=form.name.data
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)  # Login user after registration
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


# Create login manager object and initialize
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password=password):
            login_user(user, remember=True)
            return redirect(url_for('get_all_posts'))
        else:
            flash('Invalid username or password. Please check your spelling and try again!', 'error')
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


# Sanitize html gotten from the 'body' field
def sanitize_html(html):
    """Ensures that HTML passed into the database contains only acceptable HTML tags to prevent XSS"""
    # Specify the allowed HTML tags and attributes
    allowed_tags = ['a', 'abbr', 'acronym', 'address', 'b', 'br', 'div', 'dl', 'dt',
                    'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img',
                    'li', 'ol', 'p', 'pre', 'q', 's', 'small', 'strike',
                    'span', 'sub', 'sup', 'table', 'tbody', 'td', 'tfoot', 'th',
                    'thead', 'tr', 'tt', 'u', 'ul']

    allowed_attrs = {
        'a': ['href', 'target', 'title'],
        'img': ['src', 'alt', 'width', 'height'],
    }

    cleaned_html = bleach.clean(html, tags=allowed_tags, attributes=allowed_attrs)
    return cleaned_html


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('You need to login or register to comment')
            return redirect(url_for('login'))

        new_comment = Comment(
            text=sanitize_html(form.comment.data),
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


# EMAIL SENDING LOGIC
def send_email(name, email, phone, message):
    """Sends an email to the admin with the contents of the Contact page"""
    with smtplib.SMTP('smtp.gmail.com') as connection:
        connection.starttls()
        connection.login(user=user_email, password=user_password)
        connection.sendmail(
            from_addr=user_email,
            to_addrs='admin@email.com',
            msg=f'Subject: NEW ENQUIRY\n\nName: {name}\nEmail: {email}\nPhone: {phone}'
                f'\nMessage: {message}'
        )
    print('Email sent!')


@app.route("/contact", methods=['POST', 'GET'])
def contact():
    """Allows users to contact the admin. Logged in or not."""
    if request.method == 'POST':
        data = request.form
        send_email(data["name"], data["email"], data["phone-number"], data["message"])
        return render_template('contact.html', msg_sent=True)
    return render_template('contact.html', msg_sent=False)


@app.route("/new-post", methods=['GET', 'POST'])
@login_required  # Login required decorator ensures only logged in users can access page
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=sanitize_html(form.body.data),
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    """Only allows users to edit posts they created and none else except admins, who can edit all posts"""
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = sanitize_html(edit_form.body.data)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_password = form.current_password.data
        user = User.query.filter_by(email=current_user.email).first()

        if user and check_password_hash(user.password, password=current_password):
            new_password = form.new_password.data
            retyped_password = form.retype_password.data
            if new_password != retyped_password:
                flash('Passwords do not match!', 'error')
                return redirect(url_for('account'))
            else:
                encrypted_password = generate_password_hash(
                    password=new_password,
                    method='pbkdf2:sha256',
                    salt_length=8
                )

                user.password = encrypted_password
                db.session.commit()
                logout_user()
                flash('Success! Please log in again', 'success')
                return redirect(url_for('login'))
        else:
            flash('You may not be logged in or password is incorrect!', 'error')
            return redirect(url_for('account'))
    return render_template('account.html', form=form)


@app.route("/delete/<int:post_id>")
@admin_only  # Only admins can delete a post
def delete_post(post_id):
    """Only users with admin properties can delete a post"""
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


# INITIALIZE THE FLASK SERVER
if __name__ == "__main__":
    app.run(debug=True)


# NEW_USER: new_user@email.com PASSWORD: 87654321

