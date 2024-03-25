from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, url_for, redirect, flash, request
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_admin import Admin, expose
from flask_admin.contrib.sqla import ModelView
from flask_wtf import FlaskForm
from wtforms import SelectField
from wtforms.validators import InputRequired
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import InputRequired
import os
from werkzeug.utils import secure_filename
from datetime import datetime
from flask_admin.form import Select2Widget
from cryptography.fernet import Fernet


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///base.db'
app.config['SECRET_KEY'] = 'avvrevf87ydvkey'
db = SQLAlchemy(app)
admin = Admin(app, template_mode='bootstrap3', name='INFBEZ')
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
admin._menu = admin._menu[1:]


#докеументы при загрузке(где хранить)
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static/files')
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'docx'}


#Для request.user
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#Генерация кода для зашифирования инвормации на базе
# key = Fernet.generate_key()
key = b'Y_oV0MwHgA6dlTW2rb-ZryyPZpbJ9hT5KOsT1C4M6u0='
fernet = Fernet(key)
print(key)


class AdminView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin()
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))
    
    form_extra_fields = {
        'role': SelectField(
            'Role',
            choices=[
                ('admin', 'Admin'), 
                ('user', 'User'), 
                ('moderator', 'Moderator'),
                ('editor', 'Editor'), 
            ],
            widget=Select2Widget(),
            description='Choose user role'
        )
    }

#Формы регистрации, админ -----------------------------------------------------
class Registerform(FlaskForm):
	"""Регистрация пользоватля """
	username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Имя"})
	password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Пароль"})
	submit = SubmitField('Зарегистрироваться')
	def validate_username(self,username):
		existing_user_username = User.query.filter_by(username=username.data).first()
		if existing_user_username:
			flash('Это имя пользователя уже существует. Пожалуйста, выберите другой вариант.', 'error')
			raise ValidationError('Это имя пользователя уже существует. Пожалуйста, выберите другой вариант.')


class Loginform(FlaskForm):
	"""Вход пользователя """
	username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Имя"})
	password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Пароль"})
	submit = SubmitField('Войти')


#Модели --------------------------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(20), nullable=True) 
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    documents = db.relationship('Document', back_populates='user')
	
    def is_admin(self):
        return self.role == 'admin'
    

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    _name = db.Column('name', db.String(255), nullable=False)
    _description = db.Column('description', db.Text())
    category = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    _filename = db.Column('filename', db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', back_populates='documents')
 
    @property
    def name(self):
        if isinstance(self._name, bytes):
            return fernet.decrypt(self._name).decode()
        return self._name

    @name.setter
    def name(self, value):
        self._name = fernet.encrypt(value.encode())

    @property
    def description(self):
        if self._description:
            if isinstance(self._description, bytes):
                return fernet.decrypt(self._description).decode()
            return self._description
        return None

    @description.setter
    def description(self, value):
        if value:
            self._description = fernet.encrypt(value.encode())
        else:
            self._description = None

    @property
    def filename(self):
        if self._filename:
            if isinstance(self._filename, bytes):
                return fernet.decrypt(self._filename).decode()
            return self._filename
        return None

    @filename.setter
    def filename(self, value):
        if value:
            self._filename = fernet.encrypt(value.encode())
        else:
            self._filename = None

 
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)


#Добавим модели в админ
admin.add_view(AdminView(User, db.session))
admin.add_view(AdminView(Document, db.session))
admin.add_view(AdminView(Category, db.session))


#Страницы templates-------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Loginform()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        else:
            return render_template('login.html', form=form)

    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
	logout_user()
	return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
	form = Registerform()
	"""Кеширует пароль"""
	if form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
		new_user = User(username=form.username.data, password=hashed_password) 
		db.session.add(new_user)
		db.session.commit()

		return redirect(url_for('login'))

	return render_template('register.html', form=form)


@app.route('/')
def index():
    documents = Document.query.order_by(Document.created_at.desc()).all()[:3] #сначала новые получаю
    categorys = Category.query.all()
    
    # Расшифровка данных
    decrypted_documents = []
    for doc in documents:
        decrypted_doc = {
            'id': doc.id,
            'name': doc.name,
            'description': doc.description,
            'filename': doc.filename,
            'category': doc.category,
            'created_at': doc.created_at,
            'user': doc.user
        }
        # Расшифровка данных, если они не пустые
        if doc.name:
            decrypted_doc['name'] = doc.name
        if doc.description:
            decrypted_doc['description'] = doc.description
        if doc.filename:
            decrypted_doc['filename'] = doc.filename
        
        decrypted_documents.append(decrypted_doc)
    
    return render_template('index.html', documents=decrypted_documents, categorys=categorys) 


@app.route('/documents')
@login_required
def documents():
    documents = Document.query.order_by(Document.created_at.desc()).all() #сначала новые получаю
    categorys = Category.query.all()

    # Расшифровка данных
    decrypted_documents = []
    for doc in documents:
        decrypted_doc = {
            'id': doc.id,
            'name': doc.name,
            'description': doc.description,
            'filename': doc.filename,
            'category': doc.category,
            'created_at': doc.created_at,
            'user': doc.user
        }
        # Расшифровка данных, если они не пустые
        if doc.name:
            decrypted_doc['name'] = doc.name
        if doc.description:
            decrypted_doc['description'] = doc.description
        if doc.filename:
            decrypted_doc['filename'] = doc.filename
        
        decrypted_documents.append(decrypted_doc)

    return render_template('documents.html', documents=decrypted_documents, categorys=categorys)


#Добавляем документ
@app.route('/add_document', methods=['GET', 'POST'])
@login_required
def add_document():
    categorys = Category.query.all()
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        category = request.form.get('category')
        file = request.files['file']

        if name and file:
            new_document = Document(name=name, description=description, filename=file.filename, user=current_user, created_at=datetime.utcnow(), category=category)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
            file.save(file_path)
            # базу данных
            db.session.add(new_document)
            db.session.commit()
            
            flash('Документ успешно добавлен!', 'success')
            return redirect(url_for('index'))

    return render_template('add_document.html', categorys=categorys)


#Добавляем ltcwtgktye
@app.route('/add_category', methods=['GET', 'POST'])
@login_required
def add_category():
    if request.method == 'POST':
        name = request.form.get('name')

        if name:
            new_document = Category(name=name)
            # базу данных
            db.session.add(new_document)
            db.session.commit()
            
            flash('Дисциплина успешно добавлена!', 'success')
            return redirect(url_for('index'))

    return render_template('add_category.html')



if __name__ == '__main__':
    app.run(debug=True)
