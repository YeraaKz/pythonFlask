import secrets
import re

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import logout_user, login_user, current_user, LoginManager, UserMixin, login_required
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Regexp

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root@localhost/flask_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Установка представления, на которое будет перенаправлен неавторизованный пользователь
login_manager.login_view = 'login'
class Car(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    brand = db.Column(db.String(80), nullable=False)
    model = db.Column(db.String(120), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(300))
    fuel_type = db.Column(db.String(50))
    transmission = db.Column(db.String(50))
    condition_status = db.Column(db.String(100))
    mileage = db.Column(db.Integer)
    body_type = db.Column(db.String(50))
    engine_power = db.Column(db.Integer)
    engine_volume = db.Column(db.Integer)
    color = db.Column(db.String(50))
    drive_unit = db.Column(db.String(50))
    warranty = db.Column(db.String(100))
    description = db.Column(db.Text)
    price = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


    def __repr__(self):
        return f'<Car {self.brand} {self.model}>'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    cars = db.relationship('Car', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

def unique_username(form, field):
    if User.query.filter_by(username=field.data).first():
        raise ValidationError('Bu kullanıcı adı zaten alınmış. Lütfen başka bir tane seçin.')

def unique_email(form, field):
    if User.query.filter_by(email=field.data).first():
        raise ValidationError('Bu e-posta adresi zaten kullanılmakta. Lütfen başka bir tane seçin.')

def unique_phone(form, field):
    pattern = r'\+?[0-9]{3}-?[0-9]{2}-?[0-9]{7}'
    if not re.match(pattern, field.data):
        raise ValidationError('Geçerli bir telefon numarası girin.')
    if User.query.filter_by(phone=field.data).first():
        raise ValidationError('Bu telefon numarası zaten kullanılmakta. Lütfen başka bir tane seçin.')

class RegistrationForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[DataRequired(), unique_username])
    email = StringField('E-posta', validators=[DataRequired(), Email(), unique_email])
    phone = StringField('Telefon', validators=[DataRequired(), unique_phone])
    password = PasswordField('Şifre', validators=[DataRequired()])
    submit = SubmitField('Kayıt Ol')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Şifre', validators=[DataRequired()])
    submit = SubmitField('Giriş Yap')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        phone = form.phone.data
        password = form.password.data

        new_user = User(username=username, email=email, phone=phone)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash('Kayıt başarılı!')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Поиск пользователя в базе данных
        user = User.query.filter_by(username=username).first()

        # Проверка учетных данных пользователя
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Yanlış kimlik bilgileri')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/protected')
@login_required
def protected():
    return f"Hello secured user, {current_user.id}!"


@app.route('/')
def index():
    cars = Car.query.all()
    return render_template('index.html', cars=cars)

@app.route('/add', methods=('GET', 'POST'))
@login_required
def add():
    if request.method == 'POST':
        brand = request.form['brand']
        model = request.form['model']
        year = request.form['year']
        image = request.form['image']
        fuel_type = request.form['fuel_type']
        color = request.form['color']
        body_type = request.form['body_type']
        condition_status = request.form['condition_status']
        description = request.form['description']
        drive_unit = request.form['drive_unit']
        engine_power = request.form['engine_power']
        engine_volume = request.form['engine_volume']
        mileage = request.form['mileage']
        transmission = request.form['transmission']
        warranty = request.form['warranty']
        user_id = current_user.id
        new_car = Car(brand=brand, model=model, year=year, image=image,
                      fuel_type=fuel_type, color=color, body_type=body_type,
                      condition_status=condition_status, description=description,
                      drive_unit=drive_unit, engine_power=engine_power, engine_volume=engine_volume,
                      mileage=mileage, transmission=transmission, warranty=warranty, user_id=user_id)
        db.session.add(new_car)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('add.html')

@app.route('/my_cars')
@login_required
def my_cars():
    cars = Car.query.filter_by(user_id=current_user.id).all()
    print(cars)
    return render_template('my_cars.html', cars=cars)

@app.route('/edit/<int:id>', methods=('GET', 'POST'))
@login_required
def edit(id):
    car = Car.query.get_or_404(id)
    if request.method == 'POST':
        car.brand = request.form['brand']
        car.model = request.form['model']
        car.year = request.form['year']

        db.session.commit()
        return redirect(url_for('my_cars'))
    return render_template('edit.html', car=car)

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    car = Car.query.get_or_404(id)
    db.session.delete(car)
    db.session.commit()
    return redirect(url_for('my_cars'))

@app.route('/car/<int:id>')
@login_required
def car_detail(id):
    car = Car.query.get_or_404(id)
    print(car.fuel_type)  # Для отладки
    return render_template('car_detail.html', car=car)

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
