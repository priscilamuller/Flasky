from datetime import datetime
from flask import Flask, render_template, flash, request, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, login_user, LoginManager, login_required,logout_user, current_user
from flask_migrate import Migrate
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, EqualTo



#Flask Instance
app = Flask(__name__)
#Add Database SQLite
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#Secret Key
app.config['SECRET_KEY'] = 'password123'



#Initialize Bootstrap, Database, Migrate, Moment
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
moment = Moment(app)



#Database Model Users
class Users(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(79), nullable=False, index=True)
    email = db.Column(db.String(79), nullable=False, unique=True, index=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    password_hash = db.Column(db.String(20))

    @property
    def password(self):
        raise AttributeError('erro de password')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<Name %r>' % self.name



#Database Model Items
class Items(db.Model):
    __tablename__ = 'items'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.Integer, nullable=False, index=True)
    type = db.Column(db.String(3), nullable=False)
    name = db.Column(db.String(100), nullable=False, index=True)
    value = db.Column(db.Float, nullable=False, index=True)

    def __repr__(self):
        return '<Name %r>' % self.name

#Flask Login Stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


#Form Index
class LoginForm(FlaskForm):
    email = StringField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])
    submit = SubmitField('Entrar')

#Form Search Items
class SearchForm(FlaskForm):
    search = StringField(validators=[DataRequired()])
    submit = SubmitField('Buscar')

#Form Add/Update/Delete User
class UserForm(FlaskForm):
    name = StringField(validators=[DataRequired()])
    email = StringField(validators=[DataRequired()])
    password_hash = PasswordField('Senha', validators=[
        DataRequired(), EqualTo('password_hash2')])
    password_hash2 = PasswordField('Confirme sua senha', validators=[
        DataRequired()])
    submit = SubmitField('Enviar')

#form Add/Update/Delete Item
class ItemForm(FlaskForm):
    code = StringField(validators=[DataRequired()])
    type = StringField(validators=[DataRequired()])
    name = StringField(validators=[DataRequired()])
    value = StringField(validators=[DataRequired()])
    submit = SubmitField('Enviar')



#Index
@app.route('/', methods=['GET', 'POST'])
def index():
    form=LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email = form.email.data).first()
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                return redirect(url_for('admin'))
            else:
                flash(
                    '''Senha incorreta!'''
                    )
        else:
            flash(
                '''Usuário não cadastrado!
                Solicite acesso ao administrador através do Fale Conosco'''
                )
    return render_template(
        'index.html', 
        form=form, 
        )



#Admin
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    our_items = Items.query.order_by(Items.code)
    search=None
    form=SearchForm()
    if form.validate_on_submit():
        search=int(form.search.data)
        form.search.data = ''
        for our_item in our_items:
            if (our_item.code) == search:
                flash(f'''{our_item.code} - {our_item.name}
                R${(our_item.value)}''')
        search=None
    our_items = Items.query.order_by(Items.code)
    return render_template(
        'admin.html', 
        search=search, 
        form=form, 
        our_items=our_items, 
        current_time=datetime.utcnow()
        )



#Add User
@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    name=None
    email=None
    form=UserForm()
    if form.validate_on_submit():
        user=Users.query.filter_by(
            email=form.email.data
            ).first()
        if user is None:
            hashed_pw=generate_password_hash(
                form.password_hash.data
                )
            user=Users(
                name=form.name.data, 
                email=form.email.data,
                password_hash=hashed_pw
                )
            db.session.add(user)
            db.session.commit()
        form.name.data=''   
        form.email.data=''
        form.password_hash.data=''   
        form.password_hash2.data=''
        flash(
            '''Usuário adicionado com sucesso!'''
            ) 
    our_users = Users.query.order_by(Users.date_added)
    return render_template(
        'add_user.html',
        form=form, 
        name=name,
        email=email, 
        our_users=our_users)



#Update User
@app.route('/update_user/<int:id>', methods=['GET', 'POST'])
def update_user(id):
    form=UserForm()  
    name_to_update=Users.query.get_or_404(id)
    if request.method == 'POST':
        name_to_update.name=request.form['name']
        name_to_update.email=request.form['email']
        try:
            db.session.commit() 
            flash(
                '''Usuário atualizado com sucesso!'''
                )
            return render_template(
                'update_user.html',
                form=form,
                name_to_update=name_to_update,
            )
        except:
            flash(
                '''Não foi possível atualizar usuário.
                Tente novamente...'''
                )
            return render_template(
                'update_user.html',
                form=form,
                name_to_update=name_to_update,
                )
    else:
        return render_template(
            'update_user.html',
            form=form,
            name_to_update=name_to_update,
            )



#Delete User
@app.route('/delete_user/<int:id>')
def delete_user(id):
    user_to_delete = Users.query.get_or_404(id)
    name=None
    form=UserForm()
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(
            '''Usuário deletado com sucesso!'''
            )
        our_users = Users.query.order_by(Users.date_added)
        return render_template(
            'add_user.html',
            form=form, 
            name=name,
            our_users=our_users)
    except:
        flash(
            '''O usuário não pode ser deletado.
            Tente novamente...'''
            )
        return render_template(
            'add_user.html',
            form=form, 
            name=name,
            our_users=our_users)



#Add Item
@app.route('/add_items', methods=['GET', 'POST'])
def add_item():
    code=None
    type=None
    name=None
    value=None
    form=ItemForm()
    if form.validate_on_submit():
        item=Items(
            code=form.code.data, 
            type=form.type.data, 
            name=form.name.data, 
            value=form.value.data
            )
        db.session.add(item)
        db.session.commit()
        form.code.data=''
        form.type.data=''
        form.name.data=''
        form.value.data=''
        flash(
            '''Item adicionado com sucesso!'''
            ) 
    our_items = Items.query.order_by(Items.code)
    return render_template(
        'add_items.html',
        form=form, 
        code=code,
        type=type,
        name=name, 
        value=value, 
        our_items=our_items)



#Update Item
@app.route('/update_items/<int:id>', methods=['GET', 'POST'])
def update_items(id):
    form=ItemForm()  
    item_to_update=Items.query.get_or_404(id)
    if request.method == 'POST':
        item_to_update.code=request.form['code']
        item_to_update.type=request.form['type']
        item_to_update.name=request.form['name']
        item_to_update.value=request.form['value']
        try:
            db.session.commit() 
            flash(
                '''Item atualizado com sucesso!'''
                )
            return render_template(
                'update_items.html',
                form=form,
                item_to_update=item_to_update,
                id=id,
            )
        except:
            flash(
                '''Não foi possível atualizar item.
                Tente novamente...'''
                )
            return render_template(
                'update_items.html',
                form=form,
                item_to_update=item_to_update,
                id=id,
                )
    else:
        return render_template(
            'update_items.html',
            form=form,
            item_to_update=item_to_update,
            id=id,
            )



#Delete Item
@app.route('/delete_item/<int:id>')
def delete_item(id):
    item_to_delete = Items.query.get_or_404(id)
    code=None
    form=ItemForm()
    try:
        db.session.delete(item_to_delete)
        db.session.commit()
        flash(
            '''Item deletado com sucesso!'''
            )
        our_items = Items.query.order_by(Items.code)
        return render_template(
            'add_items.html',
            form=form, 
            code=code,
            our_items=our_items)
    except:
        flash(
            '''O item não pode ser deletado.
            Tente novamente...'''
            )
        return render_template(
            'add_items.html',
            form=form, 
            code=code,
            our_items=our_items)



# 404
@app.errorhandler(404)
def page_not_found(e):
    return render_template(
        '404.html'
        ), 404



#500
@app.errorhandler(500)
def internal_server_error(e):
    return render_template(
        '500.html'
        ), 500
