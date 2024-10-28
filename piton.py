import datetime #Импортирует модуль datetime для работы с датами и временем.
from flask import Flask, render_template, request, redirect, session, url_for 
'''
Flask - это класс  библиотека которая позволяет создовать веб приложения.

render_template - Она позволяет вставлять данные в шаблон и возвращать HTML-страницу клиенту.

request - это компонент из библиотеки flask который представляет запрос, отправленный клиентом на сервер. Он содержит информацию о запросе, такую как параметры, заголовки, метод (GET, POST и т. д.).

redirect - это функция, позволяющая перенаправить пользователя на другую страницу вашего приложения.

session - это объект, который позволяет сохранять информацию конкретного пользователя между запросами и не только.

url_for - вроде это компонент из библиотеки flask используется в шаблонах для создания ссылок на различные страницы приложения.
'''
from flask_sqlalchemy import SQLAlchemy# SQLAlchemy это библиотека для работы с бд а это flask_sqlalchemy упрощает использование. Типо можно не писать sql запросы и не только
from werkzeug.security import generate_password_hash, check_password_hash # чтобы яя смог хешировать логин и пароль и раз хешироать
import re # я использовал для валидации, проверки введенных данных пользоватеелем. 72 строка вроде



app = Flask(__name__)# короче я знаю только что без него нечего не будет работать он решает всё. поищи в инете))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///applications.db'# подключение бд 
app.config['SECRET_KEY'] = 'your_secret_key'#  создание секретного ключа для безопастности 
db = SQLAlchemy(app)
# создание класса пользователя и добавление туда id роль пользователя пароль и т.д
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(50), nullable=False)
#repr показывает “информационную карточку” объекта
    def __repr__(self):
        return f'<User {self.username}>'#возвращает строку  
# создание таблицы в бд
class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_number = db.Column(db.Integer, unique=True, nullable=False)
    org_type = db.Column(db.String(100), nullable=False)
    model = db.Column(db.String(100), nullable=False)
    problem_description = db.Column(db.Text, nullable=False)
    last_edited = db.Column(db.DateTime)
    client_name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(50), default='Новая заявка')
    responsible = db.Column(db.String(100), nullable=False)
    stage_of_executio = db.Column(db.String(50), default='Готова к выдаче')
    date_added = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    date_completed = db.Column(db.DateTime)
    comments = db.Column(db.Text, default='')  
    ordered_parts = db.Column(db.Text, default='') 
    def __repr__(self):
        return f'<Application {self.application_number}>'

# 
with app.app_context():# для обеспечивания доступа к различным функциям и объектам Flask, таким как db 
    db.create_all() # СОЗДАЕТ ТАБЛИЦЫ В БД

    #  администратора
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', password=generate_password_hash('admin'), role='admin')
        db.session.add(admin)
        db.session.commit()

    # пользователя
    user = User.query.filter_by(username='user').first()
    if not user:
        user = User(username='user', password=generate_password_hash('user'), role='user')
        db.session.add(user)
        db.session.commit()
    #  проверка с символами с длиной номера с помошью валидатора 
def validate_phone_number(phone_number):
    if not re.match(r'^[+-]?\d+$', phone_number):
        return False

    if len(phone_number) < 7 or len(phone_number) > 15:
        return False
    return True
#проверяет есть ли user_id в сесии то получаю пользоваетлья из бд если нет то отправляет пользователя в login.html(е заню работает это или нет)
@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        applications = Application.query.all()
        return render_template('index.html', applications=applications, user=user)
    else:
        return redirect(url_for('login'))
# короче тут с начала Получение идентификатора пользователя из сессии потом запрос к базе данных и Полученный объект User сохраняется в переменную ser

@app.route('/add_application', methods=['GET', 'POST'])
def add_application():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role == 'admin':#проврека роли
            if request.method == 'POST':
                application_number = request.form['application_number']
                # Проверяем, есть ли уже заявка с таким номером
                existing_application = Application.query.filter_by(application_number=application_number).first()
                if existing_application:# проверка на сущствование номера заявки при поеске
                    error = "Заявка с таким номером уже существует"
                    return render_template('add_application.html', error=error)
                comments = request.form.get('comments', '')
                ordered_parts = request.form.get('ordered_parts', '')
                org_type = request.form['org_type']
                model = request.form['model']
                problem_description = request.form['problem_description']
                client_name = request.form['client_name']
                phone_number = request.form['phone_number']
                if not validate_phone_number(phone_number):# проверка на верный формат телефона
                    error = "Неверный формат номера телефона"
                    return render_template('add_application.html', error=error)
                status = request.form['status']
                responsible = request.form['responsible']
                stage_of_executio = request.form['stage_of_executio']

                new_application = Application(
                    application_number=application_number,
                    org_type=org_type,
                    model=model,
                    problem_description=problem_description,
                    client_name=client_name,
                    phone_number=phone_number,
                    status=status,
                    responsible=responsible,
                    stage_of_executio=stage_of_executio,
                    comments=comments,
                    ordered_parts=ordered_parts
                )
                db.session.add(new_application) # Добавить объект в сессию
                db.session.commit()# Сохранить изменения в базе данных
                return redirect(url_for('index'))# с помощью redirect можно перекинуть пользователья на другой адрес
            return render_template('add_application.html')# render_template тут что-то по типу берет и отдает форму для заполнения пользователью 
        else:
            return "У вас недостаточно прав для добавления заявки"
    else:
        return redirect(url_for('login'))
    # ксатати Application.query  для выполнения запросов к базе данных.
# проверка роли
@app.route('/edit_application/<int:application_id>', methods=['GET', 'POST'])
def edit_application(application_id):
    if 'user_id' in session:# выше я говорил нориальнее так что session хранит информацию о сессии пользователя
        user = User.query.get(session['user_id'])# получает объект User из бд  используя идентификатор пользователя хранящийся в сессии.
        if user.role == 'admin':# проверка роли
            application = Application.query.get_or_404(application_id)# ищсли заявка не найдена то get_or_404(application_id) возврощает ошибку 
            if request.method == 'POST':
                application.org_type = request.form['org_type']
                application.model = request.form['model']
                application.problem_description = request.form['problem_description']
                application.client_name = request.form['client_name']
                application.phone_number = request.form['phone_number']
                application.comments = request.form.get('comments', '')
                application.last_edited = datetime.datetime.utcnow()
                application.ordered_parts = request.form.get('ordered_parts', '')
                if not validate_phone_number(application.phone_number):# опять же проверка роли
                    error = "Неверный формат номера телефона"
                    return render_template('edit.html', application=application, error=error)
                application.status = request.form['status']
                application.responsible = request.form['responsible']
                application.stage_of_executio = request.form['stage_of_executio']
                db.session.commit()
                return redirect(url_for('index'))
            return render_template('edit.html', application=application)
        else:
            return "У вас недостаточно прав для редактирования заявки"
    else:
        return redirect(url_for('login'))
# Удаление тута
@app.route('/delete_application/<int:application_id>')
def delete_application(application_id):
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role == 'admin':
            application = Application.query.get_or_404(application_id)
            db.session.delete(application)
            db.session.commit()
            return redirect(url_for('index'))
        else:
            return "У вас недостаточно прав для удаления заявки"
    else:
        return redirect(url_for('login'))
# тут идет с начала статистка заверзоных заявок потом среднее время
@app.route('/statistics')
def statistics():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role == 'admin':
            completed_applications_count = Application.query.filter_by(status='Завершена').count()
            average_completion_time_hours = 0
            completed_applications = Application.query.filter_by(status='Завершена').all()
            total_completion_time = datetime.timedelta()
            for application in completed_applications:
                 if application.date_completed and application.last_edited:
                    total_completion_time += application.date_completed - application.last_edited

            if completed_applications_count > 0:
                average_completion_time_hours = total_completion_time.total_seconds() / 3600 / completed_applications_count


            # Статистика по типам неисправностей
            problem_counts = {}
            for application in Application.query.all():
                problem = application.problem_description
                if problem in problem_counts:
                    problem_counts[problem] += 1
                else:
                    problem_counts[problem] = 1

            return render_template('statistics.html',
                                   completed_applications_count=completed_applications_count,
                                   average_completion_time_hours=average_completion_time_hours,
                                   problem_counts=problem_counts)
        else:
            return "У вас недостаточно прав для просмотра статистики"
    else:
        return redirect(url_for('login'))
# проверка на соотвествие логина и пароля
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            error = 'Неверный логин или пароль'
            return render_template('login.html', error=error)
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))
# поиск заявки
@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if request.method == 'POST':
            search_query = request.form['search_query']
            try:
                search_number = int(search_query)
                application = Application.query.filter_by(application_number=search_number).first()
                if application:
                    return render_template('search_results.html', application=application, user=user)
                else:
                    error = 'Заявка с таким номером не найдена'
                    return render_template('search_results.html', error=error, user=user)
            except ValueError:
                error = 'Неверный формат номера заявки'
                return render_template('search_results.html', error=error, user=user)
        return render_template('search.html', user=user)
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():# для обеспечивания доступа к различным функциям и объектам Flask, таким как db 
        db.create_all()# СОЗДАЕТ ТАБЛИЦЫ В БД
    app.run(debug=True)# запуск веб приложения
    