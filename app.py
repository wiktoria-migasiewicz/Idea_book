from flask import Flask, render_template, request, g, redirect, url_for, flash, session
import sqlite3
import UserPass

app_info = {
    'db_file': 'data/trips.db'
}

app = Flask(__name__)

app.config['SECRET_KEY'] = 'a_secret_string'


def get_db():
    if not hasattr(g, 'sqlite_db'):
        conn = sqlite3.connect(app_info['db_file'])
        conn.row_factory = sqlite3.Row
        g.sqlite_db = conn
    return g.sqlite_db


@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()


@app.route('/init_app')
def init_app():

    # check if there are users defined (at least one active admin required)
    db = get_db()
    sql_statement = 'select count(*) as cnt from users where is_active and is_admin;'
    cur = db.execute(sql_statement)
    active_admins = cur.fetchone()
    if active_admins is not None and active_admins['cnt'] > 0:
        flash('Application is already set-up. Nothing to do')
        return redirect(url_for('index'))

    # if not - create/update admin account with a new password and admin privileges, display random username
    user_pass = UserPass.UserPass()
    user_pass.get_random_user_password()
    sql_statement = '''insert into users(name, email, password, is_active, is_admin) values(?,?,?,True, True);'''
    db.execute(sql_statement, [user_pass.user, 'noone@nowhere.no', user_pass.hash_password()])
    db.commit()
    flash('User {} with password {} has been created'.format(user_pass.user, user_pass.password))
    return redirect(url_for('index'))


@app.route('/')
def index():
    user_pass = UserPass.UserPass(session.get('user'))
    user_pass.get_user_info()

    db = get_db()
    query = 'select * from trips;'
    cur = db.execute(query)
    trips = cur.fetchall()
    return render_template('index.html', trips=trips, active="home", user_pass=user_pass)


@app.route('/add_idea', methods=['GET', 'POST'])
def add_idea():
    user_pass = UserPass.UserPass(session.get('user'))
    user_pass.get_user_info()

    if not user_pass.is_valid:
        flash('Log in to add an idea')
        return redirect('login')

    if request.method == 'GET':
        return render_template('add_idea.html',
                               radiobutton='default', checkbox='default', active="add", user_pass=user_pass)
    elif request.method == 'POST':

        tripName = request.form['tripName'] if 'tripName' in request.form else ''
        email = request.form['email'] if 'email' in request.form else ''
        description = request.form['description'] if 'description' in request.form else ''
        checkbox = request.form.get('flexCheckDefault') if 'flexCheckDefault' in request.form else '0'
        radiobutton = request.form.get('flexRadioDefault') if 'flexRadioDefault' in request.form else 'default'

        db = get_db()

        query = 'insert into trips(trip_name, email, description, radiobutton, checkbox) values(?, ?, ?, ?, ?)'
        cur = db.execute(query, [tripName, email, description, radiobutton, checkbox])
        new_id = cur.lastrowid
        db.commit()
        db = get_db()

        cur = db.execute('select * from trips where id = ?', [new_id])
        trip = cur.fetchone()
        flash('New entry added!')

        return render_template('show_idea.html', disabled=True,
                               trip=trip, active="add", user_pass=user_pass)


@app.route('/show_idea/<trip_id>')
def show_idea(trip_id):
    user_pass = UserPass.UserPass(session.get('user'))
    user_pass.get_user_info()

    db = get_db()
    cur = db.execute('select * from trips where id = ?', [trip_id])
    trip1 = cur.fetchone()
    return render_template('show_existing_idea.html', disabled=True,
                           trip=trip1, active="home", user_pass=user_pass)


@app.route('/delete/<trip_id>')
def delete_entry(trip_id):
    user_pass = UserPass.UserPass(session.get('user'))
    user_pass.get_user_info()

    if not user_pass.is_valid:
        flash('Log in to delete an idea')
        return redirect('login')
    db = get_db()
    query = 'delete from trips where id = ?;'
    db.execute(query, [trip_id])
    db.commit()
    flash('Entry deleted!')
    return redirect(url_for('index'))


@app.route('/edit/<trip_id>', methods=['GET', 'POST'])
def edit_entry(trip_id):
    user_pass = UserPass.UserPass(session.get('user'))
    user_pass.get_user_info()

    if not user_pass.is_valid:
        flash('Log in to edit an idea')
        return redirect('login')
    if request.method == 'GET':
        db = get_db()
        cur = db.execute('select * from trips where id = ?', [trip_id])
        trip1 = cur.fetchone()
        return render_template('update.html', trip=trip1, active="add", edit=True, user_pass=user_pass)
    elif request.method == 'POST':

        tripName = request.form['tripName'] if 'tripName' in request.form else ''
        email = request.form['email'] if 'email' in request.form else ''
        description = request.form['description'] if 'description' in request.form else ''
        checkbox = request.form.get('flexCheckDefault') if 'flexCheckDefault' in request.form else '0'
        radiobutton = request.form.get('flexRadioDefault') if 'flexRadioDefault' in request.form else 'default'

        db = get_db()
        query = 'update trips set trip_name=?, email=?, description=?, radiobutton=?, checkbox=? where id=?;'
        db.execute(query, [tripName, email, description, checkbox, radiobutton, trip_id])
        db.commit()
        flash('Entry updated!')
        return redirect(url_for('index'))


@app.route('/login', methods=['POST', 'GET'])
def login():
    user_pass = UserPass.UserPass(session.get('user'))
    user_pass.get_user_info()

    if request.method == 'GET':
        return render_template('login.html', active='login', user_pass=user_pass)
    elif request.method == 'POST':
        username = request.form['username'] if 'username' in request.form else ''
        password = request.form['password'] if 'password' in request.form else ''
        user_pass = UserPass.UserPass(username, password)

        login_record = user_pass.login_user()
        if login_record is not None:
            session['user'] = username
            flash(f'Login successful, welcome {username}')
            return redirect(url_for('index'))
        else:
            flash(f'Login failed {username}')
            return render_template('login.html', active='login', user_pass=user_pass)


@app.route('/logout')
def logout():
    if 'user' in session:
        session.pop('user', None)
        flash('Logout successful')
    return redirect(url_for('login'))


@app.route('/users')
def users():
    user_pass = UserPass.UserPass(session.get('user'))
    user_pass.get_user_info()

    if not user_pass.is_valid and not user_pass.is_admin:
        return redirect('login')
    db = get_db()
    query = 'select * from users'
    cur = db.execute(query)
    records = cur.fetchall()
    return render_template('users.html', users=records, user_pass=user_pass)


@app.route('/edit_user/<username>', methods=['GET', 'POST'])
def edit_user(username):
    user_pass = UserPass.UserPass(session.get('user'))
    user_pass.get_user_info()

    if not user_pass.is_valid and not user_pass.is_admin:
        return redirect('login')

    if request.method == 'GET':
        db = get_db()
        query = 'select name, email from users where name = ?'
        cur = db.execute(query, [username])
        user = cur.fetchone()
        return render_template('edit_user.html', user_data=user, user_pass=user_pass)
    elif request.method == 'POST':
        db = get_db()
        query = 'select name, email from users where name = ?'
        cur = db.execute(query, [username])
        if cur.fetchone() is None:
            flash(f'User {username} does not exist')
            return redirect(url_for('users'))

        email = request.form['email'] if 'email' in request.form else ''
        password = request.form['password'] if 'password' in request.form else ''

        if email != '':
            query = 'update users set email = ? where name = ?'
            db.execute(query, [email, username])
            db.commit()
            flash('Email has been changed')

        if password != '':
            user_pass = UserPass.UserPass(username, password)
            hashed_pass = user_pass.hash_password()
            query = 'update users set password = ? where name = ?'
            db.execute(query, [hashed_pass, username])
            db.commit()
            flash('Password has been changed')

        return redirect(url_for('users'))


@app.route('/new_user', methods=['GET', 'POST'])
def new_user():
    user_pass = UserPass.UserPass(session.get('user'))
    user_pass.get_user_info()
    if not user_pass.is_valid and not user_pass.is_admin:
        return redirect('login')
    db = get_db()
    user = {}

    if request.method == 'GET':
        return render_template('new_user.html', user=user, user_pass=user_pass)
    elif request.method == 'POST':
        user['username'] = request.form['username'] if 'username' in request.form else ''
        user['password'] = request.form['password'] if 'password' in request.form else ''
        user['email'] = request.form['email'] if 'email' in request.form else ''

        query_email = 'select count(*) as cnt from users where email = ?'
        cur_email = db.execute(query_email, [user['email']])
        record_email = cur_email.fetchone()
        is_email_unique = (record_email['cnt'] == 0)

        query_name = 'select count(*) as cnt from users where name = ?'
        cur_name = db.execute(query_name, [user['username']])
        record_name = cur_name.fetchone()
        is_name_unique = (record_name['cnt'] == 0)

        if not is_name_unique:
            message = f'Registration failed. User {user['username']} already exists'
            flash(message)
            return render_template('new_user.html', user=user, user_pass=user_pass)
        if not is_email_unique:
            message = f'Registration failed. User with email {user['email']} already exists'
            flash(message)
            return render_template('new_user.html', user=user, user_pass=user_pass)
        if user['password'] == '':
            message = f'Registration failed. Password cannot be empty'
            flash(message)
            return render_template('new_user.html', user=user, user_pass=user_pass)
        if user['username'] == '':
            message = f'Registration failed. Username cannot be empty'
            flash(message)
            return render_template('new_user.html', user=user, user_pass=user_pass)
        if user['email'] == '':
            message = f'Registration failed. Email cannot be empty'
            flash(message)
            return render_template('new_user.html', user=user, user_pass=user_pass)

        query_add = 'insert into users(name, email, password, is_active, is_admin) values(?, ?, ?, 1, 0)'
        db.execute(query_add, [user['username'], user['email'], user['password']])
        db.commit()

        flash(f'User {user['username']} successfully added to database')
        return redirect(url_for('index'))


@app.route('/delete_user/<username>')
def delete_user(username):
    user_pass = UserPass.UserPass(session.get('user'))
    user_pass.get_user_info()

    if not user_pass.is_valid and not user_pass.is_admin:
        return redirect('login')

    db = get_db()
    query = 'delete from users where name = ? and name <> ?'
    db.execute(query, [username, user_pass.user])
    db.commit()
    flash(f'User {username} deleted from database')
    return redirect(url_for('users'))


@app.route('/user_status_change/<user>/<action>')
def user_status_change(user, action):
    user_pass = UserPass.UserPass(session.get('user'))
    user_pass.get_user_info()

    if not user_pass.is_valid and not user_pass.is_admin:
        return redirect('login')

    db = get_db()

    if action == 'active':
        query = '''update users set is_active = (is_active + 1) % 2 
                   where name = ? and name <> ?'''
        db.execute(query, [user, user_pass.user])
        db.commit()
    if action == 'admin':
        query = '''update users set is_admin = (is_admin + 1) % 2 
                   where name = ? and name <> ?'''
        db.execute(query, [user, user_pass.user])
        db.commit()

    return redirect(url_for('users'))


if __name__ == '__main__':
    app.run(debug=True)
