import random
import string
import hashlib
import binascii
from app import get_db


class UserPass:

    def __init__(self, user='', password=''):
        self.user = user
        self.password = password
        self.is_valid = False
        self.is_admin = False
        self.email = ''

    def hash_password(self):
        """Hash a password for storing."""
        # the value generated using os.urandom(60)
        os_urandom_static = b"ID_\x12p:\x8d\xe7&\xcb\xf0=H1\xc1\x16\xac\xe5BX\xd7\xd6j\xe3i\x11\xbe\xaa\x05\xccc\xc2\xe8K\xcf\xf1\xac\x9bFy(\xfbn.`\xe9\xcd\xdd'\xdf`~vm\xae\xf2\x93WD\x04"
        salt = hashlib.sha256(os_urandom_static).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac('sha512', self.password.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')

    @staticmethod
    def verify_password(stored_password, provided_password):
        """Verify a stored password against one provided by user"""
        salt = stored_password[:64]
        stored_password = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode('utf-8'), salt.encode('ascii'), 100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_password

    def get_random_user_password(self):
        random_user = ''.join(random.choice(string.ascii_lowercase) for i in range(3))
        self.user = random_user

        password_characters = string.ascii_letters  # + string.digits + string.punctuation
        random_password = ''.join(random.choice(password_characters) for i in range(3))
        self.password = random_password

    def login_user(self):

        db = get_db()
        query = 'select id, name, email, password, is_active, is_admin from users where name=?'
        cur = db.execute(query, [self.user])
        user_record = cur.fetchone()

        # self.verify_password(user_record['password'], self.password):

        if user_record is not None :
            return user_record
        else:
            self.user = None
            self.password = None
            return None

    def get_user_info(self):

        db = get_db()
        query = 'select id, name, email, password, is_active, is_admin from users where name=?'
        cur = db.execute(query, [self.user])
        user_record = cur.fetchone()

        if user_record is None:
            self.is_admin = False
            self.is_valid = False
            self.email = ''
        elif user_record['is_active'] != 1:
            self.is_admin = False
            self.is_valid = False
            self.email = user_record['email']
        else:
            self.is_admin = user_record['is_admin']
            self.is_valid = True
            self.email = user_record['email']

