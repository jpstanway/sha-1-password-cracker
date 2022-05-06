import hashlib

PW_FILE = 'top-10000-passwords.txt'
SALT_FILE = 'known-salts.txt'
DEFAULT_VALUE = 'PASSWORD NOT IN DATABASE'


def crack_sha1_hash(hash, use_salts=False):
    # get content of passwords text file
    with open(PW_FILE) as pws_file:
        for password in pws_file:
            f_password = password.strip()
            pw_encoded = f_password.encode()
            pw_hash = hashlib.sha1(pw_encoded).hexdigest()

            if use_salts:
                # apply salts
                with open(SALT_FILE) as salts_file:
                    for salt in salts_file:
                        f_salt = salt.strip()
                        app_encoded = (f_password + f_salt).encode()
                        pre_encoded = (f_salt + f_password).encode()
                        app_hash = hashlib.sha1(app_encoded).hexdigest()
                        pre_hash = hashlib.sha1(pre_encoded).hexdigest()

                        if hash == app_hash or hash == pre_hash:
                            return f_password
            else:
                if hash == pw_hash:
                    return f_password

        return DEFAULT_VALUE
