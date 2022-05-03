import hashlib


def apply_salt(password, salt):
    formatted_salt = salt.strip()
    with_salt = formatted_salt + password + formatted_salt
    encoded = str.encode(with_salt)
    return encoded


def get_hash(hash, encoded_str):
    hash.update(encoded_str)
    return hash.hexdigest()


def crack_sha1_hash(hash, use_salts=False):
    # get content of passwords text file
    pws_file = open('top-10000-passwords.txt', 'r')
    salts_file = open('known-salts.txt', 'r')

    for password in pws_file:
        pw_hash = hashlib.sha1()
        formatted_password = password.strip()

        if use_salts:
            # apply salts
            for salt in salts_file:
                encoded_with_salt = apply_salt(formatted_password, salt)
                hex = get_hash(pw_hash, encoded_with_salt)

                if hex == hash:
                    return password
        else:
            encoded = str.encode(formatted_password)
            hex = get_hash(pw_hash, encoded)

            if hex == hash:
                return password

        return 'PASSWORD NOT IN DATABASE'
