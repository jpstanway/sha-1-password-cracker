import hashlib

def apply_salt(password, salt, append=False):
  formatted_salt = salt.strip()
  
  if append:
    with_salt = formatted_salt + password
  else:
    with_salt = password + formatted_salt
  
  encoded = str.encode(with_salt)
  return encoded

def get_hash(hash, encoded_str):
  hash.update(encoded_str)
  return hash.hexdigest()

def crack_sha1_hash(hash, use_salts=False):
  # get content of passwords text file
  with open('top-10000-passwords.txt') as pws_file:
    for password in pws_file:
      pw_hash = hashlib.sha1()
      formatted_password = password.strip()
  
      if use_salts:
        # apply salts
        with open('known-salts.txt') as salts_file:
          for salt in salts_file:
            appended_salt = apply_salt(formatted_password, salt, True)
            prepended_salt = apply_salt(formatted_password, salt)
            hex1 = get_hash(pw_hash, appended_salt)
            hex2 = get_hash(pw_hash, prepended_salt)
            
            if hex1 == hash or hex2 == hash:
              return formatted_password
      else:
        encoded = str.encode(formatted_password)
        hex = get_hash(pw_hash, encoded)
        
        if hex == hash:
          return formatted_password

    return 'PASSWORD NOT IN DATABASE'