from csv import reader
import hashlib, binascii

COMMON_PASSWORDS_PATH = 'common_passwords.txt'
SALTED_BREACH_PATH = "app/scripts/breaches/salted_breach.csv"

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def load_common_passwords():
    with open(COMMON_PASSWORDS_PATH) as f:
        pws = list(reader(f))
    return pws

def brute_force_attack(target_hash, target_salt):
    # print("target____ = " + target_hash + "\n")
    pws = load_common_passwords()
    for pwd in pws:
        password = pwd[0].rstrip("\n")
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), target_salt.encode('utf-8'), 100000)
        hash_val = binascii.hexlify(hash_obj)
        # print("hash_val = " + hash_val + "\n")
        target_hash_byte = target_hash.encode('utf-8')
        if target_hash_byte == hash_val:
            print("found " + password)
            return password

    return None

def main():
    salted_creds = load_breach(SALTED_BREACH_PATH)
    for i in range(len(salted_creds)):
        brute_force_attack(salted_creds[i][1], salted_creds[i][2])

if __name__ == "__main__":
    main()