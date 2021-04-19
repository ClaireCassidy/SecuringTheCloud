import os
import time
import re
from multiprocessing.connection import Client

USERS_PATH = r"cam_files\users"
ADMINS_PATH = r"cam_files\admins"
USER_PRIVILEGE = 0
ADMIN_PRIVILEGE = 1
REGISTER = 'r'
LOG_IN = 'l'
REGEX_VALID_USERNAME = '^[A-Za-z0-9_-]*$'
REGEX_VALID_PASSWORD = r'[A-Za-z0-9@#$%^&+=]{6,}'

def main():
    # address = ('localhost', 6000)
    # conn = Client(address, authkey=b'cloud_group')

    while True:
        users, admins = load_usernames(USERS_PATH, ADMINS_PATH)
        username, privilege_lvl = prompt_for_login(users, admins)

        print(f'Welcome {username}')


        # # msg = input('Send a message to CAM (\'close\' to terminate): ')
        # filename = input('Hello user1. Please give the name of the file you wish to encrypt: ')
        #
        # if filename == 'close':
        #     conn.close()
        #     break
        #
        # path = f'group_files/user1/files/{filename}'
        #
        # file_bytes = None
        #
        # try:
        #     with open(f'{path}', 'rb') as file_to_send:
        #         upload_name = input('Give the upload a name (leave blank to use local name):')
        #
        #         if not upload_name:  # User entered no name
        #             upload_name = filename
        #
        #         print(f'\tSending file \'{path}\' to CAM with name \'{upload_name}\'')
        #         file_bytes = file_to_send.read()
        # except FileNotFoundError:
        #     print('\tCouldn\'t find file ' + path)
        #
        # if file_bytes is not None:
        #     conn.send(upload_name)
        #     time.sleep(0.2)  # ensure received separately
        #     conn.send(file_bytes)
        #
        # print(f'\n')


def load_usernames(users_path, admins_path):

    users = []
    admins = []

    cur_dir = os.path.dirname(os.path.realpath(__file__))

    full_path_users = os.path.join(cur_dir, users_path)
    users = [os.path.splitext(file)[0] for file in os.listdir(full_path_users)]

    full_path_admins = os.path.join(cur_dir, admins_path)
    admins = [os.path.splitext(file)[0] for file in os.listdir(full_path_admins)]

    return users, admins


def prompt_for_login(users, admins):

    login_success = False

    while not login_success:

        print('\n')

        privilege_level = None
        option = input(f'Welcome to SecuringTheCloud. [R]egister or [L]og in?\n-----------------\n').lower()

        if option == REGISTER:
            register_new_user(users + admins)
        elif option == LOG_IN:
            print(f'logging in...')
        else:
            print(f'Not a valid option. Please try again.')

        # if username in users:
        #     privilege_level = USER_PRIVILEGE
        # elif username in admins:
        #     privilege_level = ADMIN_PRIVILEGE
        #
        # if privilege_level is not None:
        #     password = input(f' Password:\t')
        #
        #     # get password
        #     if privilege_level == USER_PRIVILEGE:
        #         expected_pw = get_password(username, USERS_PATH)
        #     else:
        #         expected_pw = get_password(username, ADMINS_PATH)
        #
        #     if password == expected_pw:
        #         login_success = True
        #         return username, privilege_level
        #     else:
        #         print(f'Incorrect username or password. Please try again.')
        # else:
        #     print(f'No user \'{username}\' found. Please try again.')

    return None, None

def register_new_user(exclusion_list):

    valid_username = False
    valid_password = False

    while valid_username is False:
        username = input(f'Preparing to register a new user...\n Username: ').lower()

        if 6 <= len(username) <= 15 and re.match(REGEX_VALID_USERNAME, username):
            if username in exclusion_list:
                print(f' Sorry, that username has been taken.\n')
            else:
                valid_username = True
        else:
            print(f' Please enter a username between 6 and 15 characters containing only letters, numbers, -, and/or _\n')

    while valid_password is False:
        password = input(' Password: ')

        if 6 <= len(password) <= 15 and re.match(REGEX_VALID_PASSWORD, password):
            valid_password = True
        else:
            print(f' Please enter a password between 6 and 15 characters containing only letters, numbers, '
                  f'and/or the following special characters: @ # $ % ^ & + =\n')

    # have valid username and pw; proceed to register
    # -> Generate new symmetric key for user:
    

    # -> create new record for user in cam_files:
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    full_path_users = os.path.join(cur_dir, USERS_PATH)
    path_to_new_file = os.path.join(full_path_users, f'{username}.txt')

    with open(path_to_new_file, 'w') as new_user_file:
        new_user_file.write(f'{password}\n')
        new_user_file.close()

    print(f'Registered user \'{username}\' successfully. To finish registration, please contact a system administrator '
          f'to obtain your key and proceed to log in.')

    return True



def get_password(username, path):
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    full_path = os.path.join(cur_dir, path)
    files = os.listdir(full_path)
    files = [os.path.join(full_path, file).rstrip("/").rstrip("\\") for file in files]

    for file in files:

        username_from_path = os.path.splitext(os.path.split(file)[1])[0]
        if username_from_path == username:
            with open(file, 'r') as cur_user_file:
                user_file_contents = cur_user_file.read().splitlines()
                return user_file_contents[0]

    return None


if __name__ == '__main__':
    main()
