import os
import time
import re
from multiprocessing.connection import Client

USER_PRIVILEGE = 0
ADMIN_PRIVILEGE = 1

REGISTER = 'r'
LOG_IN = 'l'
QUIT = 'q'

REGEX_VALID_USERNAME = '^[A-Za-z0-9_-]*$'
REGEX_VALID_PASSWORD = r'[A-Za-z0-9@#$%^&+=]{6,}'

# Communication protocol between CAM and Client:
HELLO = "hello"
REQ_USER_LIST = "userlist"
REQ_REGISTER = "register"
REQ_CLOSE = "close"
OK = "ok"
SUCCESS = "success"             # request completed successfully
FAILURE = "failure"             # something went wrong


def main():
    address = ('localhost', 6000)
    conn = Client(address, authkey=b'cloud_group')

    # initialise communication
    conn.send(HELLO)
    res = conn.recv()

    if res == HELLO:
        # begin registration/login flow:
        conn.send(REQ_USER_LIST)
        user_list_string = conn.recv()
        users, admins = extract_usernames(user_list_string)

        username, privilege_lvl = prompt_for_login(users, admins, conn)
        # users = user_list[0]
        # admins = user_list[1]
        # print(users)
        # print(admins)

        # users, admins = load_usernames(USERS_PATH, ADMINS_PATH)
        # username, privilege_lvl = prompt_for_login(users, admins)
        #
        # print(f'Welcome {username}')
    else:
        print(f'Unexpected error in communication protocol')

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

def extract_usernames(user_list_string):
    # divide into users and admins
    split_list = user_list_string.split("|")
    user_usernames = split_list[0].split(" ")
    admin_usernames = split_list[1].split(" ")

    return user_usernames, admin_usernames


def prompt_for_login(users, admins, conn):

    login_success = False

    while not login_success:

        print('\n')

        privilege_level = None
        option = input(f'Welcome to SecuringTheCloud. [R]egister or [L]og in? ([Q] to exit)\n-----------------\n').lower()

        if option == REGISTER:

            username, pw = register_new_user(users + admins)
            conn.send(REQ_REGISTER)
            if conn.recv() == OK:
                conn.send(f'{username}|{pw}')
            else:
                raise Exception("Unexpected communication protocol error")

            if conn.recv() == SUCCESS:
                print(f'Registered user \'{username}\' successfully. To finish registration, please contact a '
                      f'system administrator to obtain your key and proceed to log in.')
            else:
                raise Exception("Unexpected communication protocol error")

        elif option == LOG_IN:
            print(f'logging in...')

        elif option == QUIT:
            conn.send(REQ_CLOSE)
            if conn.recv() == OK:
                print(f'Goodbye!')
                break
            else:
                raise Exception("Unexpected communication protocol error")

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

    return username, password



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
