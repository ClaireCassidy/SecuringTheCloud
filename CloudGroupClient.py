import os
import time
import re

from multiprocessing.connection import Client
from cryptography.fernet import Fernet

USER_PRIVILEGE = 0
ADMIN_PRIVILEGE = 1

AS_BYTES = 0
AS_STR = 1

REGISTER = 'r'
LOG_IN = 'l'
QUIT = 'q'

PROTOCOL_EX = "Unexpected communication protocol error"

REGEX_VALID_USERNAME = '^[A-Za-z0-9_-]*$'
REGEX_VALID_PASSWORD = r'[A-Za-z0-9@#$%^&+=]{6,}'

# Communication protocol between CAM and Client:
HELLO = "hello"
REQ_USER_LIST = "userlist"
REQ_REGISTER = "register"
REQ_CLOSE = "close"
REQ_LOGIN = "login"
REQ_DOWNLOAD = "download"
REQ_CLOUD_FILES = "files"
OK = "ok"
SUCCESS = "success"             # request completed successfully
FAILURE = "failure"             # something went wrong

# dynamic data structure for keeping a list of usernames in memory
users = []
admins = []
cloud_files = []

symmetric_key_cam = None


def main():
    global users, admins, symmetric_key_cam, cloud_files

    # load key for comms with CAM
    load_symm_key()

    address = ('localhost', 6000)
    conn = Client(address, authkey=b'cloud_group')

    # initialise communication with CAM
    encrypt_and_send(conn, HELLO)
    res = decrypt_from_src(conn, AS_STR)

    if res == HELLO:
        # begin registration/login flow:
        encrypt_and_send(conn, REQ_USER_LIST)
        user_list_string = decrypt_from_src(conn, AS_STR)
        users, admins = extract_usernames(user_list_string)

        # get filenames from cloud
        encrypt_and_send(conn, REQ_CLOUD_FILES)
        res = decrypt_from_src(conn, AS_STR)
        cloud_files = res.split("|")
        print(cloud_files)

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
            if username is not None:
                encrypt_and_send(conn, REQ_REGISTER)

                res = decrypt_from_src(conn, AS_STR)
                if res == OK:
                    encrypt_and_send(conn, f'{username}|{pw}')
                    users.append(username)
                else:
                    raise Exception(PROTOCOL_EX)

                res = decrypt_from_src(conn, AS_STR)
                if res == SUCCESS:
                    print(f'Registered user \'{username}\' successfully. To finish registration, please contact a '
                          f'system administrator to obtain your key and proceed to log in.')
                else:
                    raise Exception(PROTOCOL_EX)

        elif option == LOG_IN:
            handle_log_in(conn)

        elif option == QUIT:
            encrypt_and_send(conn, REQ_CLOSE)

            res = decrypt_from_src(conn, AS_STR)
            if res == OK:
                print(f'Goodbye!')
                break
            else:
                raise Exception(PROTOCOL_EX)

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
    go_back = False

    while valid_username is False:
        username = input(f'Preparing to register a new user... ([B] to go back)\n Username: ').lower()

        if username == 'b':
            go_back = True
            break
        elif 6 <= len(username) <= 15 and re.match(REGEX_VALID_USERNAME, username):
            if username in exclusion_list:
                print(f' Sorry, that username has been taken.\n')
            else:
                valid_username = True
        else:
            print(f' Please enter a username between 6 and 15 characters containing only letters, numbers, -, and/or _\n')

    if go_back is False:
        while valid_password is False:
            password = input(' Password: ')

            if 6 <= len(password) <= 15 and re.match(REGEX_VALID_PASSWORD, password):
                valid_password = True
            else:
                print(f' Please enter a password between 6 and 15 characters containing only letters, numbers, '
                      f'and/or the following special characters: @ # $ % ^ & + =\n')

    return username, password


def handle_log_in(conn):
    go_back = False

    while go_back is False:

        print(f'\nEnter your login details ([B] to go back)')

        username = input(f' Username: ').lower()
        if username == 'b':
            break

        password = input(f' Password: ')

        # send to CAM to authenticate:
        # send request to log in
        encrypt_and_send(conn, REQ_LOGIN)

        # await OK from CAM
        res = decrypt_from_src(conn, AS_STR)
        if res == OK:
            # proceed to send login details for verification
            encrypt_and_send(conn, f'{username}|{password}')

            # response is either SUCCESS if verifiable or FAIL if not
            res = decrypt_from_src(conn, AS_STR)
            if res == SUCCESS:

                # successful login
                print(f'\nLogin Successful. Welcome {username}.')

                if username in users:
                    handle_user(conn, username)
                elif username in admins:
                    handle_admin(conn)
                else:
                    raise Exception(f'Something\'s gone terribly wrong :(')

            elif res == FAILURE:
                # unsuccessful login; repeat loop
                print(f'Login unsuccessful. Please try again.')
            else:
                raise Exception(PROTOCOL_EX)

        else:
            raise Exception(PROTOCOL_EX)



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


def load_symm_key():
    global symmetric_key_cam

    cwd = os.getcwd()
    path_to_key = f'{cwd}\\client_files\\fernet_client.key'

    with open(path_to_key, 'rb') as key_file:
        symmetric_key_cam = key_file.read()
        key_file.close()

    symmetric_key_cam = Fernet(symmetric_key_cam)


def handle_user(conn, username):
    global cloud_files

    keep_going = True

    while keep_going is True:

        valid_option = False

        while valid_option is False:
            option = input(f'Do you wish to [U]pload or [D]ownload a file? ([B]ack to logout)\n').lower()

            if option == 'd':
                valid_option = True

                has_downloaded_smth = False

                while has_downloaded_smth is False:
                    option = input(f'Choose one of the following options:\n\t[L]: List the files currently available on the cloud\n\t[<filename.ext>]: Download a file\n\t[B]: Return to previous menu\n')
                    if option == 'l' or option == 'L':

                        print(f'\nFiles available for download:')
                        for file in cloud_files:
                            print(f' {file}')
                        print()
                    elif option == 'b' or option == 'B':
                        valid_option = True
                        break
                    else:   # file request
                        has_downloaded_smth = True
                        result = request_download(conn, option, username)

            elif option == 'u':
                pass
            elif option == 'b':
                pass
            else:
                print(f'Not a valid option.')



def handle_admin(conn):
    pass


# either encrypts a message and sends it using the given connection object
def encrypt_and_send(conn, msg):
    msg_bytes = str.encode(msg)
    ciphertext = symmetric_key_cam.encrypt(msg_bytes)
    print(f'\tSending {msg}; ciphertext: {ciphertext}')
    conn.send(ciphertext)


# gets the next msg from a connection object, decrypts using the key and returns the plaintext
def decrypt_from_src(conn, as_what):
    ciphertext = conn.recv()

    plaintext = symmetric_key_cam.decrypt(ciphertext)

    if as_what == AS_STR:
        plaintext = plaintext.decode("utf-8")

    print(f'\tReceived {plaintext}; ciphertext: {ciphertext}')
    return plaintext


def request_download(conn, filename, username):

    encrypt_and_send(conn, REQ_DOWNLOAD)
    res = decrypt_from_src(conn, AS_STR)

    if res == OK:
        # submit request for file in form [filename.ext]
        encrypt_and_send(conn, filename)

        res = decrypt_from_src(conn, AS_BYTES)

        if res == FAILURE:  # file not found on cloud
            print(f'Unexpected error finding file in cloud.')
        else:
            write_to_user_directory(res, username, filename)
            print(f'File download successful. You file has been saved to \'group_files\\{username}\\downloads\'.')

    else:
        raise Exception(PROTOCOL_EX)


def write_to_user_directory(file_bytes, username, filename):
    # files that are downloaded are written to group_files/<username>/downloads/
    cur_dir = os.path.dirname(os.path.realpath(__file__))

    #@todo make dir if doesn't exist already
    path_to_user_dir = os.path.join(cur_dir, f'group_files\\{username}\\downloads')
    print(path_to_user_dir)

    # make parent directories if they don't already exist
    if not os.path.exists(path_to_user_dir):
        os.makedirs(path_to_user_dir)

    path_to_target_file = os.path.join(path_to_user_dir, filename)
    print(path_to_target_file)

    with open(path_to_target_file, 'wb') as target_file:
        target_file.write(file_bytes)
        target_file.close()


if __name__ == '__main__':
    main()
