import os
import time
from multiprocessing.connection import Client

USERS_PATH = r"cam_files\users"
ADMINS_PATH = r"cam_files\admins"
USER_PRIVILEGE = 0
ADMIN_PRIVILEGE = 1

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
        username = input(f'Welcome to SecuringTheCloud. Please log in to proceed.\n--------------- \n Username:\t')

        if username in users:
            privilege_level = USER_PRIVILEGE
        elif username in admins:
            privilege_level = ADMIN_PRIVILEGE

        if privilege_level is not None:
            password = input(f' Password:\t')

            # get password
            if privilege_level == USER_PRIVILEGE:
                expected_pw = get_password(username, USERS_PATH)
            else:
                expected_pw = get_password(username, ADMINS_PATH)

            if password == expected_pw:
                login_success = True
                return username, privilege_level
            else:
                print(f'Incorrect username or password. Please try again.')
        else:
            print(f'No user \'{username}\' found. Please try again.')

    return None, None


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
