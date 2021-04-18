import os
import time
from multiprocessing.connection import Client

USERS_PATH = r"cam_files\users"
ADMINS_PATH = r"cam_files\admins"

def main():
    # address = ('localhost', 6000)
    # conn = Client(address, authkey=b'cloud_group')

    while True:
        user_list = load_usernames([USERS_PATH, ADMINS_PATH])
        username, privilege_lvl = prompt_for_login()

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

def load_usernames(paths_to_search):

    usernames = []

    for directory_path in paths_to_search:
        # Get the current directory
        cur_dir = os.path.dirname(os.path.realpath(__file__))
        # Get absolute path to folders containing user info
        full_path = os.path.join(cur_dir, directory_path)
        # Get all files in the directory, remove their extensions and add them to the list of usernames
        usernames = usernames + [os.path.splitext(file)[0] for file in os.listdir(full_path)]

    print(f'{usernames}')
    return usernames


def prompt_for_login():
    username = input(f'Welcome to SecuringTheCloud.\n --------------- \n Username:')

    return None, None


if __name__ == '__main__':
    main()
