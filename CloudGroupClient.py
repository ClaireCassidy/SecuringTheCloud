import os
import re

from multiprocessing.connection import Client

from shutil import rmtree

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

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
REQ_UPLOAD = "upload"
REQ_CLOUD_FILES = "files"
REQ_DEL_USER = "deluser"
REQ_MK_ADMIN = "admin"
REQ_RM_ADMIN = "demote"
REQ_DEL_FILE = "delfile"
OK = "ok"
SUCCESS = "success"  # request completed successfully
FAILURE = "failure"  # something went wrong

# dynamic data structure for keeping a list of usernames in memory
users = []
admins = []
cloud_files = []

public_key_cam = None
private_key = None


def main():
    global users, admins, cloud_files, public_key_cam, private_key

    # perform one-time setup of client_files and keys where applicable
    perform_initial_setup()

    # connect to CAM
    address = ('localhost', 6000)
    conn = Client(address, authkey=b'cloud_group')

    # initialise communication with CAM
    #   send plaintext HELLO msg
    conn.send(HELLO)
    res = conn.recv()
    if res == HELLO:

        # if haven't got a record of CAM's pubkey, keys haven't been exchanged yet.
        cur_dir = os.path.dirname(os.path.realpath(__file__))
        path_to_cam_pubkey = os.path.join(cur_dir, f'client_files\\cam_pubkey.pem')

        if not os.path.exists(path_to_cam_pubkey):
            perform_key_exchange(conn, cur_dir, path_to_cam_pubkey)

        # now load keys
        load_keys()

        # begin registration/login flow:
        encrypt_and_send(conn, REQ_USER_LIST)
        user_list_string = decrypt_from_src(conn, AS_STR)
        users, admins = extract_usernames(user_list_string)

        # get filenames from cloud
        encrypt_and_send(conn, REQ_CLOUD_FILES)
        res = decrypt_from_src(conn, AS_STR)
        cloud_files = res.split("|")

        prompt_for_login(users, admins, conn)

        # ^ returns when user hits QUIT, so close connection with CAM and exit
        encrypt_and_send(conn, REQ_CLOSE)
    else:
        raise Exception(PROTOCOL_EX)


def load_keys():
    global private_key, public_key_cam

    # load client's private key for decryption
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    path_to_priv_key = os.path.join(cur_dir, f'client_files\\private_key.pem')

    with open(path_to_priv_key, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # load CAM's public key for encryption
    path_to_cam_pubkey = os.path.join(cur_dir, f'client_files\\cam_pubkey.pem')

    with open(path_to_cam_pubkey, "rb") as key_file:
        public_key_cam = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )


def perform_key_exchange(conn, cur_dir, save_path):

    print(f'Performing one-time public key exchange ... ')
    # send client's pubkey to CAM
    path_to_client_pubkey = os.path.join(cur_dir, f'client_files\\public_key.pem')

    with open(path_to_client_pubkey, 'rb') as file:
        file_bytes = file.read()
        conn.send(file_bytes)

    # CAM responds with own PKey
    cam_pubkey = conn.recv()

    # save it
    with open(save_path, 'wb') as file:
        file.write(cam_pubkey)
        file.close()


def perform_initial_setup():
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    path_client_files = os.path.join(cur_dir, f'client_files')

    if not os.path.exists(path_client_files):
        os.mkdir(path_client_files)
        print(f'Created \'{path_client_files}\'')

        print(f'Generating keys ...')
        # create client's asymm keys
        client_priv_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        client_public_key = client_priv_key.public_key()

        # store the keys
        pem_priv = client_priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        save_loc = os.path.join(path_client_files, 'private_key.pem')
        with open(save_loc, 'wb') as pem_file:
            pem_file.write(pem_priv)

        pem_pub = client_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)

        save_loc = os.path.join(path_client_files, 'public_key.pem')
        with open(save_loc, 'wb') as pem_file:
            pem_file.write(pem_pub)


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
        option = input(
            f'Welcome to SecuringTheCloud. [R]egister or [L]og in? ([Q] to exit)\n-----------------\n').lower()

        if option == REGISTER:

            res = register_new_user(conn, users + admins)

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


def register_new_user(conn, exclusion_list):
    valid_username = False
    valid_password = False
    go_back = False

    username = None

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
            print(
                f' Please enter a username between 6 and 15 characters containing only letters, numbers, -, and/or _\n')

    if go_back is False:
        while valid_password is False:
            password = input(' Password: ')

            if 6 <= len(password) <= 15 and re.match(REGEX_VALID_PASSWORD, password):
                valid_password = True
            else:
                print(f' Please enter a password between 6 and 15 characters containing only letters, numbers, '
                      f'and/or the following special characters: @ # $ % ^ & + =\n')

        if username is not None:
            encrypt_and_send(conn, REQ_REGISTER)

            res = decrypt_from_src(conn, AS_STR)
            if res == OK:
                encrypt_and_send(conn, f'{username}|{password}')
                users.append(username)
            else:
                raise Exception(PROTOCOL_EX)

            res = decrypt_from_src(conn, AS_STR)
            if res == SUCCESS:
                validate_group_folder(username)
                print(f'Registered user \'{username}\' successfully. Please proceed to log in.')

            return True
    else:
        raise Exception(PROTOCOL_EX)

    return False


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
                    validate_group_folder(username)
                    handle_user(conn, username)
                elif username in admins:
                    validate_group_folder(username)
                    handle_admin(conn, username)
                else:
                    raise Exception(f'Something\'s gone terribly wrong :(')

            elif res == FAILURE:
                # unsuccessful login; repeat loop
                print(f'Login unsuccessful. Please try again.')
            else:
                raise Exception(PROTOCOL_EX)

        else:
            raise Exception(PROTOCOL_EX)


# creates \group_files\{username}\uploads if dne
def validate_group_folder(username):
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    full_path = os.path.join(cur_dir, f'group_files\\{username}\\uploads')

    if not os.path.exists(full_path):
        os.makedirs(full_path)


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


def handle_user(conn, username):
    global cloud_files

    keep_going = True

    while keep_going is True:

        valid_option = False

        while valid_option is False:
            option = input(f'Do you wish to [U]pload or [D]ownload a file? ([B]ack to logout)\n').lower()

            if option == 'd':

                handle_download(conn, username)

            elif option == 'u':

                handle_upload(conn, username)

            elif option == 'b':

                print(f'Logging out ...')
                valid_option = True
                keep_going = False

            else:
                print(f'Not a valid option.')


def handle_download(conn, username):
    valid_option = True

    has_downloaded_smth = False

    while has_downloaded_smth is False:

        option = input(
            f'Choose one of the following options:'
            f'\n\t[L]: List the files currently available on the cloud'
            f'\n\t[<filename.ext>]: Download a file'
            f'\n\t[B]: Return to previous menu\n')

        if option == 'l' or option == 'L':

            print(f'\nFiles available for download:')
            for file in cloud_files:
                print(f' {file}')
            print()

        elif option == 'b' or option == 'B':

            valid_option = True
            break

        else:  # file request

            if option in cloud_files:
                has_downloaded_smth = True

                # first notify that local file will be overwritten if required
                cur_dir = os.path.dirname(os.path.realpath(__file__))
                path_to_dl = os.path.join(cur_dir, f'group_files\\{username}\\downloads\\{option}')

                proceed = True

                if os.path.exists(path_to_dl):  # i.e. already file in user's dl folder with same name

                    valid_option = False

                    while valid_option is False:
                        option2 = input(f'Proceeding will overwrite local file \'{option}\' in your downloads folder. '
                                        f'Proceed? [Y/N]\n').lower()

                        if option2 == 'y':
                            valid_option = True
                        elif option2 == 'n':
                            valid_option = True
                            proceed = False
                            print(f'Cancelling operation ... ')
                        else:
                            print(f'Not a recognised option. Please enter [Y/N]')

                if proceed is True:
                    result = request_download(conn, option, username)

            else:
                print(f'That file does not exist. Enter [L] to see a list of files available to download.')


def handle_upload(conn, username):

    valid_filename = False

    while valid_filename is False:

        # get filenames in user's uploads folder
        cur_dir = os.path.dirname(os.path.realpath(__file__))
        path_to_uploads = os.path.join(cur_dir, f'group_files\\{username}\\uploads')

        file_names = None

        if os.path.exists(path_to_uploads):
            print(f'Files available for upload:')
            file_names = os.listdir(path_to_uploads)
            for file in file_names:
                print(f'\t{file}')
            print()
        else:
            raise Exception(f'Uploads folder doesn\'t exist for user {username}')

        file_name = input('\nPlease enter the name of the file you wish to upload. ([B]ack to return)\n')

        if file_name == 'b' or file_name == 'B':
            valid_filename = True
        elif file_name in file_names:

            proceed = True

            if file_name in cloud_files:
                valid_option = False

                while valid_option is False:
                    overwrite = input(f'File with this name already uploaded. Overwrite? [Y/N]\n').lower()
                    if overwrite == 'y':
                        valid_option = True
                        proceed = True

                        # Delete the old file
                        encrypt_and_send(conn, REQ_DEL_FILE)
                        res = decrypt_from_src(conn, AS_STR)
                        if res == OK:
                            encrypt_and_send(conn, file_name)

                            res = decrypt_from_src(conn, REQ_DEL_FILE)
                            if res == FAILURE:
                                print(f'Something went wrong deleting cloud file. Aborting ...')
                                proceed = False
                        else:
                            raise Exception(PROTOCOL_EX)
                    elif overwrite == 'n':
                        valid_option = True
                        proceed = False
                        print(f'Operation cancelled.')
                    else:
                        print(f'Invalid option. Please enter [Y/N].')

            if proceed:
                upload_file_path = os.path.join(path_to_uploads, file_name)
                print(f'Uploading \'{file_name}\' ... ')

                file_bytes_unencrypted = None
                with open(upload_file_path, 'rb') as upload_file:
                    file_bytes_unencrypted = upload_file.read()

                encrypt_and_send(conn, REQ_UPLOAD)
                res = decrypt_from_src(conn, AS_STR)

                if res == OK:
                    # proceed to send encrypted file bytes
                    encrypt_and_send(conn, file_name)

                    res = decrypt_from_src(conn, AS_STR)
                    if res == OK:
                        encrypt_and_send(conn, file_bytes_unencrypted)
                    else:
                        raise Exception(PROTOCOL_EX)

                    res = decrypt_from_src(conn, AS_STR)
                    if res == SUCCESS:
                        # add file to local list of files available on cloud
                        cloud_files.append(file_name)

                        print(f'File uploaded to cloud successfully.')
                    else:
                        print(f'Unexpected error uploading file to cloud')

                else:
                    raise Exception(PROTOCOL_EX)

        else:
            print(f'Couldn\'t find file \'{file_name}\'. Please ensure this file is '
                  f'located at {path_to_uploads}')


def handle_admin(conn, username):
    keep_going = True

    while keep_going:
        option = input(f'Please choose an option:'
                       f'\n\t[U]:\tUpload a file'
                       f'\n\t[D]:\tDownload a file'
                       f'\n\t[M]:\tManage cloud group'
                       f'\n\t[B]:\tLog out\n').lower()

        if option == 'u':
            handle_upload(conn, username)
        elif option == 'd':
            handle_download(conn, username)
        elif option == 'm':
            manage_cloud_group(conn, username)
        elif option == 'b':
            keep_going = False


def manage_cloud_group(conn, username):
    keep_going = True

    while keep_going:
        option = input(f'Please choose a user management option:'
                       f'\n[U]:\tDelete a user'
                       f'\n[F]:\tDelete a cloud file'
                       f'\n[P]:\tPromote a user to admin'
                       f'\n[D]:\tDemote an admin'
                       f'\n[B]:\tGo back\n').lower()

        if option == 'u':
            handle_delete_user(conn)
        elif option == 'f':
            handle_file_deletion(conn)
        elif option == 'd':
            handle_admin_demotion(conn)
        elif option == 'p':
            handle_user_promotion(conn)
        elif option == 'b':
            keep_going = False
        else:
            print(f'Option not recognised. Please try again.\n')


def handle_file_deletion(conn):
    global cloud_files

    keep_going = True

    while keep_going is True:
        print(f'Files currently stored on cloud:')
        for file in cloud_files:
            print(f'\t{file}')

        file_name = input(f'Please enter the name of the file you wish to delete: ([B] to go back)\n')

        if file_name.lower() == 'b':
            keep_going = False
        elif file_name in cloud_files:
            # send request to CAM to delete file
            encrypt_and_send(conn, REQ_DEL_FILE)
            res = decrypt_from_src(conn, AS_STR)

            if res == OK:

                # send filename to delete
                encrypt_and_send(conn, file_name)
                res = decrypt_from_src(conn, AS_STR)

                if res == SUCCESS:
                    print(f'File \'{file_name}\' successfully removed from cloud group storage')

                    # remove reference in local data structure
                    cloud_files.remove(file_name)
                else:
                    print(f'Something went wrong deleting that file :/')

            else:
                raise Exception(PROTOCOL_EX)

        else:
            print(f'Invalid file name. Please try again.')


def handle_admin_demotion(conn):
    global users, admins

    valid_username = False

    while valid_username is False:

        print(f'Admins available for demotion:')
        for admin in admins:
            print(f'\t{admin}')

        target_admin = input(f'\nPlease enter the name of the admin you wish to demote. ([B]ack to go back)\n')

        if target_admin.lower() == 'b':
            valid_username = True  # break
        elif target_admin in admins:
            # Move local record into users list
            admins.remove(target_admin)
            users.append(target_admin)

            # Send CAM a message to move user record into users directory
            encrypt_and_send(conn, REQ_RM_ADMIN)
            res = decrypt_from_src(conn, AS_STR)

            if res == OK:
                # send username to demote:
                encrypt_and_send(conn, target_admin)
                res = decrypt_from_src(conn, AS_STR)

                if res == SUCCESS:
                    print(f'User {target_admin} successfully demoted to user')
                    print(f'\tUSERS: {users}')
                    print(f'\tADMINS: {admins}')
                else:  # FAILURE
                    print(f'Unexpected error occurred when promoting user in CAM :/')
            else:
                raise Exception(PROTOCOL_EX)

        elif target_admin in users:
            print(f'That user is not an admin!')
        else:  # invalid username
            print(f'That user does not exist. Please try again.')


def handle_user_promotion(conn):
    global users, admins

    valid_username = False

    while valid_username is False:

        print(f'Users available for promotion:')
        for user in users:
            print(f'\t{user}')

        target_user = input(f'\nPlease enter the name of the user you wish to promote to admin. ([B]ack to go back)\n')

        if target_user.lower() == 'b':
            valid_username = True  # break
        elif target_user in users:
            # Move local record into admins list
            users.remove(target_user)
            admins.append(target_user)

            # Send CAM a message to move user record into admin directory
            encrypt_and_send(conn, REQ_MK_ADMIN)
            res = decrypt_from_src(conn, AS_STR)

            if res == OK:
                # send username to promote:
                encrypt_and_send(conn, target_user)
                res = decrypt_from_src(conn, AS_STR)

                if res == SUCCESS:
                    print(f'User {target_user} successfully promoted to admin')
                    print(f'\tUSERS: {users}')
                    print(f'\tADMINS: {admins}')
                else:  # FAILURE
                    print(f'Unexpected error occurred when promoting user in CAM :/')
            else:
                raise Exception(PROTOCOL_EX)
        elif target_user in admins:
            print(f'That user is already an admin!')
        else:  # invalid username
            print(f'That user does not exist. Please try again.')


def handle_delete_user(conn):

    global users, admins

    all_users = users + admins
    print(all_users)

    valid_username = False

    while valid_username is False:
        target_user = input(f'Enter a username to delete. Enter [L] to view a list of registered users. '
                            f'Enter [B] to go back.\n')

        if target_user == 'L' or target_user == 'l':
            for user in all_users:
                print(f'\t{user}')
        elif target_user == 'B' or target_user == 'b':
            valid_username = True
        elif target_user in all_users:
            # send req to delete to cam:
            encrypt_and_send(conn, REQ_DEL_USER)
            res = decrypt_from_src(conn, AS_STR)

            if res == OK:
                # send the username
                encrypt_and_send(conn, target_user)
                res = decrypt_from_src(conn, AS_STR)

                if res == SUCCESS:
                    print(f'User {target_user} deleted from CAM records ... ')
                else:
                    print(f'Couldn\'t find record for user {target_user} in CAM :/')
            else:
                raise Exception(PROTOCOL_EX)

            # delete from local group records:
            cur_dir = os.path.dirname(os.path.realpath(__file__))
            group_files_target = os.path.join(cur_dir, f'group_files\\{target_user}')
            print(group_files_target)

            rmtree(group_files_target)


def encrypt_and_send(conn, msg):
    global public_key_cam

    # convert msg to bytes
    if isinstance(msg, str):
        msg = str.encode(msg)

    ciphertext = public_key_cam.encrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    signature = private_key.sign(
        ciphertext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # print(f'\tSending {msg}; ciphertext: {ciphertext}')
    conn.send(ciphertext)

    # print(f'\t\tSending signature: {signature}')
    conn.send(signature)


def decrypt_from_src(conn, as_what):
    global private_key, public_key_cam

    ciphertext = conn.recv()
    signature = conn.recv()

    try:
        verified_ciphertext = public_key_cam.verify(
            signature,
            ciphertext,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # will throw exception if signature not valid
        #   otherwise decrypt
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # cast as string if requested
        if as_what == AS_STR:
            plaintext = plaintext.decode("utf-8")

        # print(f'\tReceived {plaintext}; ciphertext: {ciphertext}')
        return plaintext

    except InvalidSignature:
        print(f'Invalid signature on msg')

    return None


def request_download(conn, filename, username):
    encrypt_and_send(conn, REQ_DOWNLOAD)
    res = decrypt_from_src(conn, AS_STR)

    if res == OK:
        # submit request for file in form [filename.ext]
        encrypt_and_send(conn, filename)

        res = decrypt_from_src(conn, AS_BYTES)

        if res == str.encode(FAILURE):  # file not found on cloud
            print(f'Unexpected error finding file in cloud.')
        else:
            write_to_user_directory(res, username, filename)
            print(f'File download successful. You file has been saved to \'group_files\\{username}\\downloads\'.')

    else:
        raise Exception(PROTOCOL_EX)


def write_to_user_directory(file_bytes, username, filename):
    # files that are downloaded are written to group_files/<username>/downloads/
    cur_dir = os.path.dirname(os.path.realpath(__file__))

    path_to_user_dir = os.path.join(cur_dir, f'group_files\\{username}\\downloads')

    # make parent directories if they don't already exist
    if not os.path.exists(path_to_user_dir):
        os.makedirs(path_to_user_dir)

    path_to_target_file = os.path.join(path_to_user_dir, filename)

    with open(path_to_target_file, 'wb') as target_file:
        target_file.write(file_bytes)
        target_file.close()


if __name__ == '__main__':
    main()
