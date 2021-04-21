import io
import os.path

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from multiprocessing.connection import Listener

from cryptography.fernet import Fernet

# What GDrive permissions we're requiring:
SCOPES = ['https://www.googleapis.com/auth/drive']

# Constants
REGISTER = 0
LOG_IN = 1

CLOUD = 0
CLIENT = 1

ENCRYPT = 0
DECRYPT = 1

USERS_PATH = r"cam_files\users"
ADMINS_PATH = r"cam_files\admins"

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
user_usernames = []
admin_usernames = []

symmetric_key_cloud = None
symmetric_key_client = None


def main():
    global user_usernames, admin_usernames, symmetric_key_client, symmetric_key_cloud

    # authorise self to upload/download from associated GDrive account
    drive_service = perform_cloud_auth()

    # get the Fernet key for communication between program and cloud
    symmetric_key_cloud = Fernet(load_key(CLOUD))
    # get the Fernet key for communication between the program and client
    symmetric_key_client = Fernet(load_key(CLIENT))

    # initialise list of usernames (one time file-read)
    user_usernames, admin_usernames = load_usernames(USERS_PATH, ADMINS_PATH)

    print(f'CloudAccessManager ready to service requests ...')

    # listen for communication from cloud group client
    address = ('localhost', 6000)
    listener = Listener(address, authkey=b'cloud_group')

    # accept connection via socket
    conn = listener.accept()
    print(f'connection accepted from {listener.last_accepted}')

    # receive messages from cloud group client
    while True:
        msg = decrypt_from_src(conn, symmetric_key_client)
        print(msg)
        if msg == HELLO:  # communication established
            print('msg was hello')
            # conn.send(HELLO)
            encrypt_and_send(conn, HELLO, symmetric_key_client)

            close = False

            while close is False:
                req = decrypt_from_src(conn, symmetric_key_client)
                if req == REQ_USER_LIST:
                    send_user_list(conn)
                elif req == REQ_REGISTER:
                    process_registration(conn)
                elif req == REQ_LOGIN:
                    process_login(conn)
                elif req == REQ_DOWNLOAD:
                    process_download(conn)
                elif req == REQ_CLOSE:
                    # conn.send(OK)
                    encrypt_and_send(conn, OK, symmetric_key_client)
                    print(f'Closing connection ... ')
                    close = True

        conn.close()
        break


        # file_name = conn.recv()
        # if file_name == 'close':
        #     conn.close()
        #     break
        # else:
        #     print(f'Expecting file from [{listener.last_accepted}]: {file_name}')
        #
        #     file_bytes = conn.recv()
        #     print(f'Received file bytes of \'{file_name}\' from [{listener.last_accepted}]: {file_bytes}')
    listener.close()


def perform_cloud_auth():
    # Load access token or creates one if DNE
    creds = None

    # Load credentials if they exist (i.e. the authorisation set up has been run already)
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    # If they don't exist, create
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    # return reference to drive service object that will handle upload/download requests
    return build('drive', 'v3', credentials=creds)


def load_key(type):

    cwd = os.getcwd()
    key = None

    # Either fetch saved fernet key from previous session or generate if DNE
    if type == CLOUD:
        path_to_key = f'{cwd}\\cam_files\\fernet_cloud.key'
    elif type == CLIENT:
        path_to_key = f'{cwd}\\cam_files\\fernet_client.key'

    if os.path.exists(path_to_key) is False:  # key dne yet; create
        # generate symmetric key for communication with cloud/client
        print(f'Writing New {"Cloud" if type == CLOUD else "Client"} Symmetric Key ...')
        key = Fernet.generate_key()

        # save the key
        with open(path_to_key, 'wb') as key_file:
            key_file.write(key)
            key_file.close()

        # Save an additional copy for the client to use
        if type == CLIENT:
            path_to_client = f'{cwd}\\client_files\\fernet_client.key'

            # save the key
            with open(path_to_client, 'wb') as key_file:
                key_file.write(key)
                key_file.close()

    if key is None:  # will be none if it already existed; load
        # load symmetric key
        with open(path_to_key, 'rb') as key_file:
            key = key_file.read()

    return key


def load_usernames(users_path, admins_path):

    users = []
    admins = []

    cur_dir = os.path.dirname(os.path.realpath(__file__))

    full_path_users = os.path.join(cur_dir, users_path)
    users = [os.path.splitext(file)[0] for file in os.listdir(full_path_users)]

    full_path_admins = os.path.join(cur_dir, admins_path)
    admins = [os.path.splitext(file)[0] for file in os.listdir(full_path_admins)]

    return users, admins


def send_user_list(conn):
    # user_list, admin_list = load_usernames(USERS_PATH, ADMINS_PATH)
    encoded_list = " ".join(user_usernames)
    encoded_list += "|"
    encoded_list += " ".join(admin_usernames)
    # conn.send(encoded_list)
    encrypt_and_send(conn, encoded_list, symmetric_key_client)


def process_registration(conn):
    encrypt_and_send(conn, OK, symmetric_key_client)

    # TODO: ENCRYPT ON CLIENT SIDE, DECRYPT HERE
    registration_details = decrypt_from_src(conn, symmetric_key_client)  # in form "username|password"
    registration_details = registration_details.split("|")
    username = registration_details[0]
    password = registration_details[1]
    print(f'Preparing to register user \'{username}\' ... ')

    # generate new Fernet symm key for user:
    users_symm_key = Fernet.generate_key()
    print(f'Generating key for \'{username}\' ...')

    # write the new user details to CAM files:
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    full_path_users = os.path.join(cur_dir, USERS_PATH)
    path_to_new_file = os.path.join(full_path_users, f'{username}.txt')

    with open(path_to_new_file, 'w') as new_user_file:
        new_user_file.write(f'{password}\n{users_symm_key}')
        new_user_file.close()

    # add to dynamic data structure representing usernames:
    user_usernames.append(username)

    # conn.send(SUCCESS)
    encrypt_and_send(conn, SUCCESS, symmetric_key_client)
    print(f'Successfully created registration record for \'{username}\'')


def process_login(conn):
    # acknowledge login request
    encrypt_and_send(conn, OK, symmetric_key_client)

    login_details = decrypt_from_src(conn, symmetric_key_client)  # in form '[username]|[password]'
    login_details = login_details.split("|")
    print(f'Login Details: {login_details}')
    username = login_details[0]
    password = login_details[1]

    if username in user_usernames or username in admin_usernames:
        # get user's password from storage
        cur_dir = os.path.dirname(os.path.realpath(__file__))
        full_path_users = os.path.join(cur_dir, USERS_PATH)
        print(full_path_users)
        path_user_record = os.path.join(full_path_users, f'{username}.txt')

        print(path_user_record)

        with open(path_user_record, 'rb') as user_file:
            # receive string representation from saved bytes
            true_password = ''.join(user_file.readline().decode('utf-8').split())

        # if passed pw matches registration pw
        if password == true_password:
            encrypt_and_send(conn, SUCCESS, symmetric_key_client)
        else:
            encrypt_and_send(conn, FAILURE, symmetric_key_client)

    else:
        # user dne
        encrypt_and_send(conn, FAILURE, symmetric_key_client)


def process_download(conn):
    encrypt_and_send(conn, OK, symmetric_key_client)

    target_file = decrypt_from_src(conn, symmetric_key_client)
    print(target_file)

    #@todo replace sample file with actual logic
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    full_path_users = os.path.join(cur_dir, USERS_PATH)
    path_user_record = os.path.join(full_path_users, f'claire.txt')

    with open(path_user_record, 'rb') as user_file:
        file_bytes = user_file.read()
        encrypt_and_send(conn, file_bytes, symmetric_key_client)


# either encrypts a message given a fernet key and sends it using the given connection object
def encrypt_and_send(conn, msg, fernet_key):
    if isinstance(msg, str):
        msg = str.encode(msg)
    ciphertext = fernet_key.encrypt(msg)
    print(f'\tSending {msg}; ciphertext: {ciphertext}')
    conn.send(ciphertext)


# gets the next msg from a connection object, decrypts using the key and returns the plaintext
def decrypt_from_src(conn, fernet_key):
    ciphertext = conn.recv()
    plaintext = fernet_key.decrypt(ciphertext).decode("utf-8")
    print(f'\tReceived {plaintext}; ciphertext: {ciphertext}')
    return plaintext


def service_login(conn):
    # get whether the client is registering or logging in
    service_type = None


if __name__ == '__main__':
    main()
