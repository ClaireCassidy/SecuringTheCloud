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

REGISTER = 0
LOG_IN = 1

USERS_PATH = r"cam_files\users"
ADMINS_PATH = r"cam_files\admins"

# Communication protocol between CAM and Client:
HELLO = "hello"
REQ_USER_LIST = "userlist"
REQ_REGISTER = "register"
REQ_CLOSE = "close"
OK = "ok"                       # request received, proceed
SUCCESS = "success"             # request completed successfully
FAILURE = "failure"             # something went wrong

# dynamic data structure for keeping a list of usernames in memory
user_usernames = []
admin_usernames = []

def main():
    global user_usernames
    global admin_usernames

    # authorise self to upload/download from associated GDrive account
    drive_service = perform_cloud_auth()

    # get the Fernet key for communication between program and cloud
    symmetric_key_cloud = load_key()
    fernet_key = Fernet(symmetric_key_cloud)

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
        msg = conn.recv()
        if msg == HELLO:  # communication established
            conn.send(HELLO)

            close = False

            while close is False:
                req = conn.recv()
                if req == REQ_USER_LIST:
                    send_user_list(conn)
                elif req == REQ_REGISTER:
                    process_registration(conn)
                elif req == REQ_CLOSE:
                    conn.send(OK)
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


def load_key():
    # Either fetch saved fernet key from previous session or generate if DNE
    symmetric_key_cloud = None

    if os.path.exists('fernet.key') is False:  # key dne yet; create
        # generate symmetric key for communication with cloud
        print("Writing New Cloud Symmetric Key ...")
        symmetric_key_cloud = Fernet.generate_key()

        # save the key
        with open('fernet.key', 'wb') as key_file:
            key_file.write(symmetric_key_cloud)
            key_file.close()

    if symmetric_key_cloud is None:  # will be none if it already existed; load
        # load symmetric key
        with open('fernet.key', 'rb') as key_file:
            symmetric_key_cloud = key_file.read()

    return symmetric_key_cloud

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
    conn.send(encoded_list)

def process_registration(conn):
    conn.send(OK)

    # TODO: ENCRYPT ON CLIENT SIDE, DECRYPT HERE
    registration_details = conn.recv()  # in form "username|password"
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

    conn.send(SUCCESS)
    print(f'Successfully created registration record for \'{username}\'')


def service_login(conn):
    # get whether the client is registering or logging in
    service_type = None





if __name__ == '__main__':
    main()
