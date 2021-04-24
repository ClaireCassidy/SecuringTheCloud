import io
import os.path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload

from multiprocessing.connection import Listener
from apiclient import errors

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# What GDrive permissions we're requiring:
SCOPES = ['https://www.googleapis.com/auth/drive']
drive_service = None

# Constants
REGISTER = 0
LOG_IN = 1

CLOUD = 0
CLIENT = 1

ENCRYPT = 0
DECRYPT = 1

AS_BYTES = 0
AS_STR = 1

USER = 0
ADMIN = 1

USERS_PATH = r"cam_files\users"
ADMINS_PATH = r"cam_files\admins"

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
user_usernames = []
admin_usernames = []
cloud_filenames = {}

symmetric_key_cloud = None
public_key_client = None
private_key = None


def main():
    global user_usernames, admin_usernames, \
        symmetric_key_cloud, drive_service, cloud_filenames, public_key_client, private_key

    # authorise self to upload/download from associated GDrive account
    drive_service = perform_cloud_auth()

    # perform one-time directory setups
    perform_dir_setup()
    # perform one-time public/private key generation or load existing keys
    load_asymm_keys()

    # get the Fernet key for communication between program and cloud
    symmetric_key_cloud = Fernet(load_key(CLOUD))

    # initialise list of usernames (one time file-read)
    user_usernames, admin_usernames = load_usernames(USERS_PATH, ADMINS_PATH)
    # initialise list of gdrive files
    load_cloud_file_list()

    print(f'CloudAccessManager ready to service requests ...')

    # listen for communication from cloud group client
    address = ('localhost', 6000)
    listener = Listener(address, authkey=b'cloud_group')

    # accept connection via socket
    conn = listener.accept()
    print(f'connection accepted from {listener.last_accepted}')

    # client initiate comms with a plaintext HELLO exchange:

    proceed = True

    msg = conn.recv()
    if msg == HELLO:

        # respond with plaintext hello
        conn.send(HELLO)

        # If first time communicating with client, exchange pub keys in plaintext
        cur_dir = os.path.dirname(os.path.realpath(__file__))
        path_to_client_pubkey = os.path.join(cur_dir, f'cam_files\\keys\\client_pubkey.pem')

        if not os.path.exists(path_to_client_pubkey):
            perform_key_exchange(conn, cur_dir, path_to_client_pubkey)

        # further comms will be encrypted, so load client's pub key
        load_client_pub_key()

        # # send test msg:
        # encrypt_and_send(conn, f'Hello from CAM!', public_key_client)
        # res = decrypt_from_src(conn, private_key)
        # print(f'Client says: \'{res}\'')

    else:
        proceed = False
        conn.close()  # terminate connection; protocol not being followed

    if proceed is True:

        while True:  # repeatedly service requests from client until they close

            # keys exchanged, can now engage in encrypted comms
            close = False

            while close is False:

                req = decrypt_from_src(conn, AS_STR)

                if req == REQ_USER_LIST:
                    send_user_list(conn)
                elif req == REQ_REGISTER:
                    process_registration(conn)
                elif req == REQ_LOGIN:
                    process_login(conn)
                elif req == REQ_DOWNLOAD:
                    process_download(conn)
                elif req == REQ_CLOUD_FILES:
                    send_file_list(conn)
                elif req == REQ_UPLOAD:
                    handle_upload(conn)
                elif req == REQ_DEL_USER:
                    handle_user_deletion(conn)
                elif req == REQ_MK_ADMIN:
                    handle_user_promotion(conn)
                elif req == REQ_RM_ADMIN:
                    handle_admin_demotion(conn)
                elif req == REQ_DEL_FILE:
                    handle_delete_file(conn)
                elif req == REQ_CLOSE:

                    encrypt_and_send(conn, OK)
                    print(f'Closing connection ... ')
                    close = True

            conn.close()
            break

    listener.close()


def perform_key_exchange(conn, cur_dir, save_path):
    # receive public key
    client_pubkey = conn.recv()
    print(client_pubkey)

    # store key
    with open(save_path, 'wb') as file:
        file.write(client_pubkey)
        file.close()

    # respond with own pubkey
    path_to_cam_pubkey = os.path.join(cur_dir, f'cam_files\\keys\\public_key.pem')

    with open(path_to_cam_pubkey, 'rb') as file:
        file_bytes = file.read()
        print(file_bytes)
        conn.send(file_bytes)


def load_asymm_keys():
    global private_key

    cur_dir = os.path.dirname(os.path.realpath(__file__))
    path_to_keys = os.path.join(cur_dir, f'cam_files\\keys')

    if not os.path.exists(path_to_keys):    # need to generate them
        print(f'Performing one-time key generation ... ')
        # make it
        os.mkdir(path_to_keys)

        # generate public and private keys
        cam_priv_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        cam_public_key = cam_priv_key.public_key()

        # store the keys
        pem_priv = cam_priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # save local variable for priv key
        private_key = pem_priv

        save_loc = os.path.join(path_to_keys, 'private_key.pem')
        with open(save_loc, 'wb') as pem_file:
            pem_file.write(pem_priv)

        pem_pub = cam_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                              format=serialization.PublicFormat.SubjectPublicKeyInfo)

        save_loc = os.path.join(path_to_keys, 'public_key.pem')
        with open(save_loc, 'wb') as pem_file:
            pem_file.write(pem_pub)
    else:
        print(f'Loading asymm keys ... ')

        path_to_priv_key = os.path.join(path_to_keys, f'private_key.pem')

        # retrieve private key
        with open(path_to_priv_key, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )


def load_client_pub_key():
    global public_key_client

    cur_dir = os.path.dirname(os.path.realpath(__file__))
    path_to_client_pubkey = os.path.join(cur_dir, f'cam_files\\keys\\client_pubkey.pem')

    with open(path_to_client_pubkey, "rb") as key_file:
        public_key_client = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )


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


def load_cloud_file_list():
    global cloud_filenames

    results = drive_service.files().list().execute()
    items = results.get('files', [])

    if not items:
        print('No files found.')
    else:
        print('Files:')
        for item in items:
            print(u'{0} ({1})'.format(item['name'], item['id']))

    # List of filename : id pairs
    for item in items:
        cloud_filenames[item['name']] = item['id']

    print(cloud_filenames)


# Client request handlers:


def send_user_list(conn):
    # user_list, admin_list = load_usernames(USERS_PATH, ADMINS_PATH)
    encoded_list = " ".join(user_usernames)
    encoded_list += "|"
    encoded_list += " ".join(admin_usernames)
    # conn.send(encoded_list)
    encrypt_and_send(conn, encoded_list)


def process_registration(conn):
    encrypt_and_send(conn, OK)

    registration_details = decrypt_from_src(conn, AS_STR)  # in form "username|password"
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
    encrypt_and_send(conn, SUCCESS)
    print(f'Successfully created registration record for \'{username}\'')


def handle_user_promotion(conn):
    global user_usernames, admin_usernames

    encrypt_and_send(conn, OK)
    username = decrypt_from_src(conn, AS_STR)

    cur_dir = os.path.dirname(os.path.realpath(__file__))
    # get cur path to user record:
    full_path_to_user_record = os.path.join(cur_dir, f'cam_files\\users\\{username}.txt')

    # get dest path:
    dest_path = os.path.join(cur_dir, f'cam_files\\admins\\{username}.txt')

    # move the record
    os.rename(full_path_to_user_record, dest_path)

    # update dynamic data structures holding usernames
    user_usernames.remove(username)
    admin_usernames.append(username)

    encrypt_and_send(conn, SUCCESS)


def handle_admin_demotion(conn):
    global user_usernames, admin_usernames

    encrypt_and_send(conn, OK)
    username = decrypt_from_src(conn, AS_STR)

    cur_dir = os.path.dirname(os.path.realpath(__file__))
    # get cur path to admin record:
    full_path_to_admin_record = os.path.join(cur_dir, f'cam_files\\admins\\{username}.txt')

    # get dest path:
    dest_path = os.path.join(cur_dir, f'cam_files\\users\\{username}.txt')

    # move the record
    os.rename(full_path_to_admin_record, dest_path)

    # update dynamic data structures holding usernames
    admin_usernames.remove(username)
    user_usernames.append(username)

    encrypt_and_send(conn, SUCCESS)


def process_login(conn):
    # acknowledge login request
    encrypt_and_send(conn, OK)

    login_details = decrypt_from_src(conn, AS_STR)  # in form '[username]|[password]'
    login_details = login_details.split("|")
    print(f'Login Details: {login_details}')
    username = login_details[0]
    password = login_details[1]

    user_type = None
    print(f'Users: {user_usernames}')
    print(f'Admins: {admin_usernames}')

    if username in user_usernames:
        user_type = USER
    elif username in admin_usernames:
        user_type = ADMIN

    if user_type is not None:

        # get user's password from storage
        cur_dir = os.path.dirname(os.path.realpath(__file__))

        if user_type == USER:
            full_path = os.path.join(cur_dir, USERS_PATH)
        else:  # admin
            full_path = os.path.join(cur_dir, ADMINS_PATH)

        path_user_record = os.path.join(full_path, f'{username}.txt')
        print(path_user_record)

        with open(path_user_record, 'rb') as user_file:
            # receive string representation from saved bytes
            true_password = ''.join(user_file.readline().decode('utf-8').split())

        # if passed pw matches registration pw
        if password == true_password:
            encrypt_and_send(conn, SUCCESS)
        else:
            encrypt_and_send(conn, FAILURE)

    else:
        # user dne
        encrypt_and_send(conn, FAILURE)


def process_download(conn):
    global cloud_filenames

    encrypt_and_send(conn, OK)

    target_file = decrypt_from_src(conn, AS_STR)
    print(target_file)
    print(cloud_filenames)

    if target_file in cloud_filenames:
        # query Gdrive for file
        request = drive_service.files().get_media(fileId=cloud_filenames[target_file])

        file_handler = io.BytesIO()
        downloader = MediaIoBaseDownload(file_handler, request)
        done = False
        while done is False:
            status, done = downloader.next_chunk()
            print(f'Fetching ... {int(status.progress() * 100)}%.')

        # file bytes in file_handler; will have been encrypted with cloud symm key
        #   decrypt; re-encrypt with client symm key and send
        decrypted_bytes = symmetric_key_cloud.decrypt(file_handler.getvalue())
        encrypt_and_send(conn, decrypted_bytes)

    else:
        encrypt_and_send(conn, FAILURE)


def encrypt_and_send(conn, msg):
    global public_key_client, private_key

    # convert msg to bytes
    if isinstance(msg, str):
        msg = str.encode(msg)

    # encrypt with client's public key
    ciphertext = public_key_client.encrypt(
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

    print(f'\tSending {msg}; ciphertext: {ciphertext}')
    conn.send(ciphertext)

    print(f'\t\tSending signature: {signature}')
    conn.send(signature)


# gets the next msg from a connection object, decrypts using the key and returns the plaintext
# def decrypt_from_src_symm(conn, as_what):
#     global symmetric_key_cloud
#
#     ciphertext = conn.recv()
#     plaintext = symmetric_key_cloud.decrypt(ciphertext)
#
#     if as_what == AS_STR:
#         plaintext = plaintext.decode("utf-8")
#
#     print(f'\tReceived {plaintext}; ciphertext: {ciphertext}')
#     return plaintext


# decrypts a message from the client encrypted using CAM's pub key by using the CAM's private key
def decrypt_from_src(conn, as_what):
    global private_key, public_key_client

    ciphertext = conn.recv()
    signature = conn.recv()

    try:
        verified_ciphertext = public_key_client.verify(
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

        print(f'\tReceived {plaintext}; ciphertext: {ciphertext}')
        return plaintext

    except InvalidSignature:
        print(f'Invalid signature on msg')

    return None


def handle_delete_file(conn):
    global cloud_filenames

    encrypt_and_send(conn, OK)
    target_file = decrypt_from_src(conn, AS_STR)

    # get associated GDrive id:
    file_id = cloud_filenames[target_file]

    delete_success = False
    # call on drive service to delete the file:
    try:
        drive_service.files().delete(fileId=file_id).execute()
        delete_success = True
    except errors.HttpError as error:
        print(f'ERROR OCCURRED DELETING FILE {target_file}:{file_id}\n\t{error}')

    if delete_success:
        # remove from local data structure
        cloud_filenames.pop(target_file)

        # report success to client
        encrypt_and_send(conn, SUCCESS)
    else:
        encrypt_and_send(conn, FAILURE)


def send_file_list(conn):
    global cloud_filenames

    encoded_file_list = "|".join(cloud_filenames.keys())
    print(encoded_file_list)

    encrypt_and_send(conn, encoded_file_list)


def handle_upload(conn):
    global drive_service

    encrypt_and_send(conn, OK)

    # response will be filename followed by filebytes
    file_name = decrypt_from_src(conn, AS_STR)
    encrypt_and_send(conn, OK)
    file_bytes = decrypt_from_src(conn, AS_BYTES)
    print(file_bytes)

    # encrypt the file using CAM's cloud symm key
    encrypted_file_bytes = symmetric_key_cloud.encrypt(file_bytes)

    # upload to cloud
    #   first need to save to staging area

    cur_dir = os.path.dirname(os.path.realpath(__file__))
    rel_path = f'cam_files\\stage\\{file_name}'
    path_to_stage_file = os.path.join(cur_dir, rel_path)

    with open(path_to_stage_file, 'wb') as stage_file:
        stage_file.write(encrypted_file_bytes)
        stage_file.close()

    # now upload it
    file_metadata = {'name': file_name}
    to_upload = MediaFileUpload(rel_path, resumable=True)
    file = drive_service.files().create(body=file_metadata,
                                        media_body=to_upload,
                                        fields='id').execute()
    to_upload = None

    # save uploaded file data to dynamic data structure
    cloud_filenames[file_name] = file.get('id')

    # remove file from staging area
    os.remove(rel_path)

    # tell client it was successful
    encrypt_and_send(conn, SUCCESS)


def perform_dir_setup():
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    path_to_cam_files = os.path.join(cur_dir, f'cam_files')

    if not os.path.exists(path_to_cam_files):
        print(f'Creating CAM files ... ')
        os.mkdir(path_to_cam_files)

        print(f'Setting up stage ... ')
        path_to_stage = os.path.join(path_to_cam_files, f'stage')
        os.mkdir(path_to_stage)

        print(f'Setting up user records ... ')
        path_to_users = os.path.join(path_to_cam_files, USERS_PATH)
        os.mkdir(path_to_users)

        print(f'Setting up admin records ... ')
        path_to_admins = os.path.join(path_to_cam_files, ADMINS_PATH)
        os.mkdir(path_to_admins)


def handle_user_deletion(conn):
    encrypt_and_send(conn, OK)

    username = decrypt_from_src(conn, AS_STR)

    rel_path = None
    if username in admin_usernames:
        # also delete record in users dynamic data structure:
        admin_usernames.remove(username)
        rel_path = os.path.join(ADMINS_PATH, f'{username}.txt')
    elif username in user_usernames:
        user_usernames.remove(username)
        rel_path = os.path.join(USERS_PATH, f'{username}.txt')
    else:  # user doesn't seem to exist :/
        encrypt_and_send(conn, FAILURE)

    if rel_path is not None:
        # delete user record file
        cur_dir = os.path.dirname(os.path.realpath(__file__))
        target_file = os.path.join(cur_dir, rel_path)
        print(target_file)

        os.remove(target_file)

        encrypt_and_send(conn, SUCCESS)


if __name__ == '__main__':
    main()
