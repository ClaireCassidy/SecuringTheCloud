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


def main():
    # authorise self to upload/download from associated GDrive account
    drive_service = perform_cloud_auth()

    # get the Fernet key for communication between program and cloud
    symmetric_key_cloud = load_key()
    fernet_key = Fernet(symmetric_key_cloud)

    print(f'CloudAccessManager ready to service requests ...')

    # listen for communication from cloud group client
    address = ('localhost', 6000)
    listener = Listener(address, authkey=b'cloud_group')
    conn = listener.accept()
    print(f'connection accepted from {listener.last_accepted}')
    while True:
        file_name = conn.recv()
        if file_name == 'close':
            conn.close()
            break
        else:
            print(f'Expecting file from [{listener.last_accepted}]: {file_name}')

            file_bytes = conn.recv()
            print(f'Received file bytes of \'{file_name}\' from [{listener.last_accepted}]: {file_bytes}')
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


if __name__ == '__main__':
    main()
