import io
import os.path

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload

from cryptography.fernet import Fernet

# What GDrive permissions we're requiring:
SCOPES = ['https://www.googleapis.com/auth/drive']


def main():
    # authorise self to upload/download from associated GDrive account
    drive_service = perform_cloud_auth()

    # get the Fernet key for communication between program and cloud
    symmetric_key_cloud = load_key()
    fernet_key = Fernet(symmetric_key_cloud)

    plaintext = b'howeye'
    ciphertext = fernet_key.encrypt(plaintext)
    print(f'Plaintext: {plaintext}\nCiphertext: {ciphertext}\nDecrypted: {fernet_key.decrypt(ciphertext)}')

    with open('cam_encrypted.txt', 'wb') as test_file:
        test_file.write(ciphertext)

    file_name = 'cam_encrypted.txt'
    file_metadata = {'name': file_name}
    try:
        to_upload = MediaFileUpload(file_name, resumable=True)
        file = drive_service.files().create(body=file_metadata,
                                            media_body=to_upload,
                                            fields='id').execute()
        file_id = file.get('id')

        print('Created file with id ' + file_id)

        # Now pull it back down - query api by file_id:
        print(f'Fetching file with id {file_id}')
        request = drive_service.files().get_media(fileId=file_id)
        file_stream = io.BytesIO()
        downloader = MediaIoBaseDownload(file_stream, request)

        finished_downloading = False
        while finished_downloading is False:
            finished_downloading, done = downloader.next_chunk()
            print(f'Download {int(finished_downloading.progress() * 100)} %')

        # file bytes in file_stream, decrypt:
        decrypted_text = fernet_key.decrypt(file_stream.getvalue())
        print(f'Calling Decrypt on downloaded ciphertext: {decrypted_text}')
    except FileNotFoundError:
        print('Couldn\'t find file ' + file_name)


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
