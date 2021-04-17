from __future__ import print_function

import io
import os.path
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from cryptography.fernet import Fernet

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/drive']


def main():
    """Shows basic usage of the Drive v3 API.
    Prints the names and ids of the first 10 files the user has access to.
    """

    # ONE-TIME AUTHORISATION OF APP FOR GROUP TO EDIT FILES ON THE CONNECTED GOOGLE DRIVE ACCOUNT
    #   IF CHANGING SCOPES, DELETE token.json TO REGEN PERMISSIONS
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
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

    service = build('drive', 'v3', credentials=creds)

    ################## Finish create credentials

    # One-time create of symmetric key for encrypting file up to cloud
    symmetric_key_cloud = None

    if os.path.exists('fernet.key') is False:  # file dne yet; create
        # generate symmetric key for communication with cloud
        print("Writing New Cloud Symmetric Key ...")
        symmetric_key_cloud = Fernet.generate_key()

        # save the key
        with open('fernet.key', 'wb') as key_file:
            key_file.write(symmetric_key_cloud)
            key_file.close()

    ################# Finish create symmetric key

    try:

        if symmetric_key_cloud is None:
            # load symmetric key
            with open('fernet.key', 'rb') as key_file:
                symmetric_key_cloud = key_file.read()

        fernet_key = Fernet(symmetric_key_cloud)

        # Load the file bytes to encrypt
        with open('encrypt_me.txt', 'rb') as to_encrypt:
            plaintext = to_encrypt.read()

        # Encrypt plaintext using cloud symmetric key:
        ciphertext = fernet_key.encrypt(plaintext)
        print(f'Plaintext: {plaintext}\nCiphertext: {ciphertext}\nDecrypted: {fernet_key.decrypt(ciphertext)}')

        # with open('encrypted.txt', 'wb') as encrypted:
        #     encrypted.write(ciphertext)
        #     encrypted.close()
        #

        # Perform resumable upload: (could be >5MB)

        file_name = 'test_upload.txt'
        file_metadata = {'name': file_name}
        try:
            to_upload = MediaFileUpload(file_name, resumable=True)
            file = service.files().create(body=file_metadata,
                                          media_body=to_upload,
                                          fields='id').execute()
            file_id = file.get('id')

            print('Created file with id ' + file_id)

            # Now pull it back down - query api by file_id:
            print(f'Fetching file with id {file_id}')
            request = service.files().get_media(fileId=file_id)
            file_stream = io.BytesIO()
            downloader = MediaIoBaseDownload(file_stream, request)

            finishedDownloading = False
            while finishedDownloading is False:
                finishedDownloading, done = downloader.next_chunk()
                print(f'Download {int(finishedDownloading.progress() * 100)} %')

            # File bytes in file_stream; now save to file on os
            with open(f'DL_{file_name}', 'wb') as local_file:
                local_file.write(file_stream.getvalue())
                file_stream.close()
                local_file.close()

        except FileNotFoundError:
            print('Couldn\'t find file ' + file_name)

        # Call the Drive v3 API
        results = service.files().list(
            pageSize=10, fields="nextPageToken, files(id, name)").execute()
        items = results.get('files', [])

        if not items:
            print('No files found.')
        else:
            print('Files:')
            for item in items:
                print(u'{0} ({1})'.format(item['name'], item['id']))
    except FileNotFoundError:
        print('Cloud Symmetric Key failed to load :?')


if __name__ == '__main__':
    main()
