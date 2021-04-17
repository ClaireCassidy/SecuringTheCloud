from __future__ import print_function

import io
import os.path
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

# If modifying these scopes, delete the file token.json.
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload

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


if __name__ == '__main__':
    main()
