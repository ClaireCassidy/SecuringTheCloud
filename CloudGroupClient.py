from multiprocessing.connection import Client


def main():
    address = ('localhost', 6000)
    conn = Client(address, authkey=b'cloud_group')

    while True:

        # msg = input('Send a message to CAM (\'close\' to terminate): ')
        filename = input('Hello user1. Please give the name of the file you wish to encrypt: ')

        if filename == 'close':
            conn.close()
            break

        path = f'group_files/user1/files/{filename}'

        file_bytes = None

        try:
            with open(f'{path}', 'rb') as file_to_send:
                upload_name = input('Give the upload a name (ENTER to use current name):')
                if not upload_name:  # User entered no name
                    upload_name = filename

                print(f'Sending file \'{path}\' to CAM with name \'{upload_name}\'')
                file_bytes = file_to_send.read()
        except FileNotFoundError:
            print('Couldn\'t find file ' + path)

        if file_bytes is not None:
            conn.send(file_bytes)

        print()


if __name__ == '__main__':
    main()
