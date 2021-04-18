from multiprocessing.connection import Client

def main():
    address = ('localhost', 6000)
    conn = Client(address, authkey=b'cloud_group')
    conn.send("HELLO THERE FROM CLIENT")
    conn.send('close')

if __name__ == '__main__':
    main()
