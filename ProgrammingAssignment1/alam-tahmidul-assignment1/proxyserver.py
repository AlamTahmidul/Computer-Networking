from socket import *

serverName = "127.0.0.1"
serverPort = 4080

def get_requests(connectionSocket: socket):
    # Get the Request from Browser
    request = connectionSocket.recv(2048)
    response = request.decode()
    url = response.split(" ")[1].lstrip("/")

    if (url == ""):
        head = "HTTP/1.1 Root\r\n\r\n Root Page!\r\n\r\n" # Send the HTTP Response
        connectionSocket.sendall(head.encode()) # Send 404 Back
    else:
        # CHECK CACHE
        if (url.find("favicon.ico") == -1 and url.find(".png") == -1):
            try: # If there is a cache present, give it to connectionSocket
                f = open(f"{url}.txt", "rb").read()
                print(f"Loading {url} from cache...")
                connectionSocket.sendall(f)
                print(f"Loaded {url} from Cache!")
                # return
            except FileNotFoundError as fnf: # Otherwise, create a cache for the given url
                try:
                    # print(response)
                    header = f"GET / HTTP/1.1\r\nHost: {url}\r\nAccept: text/html\r\n\r\n"
                    newServer = socket(AF_INET, SOCK_STREAM)
                    newServer.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                    newServer.connect((url, 80))
                    newServer.sendall(header.encode())
                    newServer.settimeout(3) # After 3 seconds, block all socket operations
                    
                    # Save cache in file
                    print(f"Creating Cache for {url}!")
                    f = open(f"{url}.txt", "wb")
                    r_len = 1024 # Default Buffer Size
                    while r_len >= 1024: # Loop over buffer length (as much as possible within 5 secs)
                        data = newServer.recv(4096) # Get data from the accessing server (i.e. www.google.com)
                        connectionSocket.send(data) # Send data back to client
                        r_len = len(data) # Get the length in bytes of read data (Should have a lot of data)
                        f.write(data) # Write to file (aka cache)
                    print(f"Created Cache for {url}!")
                    f.close()
                except gaierror as g:
                    # print(f"Created Cache for {url} with errors")
                    head = "HTTP/1.1 404 Not Found\r\n\r\n URL cannot be reached\r\n\r\n" # Send the HTTP Response head
                    connectionSocket.sendall(head.encode()) # Send 404 Back
                except timeout as t:
                    print(f"Created Cache for {url}!")
                except Exception as e:
                    head = "HTTP/1.1 404 Not Found\r\n\r\n URL cannot be reached\r\n\r\n" # Send the HTTP Response head
                    connectionSocket.sendall(head.encode()) # Send 404 Back
                except OSError as ose:
                    head = "HTTP/1.1 404 Not Found\r\n\r\n URL cannot be reached\r\n\r\n" # Send the HTTP Response head
                    connectionSocket.sendall(head.encode()) # Send 404 Back


def run_proxy():
    serverSocket = socket(AF_INET, SOCK_STREAM) # TCP Socket
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serverSocket.bind((serverName, serverPort))
    serverSocket.listen(1) # Listen to 1 request at a time
    print(f"Proxy Server {serverName} listening on port {serverPort}: http://{serverName}:{serverPort}")

    while True:
        connectionSocket, addr = serverSocket.accept() # Accept incoming connections
        get_requests(connectionSocket)
        connectionSocket.close() # Keep welcoming socket

if __name__ == "__main__":
    run_proxy()