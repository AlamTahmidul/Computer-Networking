from socket import *

# PRELIM SETUP 
localAddr = '127.0.0.1' # IPV4 ADDRESS
serverPort = 5000 # PORT NUMBER
indexFile = "HelloWorld.html" # DEFAULT PAGE

def receive_requests(connectionSocket : socket):
    request = connectionSocket.recv(65535) # Gets the content
    response = request.decode()
    # print(response)
    f_url = response.split(" ")[1].lstrip("/")

    if (f_url == ""):
        f_url = indexFile

    try:
        f = open("" + f_url)
        data = f.read()
        response = f"HTTP/1.1 200 OK\r\n\r\n {data}\r\n\r\n" # Send the HTTP Response
        connectionSocket.sendall(response.encode())
    except FileNotFoundError as f:
        response = "HTTP/1.1 404 NOT FOUND\r\n\r\n 404 Not Found: File not found\r\n\r\n" # Send the HTTP Response
        connectionSocket.sendall(response.encode()) # Send 404 Back
    except PermissionError as pe:
        response = "HTTP/1.1 404 NOT FOUND\r\n\r\n 404 Not Found: Access Denied\r\n\r\n" # Send the HTTP Response
        connectionSocket.sendall(response.encode()) # Send 404 Back
    finally:
        # print("============================")
        pass

def run_server():
    serverSocket = socket(AF_INET, SOCK_STREAM) # Creates TCP Socket for server at port 4200
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1) # OSERR 98: Address already in use; SO_REUSEADDR = reuse local socket in TIME_WAIT state
    serverSocket.bind((localAddr, serverPort))
    serverSocket.listen(1) # Listen for incoming connections
    print("Server running on ", (localAddr, serverPort))

    while True:
        connectionSocket, addr = serverSocket.accept() # Accept connection from client
        print(f"Connection from {addr} is established!")

        receive_requests(connectionSocket=connectionSocket) # Get the request
        connectionSocket.close() # Close the connection socket (not the welcoming socket)


if __name__ == "__main__":
    run_server()