import socket

# Fake DNS server that only returns one thing no matter what (for now)
# https://pythontic.com/modules/socket/udp-client-server-example

localIP = "127.0.0.1"
localPort = 20001
bufferSize = 1024


msgFromServer = "Hello UDP Client\n"
bytesToSend = str.encode(msgFromServer)

# create a new socket
# https://docs.python.org/3.10/library/socket.html#creating-sockets
# family is address family, using AF_INET will be (host, port) pair
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
# bind socket to an address -> format of the address dpends on the family
UDPServerSocket.bind((localIP, localPort))

print(f"UDP server up and listening on port: %s" % (localPort))

while(True):
    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    message = bytesAddressPair[0]
    address = bytesAddressPair[1]

    clientMsg = f"Message from client: {message}"
    clientIP = f"Client IP Address: {address}"

    print(len(message))
    print(clientMsg)
    print(clientIP)

    UDPServerSocket.sendto(bytesToSend, address)
