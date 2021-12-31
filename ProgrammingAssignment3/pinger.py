import os
import sys
import struct
import time
import select
import socket
import binascii

ICMP_ECHO_REQUEST = 8

def checksum(str):
    csum = 0
    countTo = (len(str) / 2) * 2

    count = 0
    while count < countTo:
        thisVal = str[count+1] * 256 + str[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(str):
        csum = csum + str(len(str) - 1)
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def receiveOnePing(mySocket, ID, timeout, destAddr):
    global rtt_min, rtt_max, rtt_sum, rtt_cnt
    timeLeft = float(timeout)
    while 1:
        startedSelect = time.time()
        #print(mySocket)
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        # print(howLongInSelect)
        # print(mySocket)
        if whatReady[0] == []: # Timeout
            return "Request timed out."
            
        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)

        #Fill in start
        #Fetch the ICMP header from the IP packet
        if addr[0] == destAddr: # Check if the destAddr is the same
            # ICMP Data stored after 160-bit (20-bytes) and before 224-bit (192+16+16 bits) (28 bytes)
            # type (8), code (8), checksum (16), id (16), sequence (16)
            icmp_begin_index = 160 // 8
            icmp_last_index = (192 + 16 + 16) // 8
            # Parse header (format is in sendOnePing())
            header = recPacket[icmp_begin_index:icmp_last_index]
            myType, myCode, myChecksum, myID, mySeq = struct.unpack("bbHHh", header)
            # Sent Time data packed after ICMP header (packed with code size("d") = 8
            myData = struct.unpack("d", recPacket[icmp_last_index:icmp_last_index+8])[0]
            myTimeDiff = timeReceived - myData
            myTimeDiff *= 1000 # Convert to ms
            
            # RTT calculations
            rtt_sum += myTimeDiff # For avg. RTT
            if myTimeDiff < rtt_min: # For min. RTT
                rtt_min = myTimeDiff
            elif myTimeDiff > rtt_max: # For max. RTT
                rtt_max = myTimeDiff
            rtt_cnt += 1
            # print(f"{myType}, {myCode}, {myChecksum}, {myID}, {mySeq}, myData: {myData}, startTime: {timeReceived}, {myTimeDiff}")
            
            #Fill in end

            # Send Echo Reply
            # Type and code must be 0
            header = struct.pack("bbHHh", 0, 0, myChecksum, myID, mySeq)
            myData = struct.pack("d", myData)
            packet = header + myData
            #print(type(packet))
            mySocket.sendto(packet, (destAddr, 1))

            return ("Pinging {}: Checksum: {}, ID: {}, Seq: {}, Time: {:.4f} ms".format(destAddr, myChecksum, myID, mySeq, myTimeDiff))
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."

def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    
    myChecksum = 0
    # Make a dummy header with a 0 checksum.
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, rtt_cnt + 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        myChecksum = socket.htons(myChecksum) & 0xffff
        #Convert 16-bit integers from host to network byte order.
    else:
        myChecksum = socket.htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, rtt_cnt + 1)
    packet = header + data

    # Sends packet
    mySocket.sendto(packet, (destAddr, 1)) # AF_INET address must be tuple, not str
    #Both LISTS and TUPLES consist of a number of objects
    #which can be referenced by their position number within the object

def doOnePing(destAddr, timeout):
    icmp = socket.getprotobyname("icmp")
    #SOCK_RAW is a powerful socket type. For more details see: http://sock-raw.org/papers/sock_raw
    
    #Fill in start
    
    #Create Socket here
    try:
        mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        #Fill in end
        mySocket.settimeout(1)
        mySocket.connect((destAddr, 1))
        myID = os.getpid() & 0xFFFF #Return the current process i
        sendOnePing(mySocket, destAddr, myID)
        delay = receiveOnePing(mySocket, myID, timeout, destAddr)

        mySocket.close()
        return delay
    except socket.error as e:
        print("Can't create socket: " + e)
        exit(-1)

def ping(host, timeout=1):
    global rtt_min, rtt_max, rtt_sum, rtt_cnt
    rtt_min = float('+inf')
    rtt_max = float('-inf')
    rtt_sum = 0
    rtt_cnt = 0
    cnt = 0
    #timeout=1 means: If one second goes by without a reply from the server,
    #the client assumes that either the client's ping or the server's pong is lost
    dest = socket.gethostbyname(host)
    print ("Pinging " + dest + " using Python:")
    #Send ping requests to a server separated by approximately one second
    try:
        while True:
            cnt += 1
            print(doOnePing(dest, timeout))
            time.sleep(1)
    except KeyboardInterrupt:
        if cnt != 0:
            print('\n--- {} ping statistics ---'.format(host))
            print('{} packets transmitted, {} packets received, {:.1f}% packet loss'.format(cnt, rtt_cnt, 100.0 - rtt_cnt * 100.0 / cnt))
            if rtt_cnt != 0:
                print('round-trip min/avg/max {:.3f}/{:.3f}/{:.3f} ms'.format(rtt_min, rtt_sum / rtt_cnt, rtt_max))


ping("" + sys.argv[1])
# ping("127.0.0.1")
