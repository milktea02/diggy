import socket
import sys
import random

# diggy takes a DNS address, and a qname
# RFC 1034, RFC 1035
# example of standard query: https://datatracker.ietf.org/doc/html/rfc1034#section-6.2

TYPE_MAPPING = {1:"A", 2:"NS", 5:"CNAME", 6:"SOA"}
CLASS_MAPPING = {1:"IN", 2:"CS", 3:"CH", 4:"HS"}

'''
Typical message format:

    HEADER
    QUESTION
    ANSWER
    AUTHORITY
    ADDITIONAL
'''

'''
16 bit width

| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 0 | 1 | 2 | 3 | 4 | 5 |
|  ID                                                           |
|QR | Opcode        |AA |TC |RD |RA |Z          |RCODE          |
|QDCOUNT                                                        |
|ANCOUNT                                                        |
|NSCOUNT                                                        |
|ARCOUNT                                                        |

ID - 16 bit identifier
QR - 1 bit -> query (0) or response (1)
OPcode - 4 bit field for kind of query; standard (0), inverse (1), status (2)
AA - Authoritative answer
TC - TrunCation - was this message truncated?
RD - recursion desired
RA - recursion available; set or cleared in response; wehether recursive query is supported
Z  - reserved for future use
RCODE - Response code - 4 bit; no error (0), format error (1), server failure (2), name error (3), not implemented (4), refused (5)
QDCOUNT - unsigned 16 bit; number of question entries
ANCOUNT - unsigned 16 bit; number of resource records
NSCOUNT - unsigned 16 bit; number of name server resources records in authority section
ARCOUNT - unsigned 16 bit; number of resource records in additional records section
'''

def write_header():
    message_id = random.getrandbits(16).to_bytes(2, byteorder='big')
    print(f"Message ID: { int.from_bytes(message_id, 'big')}")
    qr = 0
    opcode = 0
    aa = 0
    tc = 0
    rd = 0 
    ra = 0
    z = 0
    rcode = 0
    flags = int.to_bytes(0, 2, 'big')
    # only support 1 qname
    qd_count = int.to_bytes(1, 2, 'big') 
    an_count = int.to_bytes(0, 2, 'big') 
    ns_count = int.to_bytes(0, 2, 'big') 
    ar_count = int.to_bytes(0, 2, 'big') 

    first_octect = ''.join([str(l) for l in [qr, 0, 0, 0, opcode, aa, tc, rd]])
    first_octect = bytearray([int(first_octect, 2)])
    second_octect = ''.join([str(l) for l in [ra, 0, 0, 0, z, z, z, rcode]])
    second_octect = bytearray([int(second_octect, 2)])
   
    return message_id + flags + qd_count + an_count + ns_count + ar_count 

'''
| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 0 | 1 | 2 | 3 | 4 | 5 |
| QNAME                                                         |
/                                                               /
/                                                               /
| QTYPE                                                         |
| QCLASS                                                        |

QNAME  - domain name; sequence of labels where each label is length of the octect followed by the number of octects; terminates with the zero length octect for the null label of the root
QTYPE  - type of query
QCLASS - class of query
'''
def write_labels(qname):
    labels = qname.split('.')
    labels_ba = []
    for label in labels:
        labels_ba.append(len(label))
        for c in label:
            labels_ba.append(ord(c))
    # add terminating byte
    labels_ba.append(0)
    return bytearray(labels_ba) 

def write_question_section(qname):
    labels = write_labels(qname)
    qtype = 1
    qclass = 1
    return labels + int.to_bytes(qtype, 2, 'big') + int.to_bytes(qclass, 2, 'big') 

def write_message(qname):
    header = write_header()
    question = write_question_section(qname)
    return header + question 

'''
Resource Record Format

// NAME      // -- variable, could be compressed
| TYPE        | -- 16 bits -- usually A
| CLASS       | -- 16 bits -- usually IN
| TTL         | -- 32 bit unsigned integer
| RD LENGTH   | -- 16 bits
// RDATA      // -- variable, for A record data 4 octect ARPA Internet Address
'''

def read_rdata(msg, start_index, rr_type, rd_length):
    if rr_type == 1: # A Record
        addresses = []
        # this is the most usual one
        num_addresses = int(rd_length/4)
        for i in range(num_addresses):
            address = "{}.{}.{}.{}".format(msg[start_index], msg[start_index + 1], msg[start_index + 2], msg[start_index + 3])
            start_index += 4
            addresses.append(address)
        return start_index, addresses 
    if rr_type == 6: # SOA
        # according to rfc1035; SOA records cause no additional section processing
        return start_index, [] 
    return start_index, [] 


def read_labels(msg, start_index):
    label = ""
    while(True):
        end = False
        reading_frame = msg[start_index]
        ## check for compression
        if ((reading_frame >> 6) & 1) and ((reading_frame >> 6) & 2):
            #print(reading_frame, "---->", format(reading_frame, '08b'))
            #print("Compresion")
            start_index += 1
            go_to_index = msg[start_index]
            while(True):
                length = msg[go_to_index]
                if length == 0:
                    end = True
                    break;
                for i in range(length):
                    label += (chr(msg[go_to_index + 1 + i]))
                label += '.'
                go_to_index = go_to_index + 1 + length
            break
        if end:
            break
        if reading_frame == 0:
            break
        start_index += 1

    return start_index + 1, label

def read_question_section(msg, qd_count=1):
    # we know that header is 12 bytes long
    start_index, labels = read_labels(msg, 12)
    qtype = int.from_bytes(msg[start_index: start_index + 2], 'big') 
    qclass = int.from_bytes(msg[start_index + 2: start_index + 4], 'big') 
    print(f"QTYPE: {qtype}")
    print(f"QCLASS: {qclass}")
    return start_index + 4 

def read_resource_record(msg, start_index):
    start_index, label = read_labels(msg, start_index)
    rr_type = int.from_bytes(msg[start_index: start_index + 2], 'big') 
    rr_class = int.from_bytes(msg[start_index + 2: start_index + 4], 'big') 
    ttl = int.from_bytes(msg[start_index + 4: start_index + 8], 'big') 
    rd_length = int.from_bytes(msg[start_index + 8: start_index + 10], 'big') 
    print(f"RR TYPE: {rr_type}")
    print(f"RR CLASS: {rr_class}")
    print(f"TTL: {ttl}")
    print(f"RD LENGTH: {rd_length}")
    return start_index + 10, label, rr_type, rr_class, ttl, rd_length

def read_header(msg):
    header_id=flags=qd_count=an_count=ns_count=ar_count = 0
    header_id = int.from_bytes(msg[0:2], 'big')
    print(f"Answer Message ID: { header_id }")
    # first octect of flags
    flags = msg[2]
    rd      = flags & 1
    tc      = (flags >> 1) & 1
    aa      = (flags >> 2) & 1
    op_code = (flags >> 3) & 7
    qr      = (flags >> 7) & 1
    # second octect of flags
    flags = msg[3]
    rcode = flags & 7 
    ra    = (flags >> 7) & 1

    print(f"QR (Q = 0; R = 1): {qr}")
    print(f"OPCODE: {op_code}")
    print(f"AA: {aa}")
    print(f"TC: {tc}")
    print(f"RD: {rd}")
    print(f"RA: {ra}")
    print(f"RCODE: {rcode}")

    qd_count = int.from_bytes(msg[4:6], 'big')
    an_count = int.from_bytes(msg[6:8], 'big')
    ns_count = int.from_bytes(msg[8:10], 'big')
    ar_count = int.from_bytes(msg[10:12], 'big')
    print(f"QD COUNT: {qd_count}")
    print(f"AN COUNT: {an_count}")
    print(f"NS COUNT: {ns_count}")
    print(f"AR COUNT: {ar_count}")

    return qd_count, an_count, ns_count, ar_count 

def read_message(msg):
    # get the counts, and any errors
    qd_count, an_count, ns_count, ar_count = read_header(msg)
    start_index = 12
    if qd_count > 0:
        print(";; QUESTION SECTION:")
        start_index = read_question_section(msg)
    if (an_count + ns_count + ar_count) == 0:
        print("Didn't recieve any answers, might need to do a recursive lookup?")
        return None
    if an_count > 0:
        print(";; ANSWER SECTION:")
        start_index, label, rr_type, rr_class, ttl, rd_length = read_resource_record(msg, start_index)
        start_index, rdatas = read_rdata(msg, start_index, rr_type, rd_length)

        for rdata in rdatas:
            print(f"{label}\t{ttl}\t{CLASS_MAPPING.get(rr_class, 'unknown')}\t{TYPE_MAPPING.get(rr_type, 'unknown')}\t{rdata}")
    if ns_count > 0:
        print("Given a NS RDATA; check the additional records section")
        return None
           
    return None

def send_recv_message(sock, msg, dns_server, buffsize):
    resp = sock.sendto(msg,(dns_server, 53))
    print(f"Message bytes: {len(msg)}; sent bytes: {resp}")
    answer = sock.recv(buffsize)
    print(f"Recieved bytes: {len(answer)}")
    return answer 

if __name__ == "__main__":
    print("Welcome to diggy!")

    args = sys.argv
    if len(args) < 3:
        print(f"Usage {args[0]} [dns_server] [qname]")
        exit()

    dns_server = args[1]
    qname = args[2]
    print(f"Using DNS Server: {dns_server}")
    print(f"Querying for: {qname}")

    msg = write_message(qname)
    diggy_address = "127.0.0.1"
    diggy_port = 30001
    diggy = socket.socket(family = socket.AF_INET, type = socket.SOCK_DGRAM)
    answer = send_recv_message(diggy, msg, dns_server, 2048)
    read_message(answer)
