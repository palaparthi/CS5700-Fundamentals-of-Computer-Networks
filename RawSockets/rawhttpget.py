import socket,sys
from urlparse import *
import random
from struct import *
import time
import array
import re

#packet variables
source_ip = ''
dest_ip=''
packet=''
#tcp header ports
tcp_source_port=random.randint(2000,64000)
tcp_dest_port=80

#global variables
current_congestion_wnd = 1
max_congestion_wnd = 1000
err =False
fin_data = ''
first_packet_flag = 0
f_flag = 'F'
http_200 = 'HTTP/1.1 200 OK'
http_301 = 'HTTP/1.1 301'
http_302 = 'HTTP/1.1 302'
http_404 = 'HTTP/1.1 404'
http_500 = 'HTTP/1.1 500'
http_501 = 'HTTP/1.1 501'
packet_last_recv_time = time.time()
min_3 = 180
min_1 = 60
urg_flg = "U"
ack_flg = "A"
push_flg = "P"
rst_flg = "R"
syn_flg = "S"
finish_flg = "F"
url_splitslash = ''

#initial handshake from the sender
def initial_handshake():
    global source_ip, dest_ip, tcp_source_port,tcp_dest_port
    packet = build_ip_header(source_ip, dest_ip, '') + build_tcp_header(source_ip, dest_ip, tcp_source_port, tcp_dest_port, 0, 0, 0, 1, 0, 0, '')
    send_socket.sendto(packet, (dest_ip,0))
    packet_sent_time = time.time()
    return packet_sent_time

#constructing ip header
def build_ip_header(source_ip, dest_ip, data):
    ip_hdr_len=5
    ip_version=4
    ip_tos=0
    ip_tot_len = 20 + len(data) #kernel will calculate the total length
    ip_id= random.randint(15000, 64000)  #Id of this packet
    ip_frag_offset = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_checksum = 0
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr=socket.inet_aton(dest_ip)
    ip_ihl_ver = (ip_version << 4) + ip_hdr_len
    ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_offset, ip_ttl, ip_proto,
                     ip_checksum, ip_saddr, ip_daddr)
    return ip_header

#constructing tcp header
def build_tcp_header(source_ip, dest_ip, tcp_source_port, tcp_dest_port, tcp_seq, tcp_ack_seq, tcp_fin,
                     tcp_syn, tcp_psh, tcp_ack, data):
    tcp_offset = 5 #4 bit field, size of tcp header, 5 * 4 = 20 bytes
    #flags
    tcp_rst = 0
    tcp_urg = 0
    tcp_window = socket.htons(5840) #maximum allowed window size
    tcp_checksum = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_offset << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

    #the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH', tcp_source_port, tcp_dest_port, tcp_seq, tcp_ack_seq, tcp_offset_res,
                      tcp_flags, tcp_window, tcp_checksum, tcp_urg_ptr)

    #pseudo header fields
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(data)

    psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length);
    psh = psh + tcp_header + data;
    tcp_check = calculate_checksum(psh)

    #make the tcp header again and fill the correct checksum - remember checksum is not in network byte order
    tcp_header = pack('!HHLLBBH', tcp_source_port, tcp_dest_port, tcp_seq, tcp_ack_seq, tcp_offset_res,
                      tcp_flags, tcp_window) + pack('H', tcp_check) + pack('!H', tcp_urg_ptr)
    return tcp_header

#calculating checksum
def calculate_checksum(data):
    sum = 0
    if(len(data) % 2 != 0):
        w=array.array('h', (data + '\0'))
    else:
        w=array.array('h' , data)
    for wd in w:
        wd = wd & 0xffff
        sum += wd
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)
    return ~sum & 0xffff

#receive response from the host
def second_handshake_recieve(initial_handshake_time):
    global dest_ip, tcp_source_port
    packet_last_sent_time = initial_handshake_time
    while(True):
        data = recieve_socket.recvfrom(65535)
        if(data):
            ip_packet = ip_unpacking(data)
            #comparing source ip of the receiving packet with destination ip address
            if(ip_packet[10] == dest_ip):
                tcp_packet = tcp_unpacking(data)
                #comparing source port of the receiving packet with destination port and vice versa
                if(tcp_packet[0] == 80 and tcp_packet[1] == tcp_source_port):
                    if(tcp_packet[5].find(ack_flg)!= -1 and tcp_packet[5].find(syn_flg)!= -1):
                        #increase the congestion window and updat the recieve timetime
                        increase_cwnd()
                        return tcp_packet
                elif time.time() - packet_last_sent_time > min_1 :
                    packet_last_sent_time = initial_handshake()
                elif time.time() - packet_last_recv_time > min_3:
                    print 'No response from the server'
                    sys.exit()

#incrementing the congestion window
def increase_cwnd():
    global current_congestion_wnd
    global packet_last_recv_time
    current_congestion_wnd = current_congestion_wnd +1
    packet_last_recv_time = time.time()
    return

#unpack ip header received from the host
def ip_unpacking(packet):
    packet = packet[0]
    ip_header = packet[0:20]
    head_ip = unpack("!BBHHHBBH4s4s", ip_header)
    ip_version = head_ip[0] >> 4
    ip_flags = head_ip[4] >> 13
    ip_offset = head_ip[4] & 0x1FFF
    ip_checksum = hex(head_ip[7])
    ip_source = socket.inet_ntoa(head_ip[8])
    ip_destination = socket.inet_ntoa(head_ip[9])
    ip_packet_data = packet[20:]
    #final data contains ip version, ip header, type of service, total length, id,flags, offset, time to live,
    final_data = [ip_version, ip_header, head_ip[1], head_ip[2], head_ip[3], ip_flags, ip_offset, head_ip[5],
                  head_ip[6], ip_checksum, ip_source, ip_destination, ip_packet_data]

    return final_data

#unpack tcp header received from the host
def tcp_unpacking(packet):
    packet = packet[0]
    packet = packet[20:]
    tcp_header_length = (ord (packet[12])>>4) * 4
    tcp_header =  unpack("!HHLLBBHHH", packet[:20])
    data_offset = tcp_header[4] >> 4
    flags=""
    for fl in {1, 2, 4, 8, 16, 32}:
        if tcp_header[5] & fl:
            if fl ==1:
                flags += finish_flg
            elif fl == 2:
                flags += syn_flg
            elif fl == 4:
                flags += rst_flg
            elif fl == 4:
                flags += rst_flg
            elif fl == 16:
                flags += ack_flg
            elif fl == 32:
                flags += urg_flg
    tcp_packet_data = packet[tcp_header_length:]
    tcp_checksum = hex(tcp_header[7])
    #final_data contains source port, destination port, sequence, ack, data offset, flags, window, checksum, urgent pointer, tcp packet data
    final_data = [tcp_header[0], tcp_header[1], tcp_header[2], tcp_header[3], data_offset, flags, tcp_header[6], tcp_checksum, tcp_header[8], tcp_packet_data]
    return final_data

#final handshake from the sender with syn and ack
def third_handshake(source_ip,dest_ip,tcp_source_port,tcp_dest_port,seq,ack):
    packet = build_ip_header(source_ip, dest_ip, '') + build_tcp_header(source_ip, dest_ip, tcp_source_port, tcp_dest_port, seq, ack, 0, 0, 0, 1, '')
    send_socket.sendto(packet, (dest_ip,0))
    packet_sent_time = time.time()
    return packet_sent_time

def get_http(url ,source_ip, dest_ip, tcp_source_pt, tcp_dest_pt, seq, ack):
    http_request = "GET "+url+" HTTP/1.0\nHost: "+dest_ip+"\nConnection: keep-alive\r\n\r\n"
    packet = build_ip_header(source_ip, dest_ip, '') + build_tcp_header(source_ip, dest_ip, tcp_source_pt, tcp_dest_pt, seq, ack, 0, 0, 1, 1, http_request) + http_request
    send_socket.sendto(packet, (dest_ip , 0))
    packet_last_sent_time = time.time()
    data = [len(packet), packet_last_sent_time, http_request]
    return data

#checking url scheme
def verify_scheme(parsed_url):
    #verify url scheme is 'http' and net location not empty
    if(not((parsed_url.scheme=="http") and (parsed_url.netloc!=''))):
        print "Error: enter correct URL\n"
        sys.exit()

#split the url
def url_split(url):
    parsed_url=urlparse(url)
    verify_scheme(parsed_url)
    url_splithttp = url.split('http://')
    url_splitslash= url_splithttp[1].split('/')
    count=0
    if url.endswith('/'):
        count=count+1
    if (len(url_splitslash)==1 or count==1):
        #if URL ends with slash or does not have any path then download index.html
        downloaded_filename='index.html'
    else:
        downloaded_filename=url_splitslash[len(url_splitslash) - 1]
    return url_splitslash, downloaded_filename

#fetching source and destination ip addresses
def def_ips():
    global source_ip, dest_ip
    #setting source and destination ip address
    dnssocket=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dest_servername=url_splitslash[0]
    dnssocket.connect((dest_servername,0))
    dest_ipaddr = socket.gethostbyname(dest_servername)
    #setting source ip address
    #getsockname() returns socket's own ip address
    source_ip = dnssocket.getsockname()[0]
    dest_ip = dest_ipaddr

#socket creation
def create_sockets():
    global send_socket,recieve_socket
    try:
        #create send socket with IPPROTO_RAW
        send_socket= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        #create receive socket with IPPROTO_TCP since kernel will not deliver any packets of RAW type
        recieve_socket=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error:
        print "Error in socket creation"
        sys.exit()

#sending packet
def http_recv(final_data, tcp_resp, src_ip, des_ip, tcp_src_port, tcp_des_port):
    final_data += tcp_resp[9]
    tcp_seq = tcp_resp[3]
    tcp_ack_seq = len(tcp_resp[9]) + tcp_resp[2]
    tcp_fin = 0
    tcp_syn = 0
    tcp_psh = 0
    tcp_ack = 1
    pack = build_ip_header(src_ip, des_ip,'') + build_tcp_header(src_ip, des_ip, tcp_src_port, tcp_des_port, tcp_seq,
                                  tcp_ack_seq, tcp_fin, tcp_syn, tcp_psh, tcp_ack, '') + ''
    pack_last_sent = pack
    send_socket.sendto(pack, (des_ip, 0))
    seq_recv = tcp_resp[2] + len(tcp_resp[9])
    ack_recv = tcp_resp[3]
    return final_data, pack, ack_recv, pack_last_sent, seq_recv

#verifying http status codes other than 200 OK
def verify_http_status_code(status_code):
    return (http_301 in status_code or http_302 in status_code or http_404 in status_code
                       or http_500 in status_code or http_501 in status_code)

#writing data to a file
def write(data, file_name):
    data = data.split('\r\n\r\n')[1]
    f = open(file_name, 'w')
    f.write(data)
    f.close()

#checking the argument length
arg_len = len(sys.argv)
if arg_len != 2:
    print "Error: Invalid arguments"
    sys.exit()
else:
    create_sockets()
    filename=''
    url=sys.argv[1]
    url_splitslash, filename = url_split(url)
    def_ips()

    #Handshakes for setting the connection
    initial_handshake_time = initial_handshake()
    second_handshake = second_handshake_recieve(initial_handshake_time)
    seq = second_handshake[3]
    ack = second_handshake[2] +1
    packet_last_sent_time = third_handshake(source_ip,dest_ip,tcp_source_port,tcp_dest_port,seq,ack)

    #http get
    http_request_data = get_http(url, source_ip, dest_ip, tcp_source_port, tcp_dest_port, seq, ack)
    packet_last_sent_time = http_request_data[1]
    seq_rec = ack
    ack_rec = seq + len(http_request_data[2])

    #recieve http
    while(True):
        #Receive data from the client
        res = recieve_socket.recvfrom(65535)
        if(res):
            ip_res = ip_unpacking(res)
            #source ip of incoming packet should be same as destination ip and destination ip of the incoming packet
            #should be equal to source ip
            if( dest_ip == ip_res[10] and source_ip == ip_res[11]):
                tcp_res = tcp_unpacking(res)
                #conditions for the first tcp packet
                if (first_packet_flag == 0 and tcp_dest_port == tcp_res[0]  and tcp_source_port == tcp_res[1]
                    and  seq_rec == tcp_res[2] and  ack_rec == tcp_res[3] and f_flag not in tcp_res[5]):
                    if (http_200 in tcp_res[9]):
                        current_congestion_wnd +=1
                        first_packet_flag = 1
                        packet_last_recv_time = time.time()
                        fin_data, packet, ack_rec, packet_last_sent, seq_rec = http_recv(fin_data, tcp_res, source_ip, dest_ip, tcp_source_port, tcp_dest_port)
                        packet_last_sent_time = time.time()
                    if(verify_http_status_code(tcp_res[9])):
                        err =True
                        print "Error: incorrect status code recieved, expected status code 200"
                        break
                #conditions for packets other than first packet
                if (first_packet_flag == 1 and tcp_source_port == tcp_res[1] and tcp_dest_port == tcp_res[0]
                    and ack_rec == tcp_res[3] and seq_rec == tcp_res[2] and f_flag not in tcp_res[5]):
                    if (http_200 in tcp_res[9]):
                        packet_last_recv_time = time.time()
                        if(current_congestion_wnd + 1> max_congestion_wnd):
                            current_congestion_wnd =1
                        else:
                            current_congestion_wnd +=1
                        fin_data += tcp_res[9]
                        tcp_seq = tcp_res[3]
                        tcp_ack_seq = len(tcp_res[9]) + tcp_res[2]
                        tcp_fin = 0
                        tcp_syn = 0
                        tcp_psh = 0
                        tcp_ack = 1
                        packet = build_ip_header(source_ip, dest_ip,'') +build_tcp_header(source_ip, dest_ip, tcp_source_port, tcp_dest_port, tcp_seq,
                                                      tcp_ack_seq, tcp_fin, tcp_syn, tcp_psh, tcp_ack, '') + ''
                        send_socket.sendto(packet, (dest_ip, 0))
                        packet_last_sent = packet
                        packet_last_sent_time = time.time()
                        seq_rec = tcp_res[2] + len(tcp_res[9])
                        ack_rec = tcp_res[3]
                    if(verify_http_status_code(tcp_res[9])):
                        err =True
                        print "Error: incorrect status code recieved, expected status code 200"
                        break
                    elif (tcp_res[0] == tcp_dest_port and tcp_res[1] == tcp_source_port and tcp_res[2] == seq_rec
                          and tcp_res[3] == ack_rec):
                        if(current_congestion_wnd + 1 > max_congestion_wnd):
                            current_congestion_wnd =1
                        else:
                            current_congestion_wnd +=1
                        packet_last_recv_time = time.time()
                        fin_data += tcp_res[9]
                        tcp_seq = tcp_res[3]
                        tcp_ack_seq = len(tcp_res[9]) + tcp_res[2]
                        tcp_fin = 0
                        tcp_syn = 0
                        tcp_psh = 0
                        tcp_ack = 1
                        packet = build_ip_header(source_ip, dest_ip,'') +build_tcp_header(source_ip, dest_ip, tcp_source_port, tcp_dest_port, tcp_seq,
                                                      tcp_ack_seq, tcp_fin, tcp_syn, tcp_psh, tcp_ack, '') + ''
                        send_socket.sendto(packet, (dest_ip, 0))
                        packet_last_sent = packet
                        packet_last_sent_time = time.time()
                        ack_rec = tcp_res[3]
                        seq_rec = tcp_res[2] + len(tcp_res[9])
                #timeout check
                if(first_packet_flag == 1 and time.time() - packet_last_recv_time > min_1):
                    send_socket.sendto(packet_last_sent, (dest_ip, 0))
                    packet_last_sent_time = time.time()
                    current_congestion_wnd = 1
                    continue
                #timeout check for first tcp packet
                if(first_packet_flag == 0 and time.time() - packet_last_recv_time > min_1):
                    get_http(url, source_ip, dest_ip, tcp_source_port, tcp_dest_port, seq, ack)
                    packet_last_sent_time = time.time()
                    current_congestion_wnd = 1
                    continue
                 #check F bit which indicates last packet
                if (first_packet_flag == 1 and  tcp_source_port == tcp_res[1] and tcp_dest_port == tcp_res[0]
                    and  ack_rec == tcp_res[3] and seq_rec == tcp_res[2] and f_flag in tcp_res[5]):
                    if('P' in tcp_res[5]):
                        fin_data += tcp_res[9]
                    tcp_seq = tcp_res[3]
                    tcp_ack_seq = tcp_res[2]+1
                    tcp_fin = 1
                    tcp_syn = 0
                    tcp_psh = 0
                    tcp_ack = 1
                    packet = build_ip_header(source_ip, dest_ip, '') +build_tcp_header(source_ip, dest_ip, tcp_source_port, tcp_dest_port, tcp_seq,
                                                  tcp_ack_seq, tcp_fin, tcp_syn, tcp_psh, tcp_ack, '') + ''
                    packet_last_sent = packet
                    packet_last_sent_time = time.time()
                    send_socket.sendto(packet, (dest_ip, 0))
                    break
                if (time.time() - packet_last_recv_time > min_3):
                    print "Error: Connection Failed"
                    sys.exit()
    if(err == False):
        write(fin_data, filename)
    send_socket.close()
    recieve_socket.close()


























































