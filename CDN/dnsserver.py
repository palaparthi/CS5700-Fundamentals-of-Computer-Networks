#!/usr/bin/python
import struct,socket,sys,urllib2,urllib,requests,time
from thread import *

class Location():
    def __init__(self):
        self.location =  {"52.90.80.45": "39.0481,-77.4728",
                          "54.183.23.203": "39.8496,-121.6061",
                          "54.70.111.57": "45.8696,-119.6880",
                          "52.215.87.82": "53.3389,-6.2595",
                          "52.28.249.79": "50.1167,8.6833",
                          "54.169.10.54": "1.2855,103.8565",
                          "52.62.198.57": "-33.8612,151.1982",
                          "52.192.64.163": "35.6427,139.7677",
                          "54.233.152.60": "-23.5733,-46.6417"}
        self.clientip=None
        self.reponsetime={"52.90.80.45": 1000,
                          "54.183.23.203": 1000,
                          "54.70.111.57": 1000,
                          "52.215.87.82": 1000,
                          "52.28.249.79": 1000,
                          "54.169.10.54": 1000,
                          "52.62.198.57": 1000,
                          "52.192.64.163": 1000,
                          "54.233.152.60": 1000
                          }
        #fetching response times for the ec2 instances
        for ip_adr in self.reponsetime:
            start_new_thread(Location.get_response, (self, ip_adr))

    #fetching response time for the given ip address
    def get_response(self,ip_adr):
        global port
        restime=0
        while True:
            try:
                url='http://'+ip_adr+':'+str(port)
                data=urllib.urlencode({'client_ip':self.clientip})
                st=time.clock()
                request=urllib2.Request(url,data)
                response=urllib2.urlopen(request)
                restime = time.clock()
                self.reponsetime[ip_adr]=restime
            except:
                pass
            time.sleep(1)

    #fetch ip address with minimum response time
    def fetch_ip(self,client_add):
        ip_add = None
        min_resp_time=float('inf')
        for add in self.reponsetime:
            if self.reponsetime[add]<min_resp_time:
                min_resp_time=self.reponsetime[add]
                ip_add=add
        return ip_add

    #fetching ip address close to client's geo location
    def fetch_ip_addr_from_location(self,client_add):
        loc_obj=requests.get('http://ipinfo.io/'+client_add)
        location=str(loc_obj.text.split("\"loc\": ")[1].split('\",')[0][1:])
        ip_add = None
        min_distance = float('inf')
        for add in self.location:
            distance=self.calc_distance(location,self.location[add])
            if min_distance<distance:
                min_distance=distance
                ip_add=add
        return ip_add

    #calculating distance between two geo locations
    def calc_distance(self,loc_origin,loc_dest):
        origin=loc_origin.split(',')
        dest=loc_dest.split(',')
        return (self.square(origin[0]-dest[0]))+(self.square(origin[1]-dest[1]))

    #calcualating square of the given argument
    def square(self,arg1):
        return arg1*arg1

    #fetching ip address from the list of ec2 instances for the client
    def fetch_ip_adr(self,client_adr):
        if client_adr!=self.clientip:
            self.clientip=client_adr
            try:
                ip_add=self.fetch_ip_addr_from_location(client_adr)
            except:
                ip_add=self.location.keys()[0]
        else:
            ip_add=self.fetch_ip(client_adr)
        return ip_add


class CustomDns():
    global loc
    def __init__(self,dnsrequest,client_addr,client_port):
        start_new_thread(CustomDns.dns_pack, (self,dnsrequest, client_addr, client_port))

    #forming the message to be sent
    def dns_pack(self,message,client_ip,client_port):
        t_id = message[:2]
        flags = struct.pack('!H', 16*16*16*8 )  # 0b1000000110000000 #0x8000
        qdcount = struct.pack('!H', 1)  # question count
        ancount = struct.pack('!H', 1)  # answer count
        nscount = struct.pack('!H', 0)  # No of resource records in authority section
        arcount = struct.pack('!H', 0)  # No of resource records in additional section
        # End of header

        question = message[12:]
        ans_name = struct.pack('!H', 0xc00c)
        ans_type = struct.pack('!H', 1)
        ans_class = struct.pack('!H', 1)
        ttl = struct.pack('!I', 70)
        resource_data_length = struct.pack('!H', 4)

        ip1=loc.fetch_ip_adr(client_ip)
        ip = socket.inet_aton(ip1)
        answer = t_id + flags + qdcount + ancount + nscount + arcount + question + ans_name + ans_type + ans_class + ttl + \
                 resource_data_length + ip
        sock.sendto(answer, (client_ip,client_port))

if __name__ == "__main__":
    global sock
    #taking name and port from the commandline
    name = sys.argv[4]
    port = int(sys.argv[2])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('',port))
    while True:
        dnsrequest, client_details = sock.recvfrom(4096)
        loc=Location()
        st=CustomDns(dnsrequest,client_details[0],client_details[1])

