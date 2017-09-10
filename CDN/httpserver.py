#!/usr/bin/python
import socket
import sys
import os
from thread import *
import urllib

inp = sys.argv
#taking origin and port from commandline
origin = sys.argv[4]
port = int(sys.argv[2])
CACHE_LIMIT = 79000
curr_cache_size = 0
cache_page = []
cache_hits = []

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
print "socket created"

try:
    sock.bind(('',port))
except socket.error as msg:
    print 'bind failed',msg
sock.listen(10)

class customHttp:
    def __init__(self):
        start_new_thread(customHttp.multiplethreads, (self,conn,))
    def multiplethreads(self,conn):

        while True:
            data = conn.recv(2048)
            length = len(data)
            customHttp.get(self,data)
            if(data[length-1]=='\n'):
                break

        conn.close()

    #lru algorithm used for cache management
    def free_memory_lru(self,memory_req):
        mem_cleaned=0
        while mem_cleaned<memory_req:
            global curr_cache_size
            min_hits_file_index=cache_hits.index(min(cache_hits))
            file_to_be_removed=cache_page[min_hits_file_index]
            file_space=os.stat(file_to_be_removed).st_size
            cache_hits.pop(min_hits_file_index)
            cache_page.pop(min_hits_file_index)
            os.remove(file_to_be_removed)
            mem_cleaned+=file_space
            curr_cache_size+=file_space

    #fetching the required file
    def get(self,data):
        global curr_cache_size
        file_path = data.split(' ', 1)[1].split(' ', 1)[0]
        cache_dir = os.path.dirname(os.path.realpath(__file__))
        file_dir = cache_dir + file_path
        if file_dir not in cache_page:
            try:
                file_tmp = file_path.rsplit('/', 1)
                url = "http://"+origin+":"+str(port)+file_path
                value = urllib.urlopen(url).read()
                if(len(value)==0):
                    conn.sendall('HTTP/1.0 404 not found')
                else:
                    conn.sendall('HTTP/1.0 200 OK\n\n'+value)
                if curr_cache_size + sys.getsizeof(value) <= CACHE_LIMIT:
                    cache_page.append(file_dir)
                    file_tmp = file_path.rsplit('/',1)
                    file_name=file_tmp[1]
                    if (len(file_tmp[0])!=0 and not os.path.exists(file_tmp[0][1:])):
                        os.makedirs(file_tmp[0][1:])
                        f=open(cache_dir+file_tmp[0]+"/"+file_name,'w')
                        f.write(value)
                        f.close()
                    elif len(file_tmp[0])==0:
                        f = open(cache_dir+"/"+file_name, 'w')
                        f.write(value)
                        f.close()
                    else:
                        f = open(cache_dir + file_tmp[0] + "/"+file_name, 'w')
                        f.write(value)
                        f.close()
                    cache_hits.insert(cache_page.index(file_dir),1)
                    curr_cache_size+=sys.getsizeof(value)
                else:
                    available_free_mem=CACHE_LIMIT-curr_cache_size
                    memory_to_be_freed=sys.getsizeof(value)-available_free_mem
                    customHttp.free_memory_lru(self,memory_to_be_freed)
                    cache_page.append(file_dir)
                    file_tmp = file_path.rsplit('/', 1)
                    file_name = file_tmp[1]
                    if (len(file_tmp[0])!=0 and not os.path.exists(file_tmp[0][1:])):
                        os.makedirs(file_tmp[0][1:])
                        f=open(cache_dir+file_tmp[0]+"/"+file_name,'w')
                        f.write(value)
                        f.close()
                    elif len(file_tmp[0])==0:
                        f = open(cache_dir+"/"+file_name, 'w')
                        f.write(value)
                        f.close()
                    else:
                        f = open(cache_dir + file_tmp[0] + "/"+file_name, 'w')
                        f.write(value)
                        f.close()
                    cache_hits.insert(cache_page.index(file_dir),1)
                    curr_cache_size+=sys.getsizeof(value)
            except Exception as e:
                print 'error.. ', e
        else:
            f=open(file_dir,'r')
            data_to_be_sent=f.read()
            conn.sendall('HTTP/1.0 200 OK \n\n'+data_to_be_sent)
            hits=cache_hits[cache_page.index(file_dir)]
            hits+=1
            cache_hits[cache_page.index(file_dir)]=hits


while True:
  conn, addr = sock.accept()
  start = customHttp()