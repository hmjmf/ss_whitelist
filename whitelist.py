# coding:utf-8

import socket
import os
os.system("apt install  -y python-pip")
os.system("pip install python-iptables")
import sys
import iptc
from multiprocessing import Process

def responce(client_socket, response_body):
    response_start_line = "HTTP/1.1 200 OK\r\n"
    response_headers = "Server: My server\r\n"
    response_body = "<h1>{}</h1>".format(response_body)
    response = response_start_line + response_headers + "\r\n" + response_body
    client_socket.send(bytes(response))
    client_socket.close()

def handle_client(client_socket, addr, ss_port, passwd):
    request_data = client_socket.recv(1024)
    print("request data:", request_data)

    if passwd not in request_data:
        responce(client_socket, "SB see your mother?") 
        return

    table = iptc.Table(iptc.Table.FILTER)
    if(len(table) > 100):
        os.system("iptables -F")
        os.system("iptables -I INPUT -p tcp --dport {} -j DROP".format(ss_port))
    for chain in table.chains:
        if chain.name == "INPUT":
            for rule in chain.rules:
                if rule.src.split("/")[0] == addr[0] and rule.protocol == "tcp" and ss_port in  [int(match.dport) for match in rule.matches] and rule.target.name == "ACCEPT":
                    responce(client_socket, "fuck u, u has been in whitelist, do not fuck touch again. {}".format(addr[0]))
                    return

    cmd = "iptables -I INPUT -s {} -p tcp --dport {} -j ACCEPT".format(addr[0], ss_port)
    ret = os.system(cmd)
    if ret == 0:
        responce(client_socket, "success {}".format(addr[0]))
    else:
        responce(client_socket, "err ret {}".format(ret))
    return
    


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("python whitelist.py <http_port> <ss_port>")
        exit(-1)
    http_port = int(sys.argv[1])
    ss_port = int(sys.argv[2])
    passwd = sys.argv[3]
    print("http port {}".format(http_port))
    print("ss port {}".format(ss_port))
    print("passwd {}".format(passwd))

    os.system("iptables -F")
    cmd = "iptables -I INPUT -p tcp --dport {} -j DROP".format(ss_port)
    ret = os.system(cmd)
    print("cmd {}, ret {}".format(cmd, ret))
    if(ret != 0):
        print("error may not root")
        exit(-1)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("", http_port))
    server_socket.listen(128)

    while True:
        client_socket, client_address = server_socket.accept()
        print("[%s, %s]用户连接上了" % client_address)
        handle_client_process = Process(target=handle_client, args=(client_socket, client_address, ss_port, passwd))
        handle_client_process.start()
        client_socket.close()
