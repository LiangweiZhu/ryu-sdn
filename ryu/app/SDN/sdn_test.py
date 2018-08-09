import requests
import json

# 1. install requests:
# 	git clone git://github.com/kennethreitz/requests.git
#	cd requests
#	pip install .
#
# 2. setup with REST
#	ryu-manager ofctl_rest.py rest_topology.py sdn.py


mac_to_ip = {}
routes = ['s1-s2-s5','s1-s3-s5','s1-s4-s5']


def sdn_test(src_ip, dst_ip):
    _get_ip()

    dst_mac = mac_to_ip[dst_ip]
    src_mac = mac_to_ip[src_ip]


    sides_temp = dst_ip.encode('gbk')
    sides = sides_temp.split('.')[-1]

    print(sides)
    r = requests.get('http://localhost:8080/stats/flow/1')
    text = r.text
    flows = json.loads(text)
    if int(sides) >= 4:
        for flow in flows['1']:
            dl_dst = flow['match'].setdefault('dl_dst')
            if dl_dst and (dl_dst == dst_mac):
                actions = flow['actions']
                out_port = actions[0].split(':')[1]
                route_printer(out_port)

    else:
        print(dst_mac)
        for flow in flows['1']:
            # print(flow)
            dl_dst = flow['match'].setdefault('dl_dst')
            in_port = flow['match'].setdefault('in_port')
            # print('dl_dst='+dl_dst+' in_port='+str(in_port))
            if (in_port >= 4) and (dl_dst == dst_mac):
                route_printer(str(in_port))

def _get_ip():
    r = requests.get('http://localhost:8080/v1.0/topology/hosts')
    text = r.text
    hosts = json.loads(text)
    # print(hosts)
    for host in hosts:
        ipv4 = host.get('ipv4')
        if ipv4:
            mac = host.get('mac')
            # print('ipv4= '+ipv4[0]+' mac= '+mac)
            mac_to_ip.setdefault(ipv4[0],mac)

def route_printer(out_port):
    if out_port == '4':
       print('\r\nYour Route is ' + routes[0])
    if out_port == '5':
       print('\r\nYour Route is ' + routes[1])
    if out_port == '6':
       print('\r\nYour Route is ' + routes[2])

if __name__ == '__main__':
    src_ip = 'a'
    while src_ip != 'q':
        src_ip = raw_input("\r\ninput the source ip, input 'q' to quit:")
        if src_ip != 'q':
            dst_ip = raw_input("input the dst ip, input 'q' to quit:")
            if dst_ip != 'q':
                sdn_test(src_ip, dst_ip)
