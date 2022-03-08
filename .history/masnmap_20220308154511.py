#!/usr/bin/env python3
# -*- coding:utf-8 -*-
###
# #      File: masnmap.py
# #      Project: Finger
# #      Created Date: Tue Mar 08 2022
# #      Author: Ryan
# #      mail: ryaninf@outlook.com
# #      github: https://github.com/ryanInf
# #      Last Modified: 
# #      Modified By: 
# #------------------------------------------
# #      Copyright (c) 2022  
# #------------------------------------------
# #
### source: https://github.com/starnightcyber/masnmap/blob/main/masnmap.py


import nmap
import datetime
import json
from queue import Queue
from multiprocessing import Pool
import os
import Finger
from config.data import Urls,Save


ip_file = 'ips.txt'
# masscan_exe = '/usr/local/bin/masscan'
masscan_exe = '/usr/bin/masscan'
masscan_rate = 2000
masscan_file = 'masscan.json'
task_queue = Queue()
result_queue = Queue()
process_num = 50
total_ports = 0
services_info = []


def run_masscan():
    command = 'sudo {} -iL {} -p 1-65535 -oJ {} --rate {}'.format(masscan_exe, ip_file, masscan_file, masscan_rate)
    msg = 'executing ==> {}'.format(command)
    print(msg)
    os.system(command)
    pass


def extract_masscan():
    """
    extract masscan result file masscan.json into ip:port format, and add to queue
    """
    # with open(masscan_file, 'r') as fr:
    #     tmp_lines = fr.readlines()
    #     lines = tmp_lines[1:-1]
    #     global total_ports
    #     total_ports = len(lines)
    #     for line in lines:
    #         tmp = line.strip(',\n')
    #         line_json = json.loads(tmp)
    #         # print(line_json)
    #         # extract ip & port
    #         ip = line_json['ip']
    #         port = line_json['ports'][0]['port']

    #         # combine ip:port, and add to queue
    #         ip_port = '{}:{}'.format(ip, port)
    #         task_queue.put(ip_port)
    #         print(ip_port)
            # exit()
    #### Masscan version 1.3.2
    if not os.path.getsize(masscan_file):
        pass
    else:
        with open(masscan_file, 'r') as fr:
            lines = json.load(fr)
            total_ports = len(lines)
            for line in lines:
                ip = line['ip']
                port = line['ports'][0]['port']

                ip_port = '{}:{}'.format(ip, port)
                task_queue.put(ip_port)
                print(ip_port)
    pass


def nmap_scan(ip_port, index):
    # print('scan ==> {}'.format(ip_port))
    try:
        ip, port = ip_port.split(':')
        nm = nmap.PortScanner()
        ret = nm.scan(ip, port, arguments='-n -Pn -sS -sV')
        service = ret['scan'][ip]['tcp'][int(port)]['name']
        msg = '{}:{}:{}:{}'.format(index, ip, port, service)
        print(msg)
        return msg
    except:
        print('sth bad happen ...')


def setcallback(msg):
    services_info.append(msg)


def run_nmap():
    pool = Pool(process_num)  # 创建进程池
    index = 0
    while not task_queue.empty():
        index += 1
        ip_port = task_queue.get(timeout=1.0)
        pool.apply_async(nmap_scan, args=(ip_port, index), callback=setcallback)
    pool.close()
    pool.join()


def save_results():
    print('save_results ...')
    print("services {} lines".format(len(services_info)))
    with open("services.txt", 'w') as fw:
        for line in services_info:
            fw.write(line+'\n')


def finger_print():
    Finger.CheckEnv()
    Urls.url = []
    Save.format = 'json'
    for line in services_info:
        index, ip, port, service = line.split(':')
        if "http" == service or "https" == service:
            _url = "{0}://{1}:{2}".format(service, ip, port)
        else :
            _url = "{0}://{1}:{2}".format('http', ip, port)
        Urls.url.append(_url)
    run = Finger.Request()
    Finger.IpAttributable()
    Finger.Output()



def main():
    # Step 1, run masscan to detect all the open port on all ips
    run_masscan()

    # Step 2, extract masscan result file:masscan.json to ip:port format
    extract_masscan()

    # Step 3, using nmap to scan ip:port
    run_nmap()

    finger_print()
    # Step 4, save results
    # save_results()


if __name__ == '__main__':
    start = datetime.datetime.now()
    main()
    end = datetime.datetime.now()
    spend_time = (end - start).seconds
    msg = 'It takes {} process {} seconds to run ... {} tasks'.format(process_num, spend_time, total_ports)
    print(msg)
