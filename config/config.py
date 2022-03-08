#!/usr/bin/env python
# -*- coding: utf-8 -*-
# author = EASY

import random

Version = "V5.1"
Author = "EASY"
Website = "https://www.easy233.top"
Banner = '''\033[1;31m
______ _                       
|  ___(_)                      
| |_   _ _ __   __ _  ___ _ __ 
|  _| | | '_ \ / _` |/ _ \ '__|
| |   | | | | | (_| |  __/ |   
\_|   |_|_| |_|\__, |\___|_|    
                __/ |          
               |___/           \033[1;34mVersion: {0}

    Author: {1}
    Website: {2}\033[0m                   
'''.format(Version,Author,Website)

# 设置线程数，默认30
threads = 30

# 设置Fofa key信息
Fofa_email = ""
Fofa_key = ""
# 普通会员API查询数据是前100，高级会员是前10000条根据自已的实际情况进行调整。

# 设置360quake key信息，每月能免费查询3000条记录
QuakeKey = ""


# 是否选择在线跟新指纹库，默认为True每次程序都会检查一遍指纹库是否是最新
FingerPrint_Update = True


user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/68.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) '
            'Gecko/20100101 Firefox/68.0',
            'Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/68.0']

head = {
    "User-Agent": random.choice(user_agents)
}
