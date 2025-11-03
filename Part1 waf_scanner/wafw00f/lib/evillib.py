#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Copyright (C) 2024, WAFW00F Developers.
See the LICENSE file for copying permission.
'''

# 导入所需模块
import time      # 用于时间相关功能
import logging   # 用于日志记录
from copy import copy  # 用于复制对象

# 导入第三方库
import requests       # 用于发送HTTP请求
import urllib3        # 用于处理HTTP连接

# 对于requests < 2.16版本，应使用以下方式
# requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
# 对于requests >= 2.16版本，使用以下方式
# 禁用urllib3的不安全请求警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 默认HTTP头部信息
def_headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0',
    'Accept-Language': 'en-US,en;q=0.5',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'cross-site',
    'Priority': 'u=0, i',
    'DNT': '1',
}
# 代理设置
proxies = {}

class waftoolsengine:
    def __init__(
        self, target='https://example.com', debuglevel=0,
        path='/', proxies=None, redir=True, head=None, timeout=7
    ):
        self.target = target
        self.debuglevel = debuglevel
        self.requestnumber = 0
        self.path = path
        self.redirectno = 0
        self.allowredir = redir
        self.proxies = proxies
        self.log = logging.getLogger('wafw00f')
        self.timeout = timeout
        if head:
            self.headers = head
        else:
            self.headers = copy(def_headers) #copy object by value not reference. Fix issue #90

    def Request(self, headers=None, path=None, params={}, delay=0):
        try:
            time.sleep(delay)
            if not headers:
                h = self.headers
            else: h = headers
            req = requests.get(self.target, proxies=self.proxies, headers=h, timeout=self.timeout,
                    allow_redirects=self.allowredir, params=params, verify=False)
            self.log.info('Request Succeeded')
            self.log.debug('Headers: %s\n' % req.headers)
            self.log.debug('Content: %s\n' % req.content)
            self.requestnumber += 1
            return req
        except requests.exceptions.RequestException as e:
            self.log.error('Something went wrong %s' % (e.__str__()))
