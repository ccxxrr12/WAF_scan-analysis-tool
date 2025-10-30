#!/usr/bin/env python3
'''
版权所有 (C) 2024, WAFW00F 开发者。
请参阅 LICENSE 文件以了解复制权限。

此文件定义了 WAFW00F 的核心工具类和方法。
'''

import time
import logging
from copy import copy

import requests
import urllib3

# 禁用不安全请求的警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 默认 HTTP 请求头
# 包含常见的浏览器标识和其他头信息
# 用于伪装成普通用户的请求

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

# 定义代理设置（默认为空）
proxies = {}

class waftoolsengine:
    '''
    WAFW00F 的核心工具类。
    提供 HTTP 请求的封装和日志记录功能。
    '''

    def __init__(
        self, target='https://example.com', debuglevel=0,
        path='/', proxies=None, redir=True, head=None, timeout=7
    ):
        '''
        初始化工具类。

        参数：
            target (str): 目标 URL。
            debuglevel (int): 调试级别。
            path (str): 请求路径。
            proxies (dict): 代理设置。
            redir (bool): 是否允许重定向。
            head (dict): 自定义 HTTP 请求头。
            timeout (int): 请求超时时间（秒）。
        '''
        self.target = target
        self.debuglevel = debuglevel
        self.requestnumber = 0  # 请求计数器
        self.path = path
        self.redirectno = 0  # 重定向计数器
        self.allowredir = redir
        self.proxies = proxies
        self.log = logging.getLogger('wafw00f')
        self.timeout = timeout
        if head:
            self.headers = head
        else:
            self.headers = copy(def_headers)  # 复制默认头信息

    def Request(self, headers=None, path=None, params={}, delay=0):
        '''
        执行 HTTP GET 请求。

        参数：
            headers (dict): 自定义 HTTP 请求头。
            path (str): 请求路径。
            params (dict): 请求参数。
            delay (int): 请求延迟（秒）。

        返回：
            Response: HTTP 响应对象。
        '''
        try:
            time.sleep(delay)  # 延迟请求
            if not headers:
                h = self.headers
            else:
                h = headers
            req = requests.get(
                self.target, proxies=self.proxies, headers=h, timeout=self.timeout,
                allow_redirects=self.allowredir, params=params, verify=False
            )
            self.log.info('请求成功')
            self.log.debug('响应头: %s\n' % req.headers)
            self.log.debug('响应内容: %s\n' % req.content)
            self.requestnumber += 1
            return req
        except requests.exceptions.RequestException as e:
            self.log.error('请求失败: %s' % (e.__str__()))
