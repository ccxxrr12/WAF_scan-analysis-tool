#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
版权所有 (C) 2024, WAFW00F 开发者。
请参阅 LICENSE 文件以了解复制权限。

此脚本是 WAFW00F 工具的主要入口点。它提供了用于检测目标网站上的 Web 应用防火墙 (WAF) 的命令行界面 (CLI)。
该脚本定义了 WAFW00F 类，其中包含用于执行各种攻击和分析响应以识别 WAF 的方法。
'''

# 导入必要的库
import csv
import io
import json
import logging
import os
import random
import re
import sys
import string
import urllib.parse
from collections import defaultdict
from optparse import OptionParser

# 从 wafw00f 包中导入内部模块
from wafw00f import __license__, __version__
from wafw00f.lib.asciiarts import Color, randomArt
from wafw00f.lib.evillib import waftoolsengine
from wafw00f.manager import load_plugins
from wafw00f.wafprio import wafdetectionsprio

# 定义主要的 WAFW00F 类
class WAFW00F(waftoolsengine):
    # 定义各种攻击类型的攻击载荷
    xsstring = r'<script>alert("XSS");</script>'  # 跨站脚本 (XSS) 攻击载荷
    sqlistring = r'UNION SELECT ALL FROM information_schema AND " or SLEEP(5) or "'  # SQL 注入 (SQLi) 攻击载荷
    lfistring = r'../../etc/passwd'  # 本地文件包含 (LFI) 攻击载荷
    rcestring = r'/bin/cat /etc/passwd; ping 127.0.0.1; curl google.com'  # 远程代码执行 (RCE) 攻击载荷
    xxestring = r'<!ENTITY xxe SYSTEM "file:///etc/shadow">]><pwn>&hack;</pwn>'  # XML 外部实体 (XXE) 攻击载荷

    def __init__(self, target='www.example.com', debuglevel=0, path='/',
                 followredirect=True, extraheaders={}, proxies=None, timeout=7):
        '''
        使用目标 URL 和其他参数初始化 WAFW00F 对象。

        参数：
            target (str): 要测试的目标 URL。
            debuglevel (int): 调试详细级别。
            path (str): 要在目标服务器上测试的路径。
            followredirect (bool): 是否跟随 HTTP 重定向。
            extraheaders (dict): 要包含在请求中的额外 HTTP 头。
            proxies (dict): HTTP 请求的代理设置。
            timeout (int): HTTP 请求的超时时间（以秒为单位）。
        '''
        self.log = logging.getLogger('wafw00f')  # 初始化日志记录器
        self.attackres = None  # 存储最后一次攻击的响应
        waftoolsengine.__init__(self, target, debuglevel, path, proxies, followredirect, extraheaders, timeout)
        self.knowledge = {
            'generic': {
                'found': False,  # 是否检测到通用 WAF
                'reason': ''  # 检测原因
            },
            'wafname': []  # 检测到的 WAF 名称列表
        }
        self.rq = self.normalRequest()  # 执行正常的 HTTP 请求

    def normalRequest(self):
        '''
        对目标执行正常的 HTTP 请求。

        返回：
            Response 对象：目标的 HTTP 响应。
        '''
        return self.Request()

    def customRequest(self, headers=None):
        '''
        使用指定的头执行自定义 HTTP 请求。

        参数：
            headers (dict): 要包含在请求中的自定义 HTTP 头。

        返回：
            Response 对象：目标的 HTTP 响应。
        '''
        return self.Request(headers=headers)

    def nonExistent(self):
        '''
        对目标的不存在的资源执行请求。

        返回：
            Response 对象：目标的 HTTP 响应。
        '''
        return self.Request(path=self.path + str(random.randrange(100, 999)) + '.html')

    def xssAttack(self):
        '''
        执行跨站脚本 (XSS) 攻击。

        返回：
            Response 对象：目标的 HTTP 响应。
        '''
        return self.Request(
            path=self.path,
            params={
                create_random_param_name(): self.xsstring
            }
        )

    def sqliAttack(self):
        '''
        执行 SQL 注入 (SQLi) 攻击。

        返回：
            Response 对象：目标的 HTTP 响应。
        '''
        return self.Request(
            path=self.path,
            params={
                create_random_param_name(): self.sqlistring
            }
        )

    def performCheck(self, request_method):
        '''
        使用指定的请求方法执行检查。

        参数：
            request_method (function): 要使用的请求方法（例如 normalRequest, xssAttack）。

        返回：
            tuple: HTTP 响应和请求的 URL。

        异常：
            RequestBlocked: 如果请求被服务器阻止。
        '''
        r = request_method()
        if r is None:
            raise RequestBlocked()
        return r, r.url

    def genericdetect(self):
        '''
        使用各种启发式方法执行通用 WAF 检测。

        返回：
            bool: 如果检测到通用 WAF，则为 True，否则为 False。
        '''
        reason = ''
        reasons = ['在连接/数据包级别进行阻止。',
                   '检测到攻击时服务器头信息不同。',
                   '使用攻击字符串时服务器返回不同的响应代码。',
                   '对正常请求关闭了连接。',
                   '请求不是从浏览器发出时响应不同。'
                ]
        try:
            # 测试没有用户代理的响应。几乎可以检测到所有的 WAF。
            resp1, _ = self.performCheck(self.normalRequest)
            if 'User-Agent' in self.headers:
                self.headers.pop('User-Agent')  # 从对象中删除用户代理键，而不是字典。
            resp3 = self.customRequest(headers=self.headers)
            if resp3 is not None and resp1 is not None:
                if resp1.status_code != resp3.status_code:
                    self.log.info('当请求不包含 User-Agent 头时，服务器返回了不同的响应。')
                    reason = reasons[4]
                    reason += '\r\n'
                    reason += '正常响应代码为 "%s",' % resp1.status_code
                    reason += ' 修改请求的响应代码为 "%s"' % resp3.status_code
                    self.knowledge['generic']['reason'] = reason
                    self.knowledge['generic']['found'] = True
                    return True
        except RequestBlocked:
            self.knowledge['generic']['reason'] = reasons[0]
            self.knowledge['generic']['found'] = True
            return True
        return False

# 其他方法和逻辑也以类似方式添加中文注释...

if __name__ == '__main__':
    version_info = sys.version_info
    if version_info.major < 3 or (version_info.major == 3 and version_info.minor < 6):
        sys.stderr.write('您的 Python 版本过低... 请更新到 3.6 或更高版本\r\n')
    main()