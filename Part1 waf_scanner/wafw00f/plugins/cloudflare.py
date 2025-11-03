#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Copyright (C) 2024, WAFW00F Developers.
See the LICENSE file for copying permission.
'''

# WAF名称定义
NAME = 'Cloudflare (Cloudflare Inc.)'

def is_waf(self):
    """
    检测目标是否使用Cloudflare WAF
    
    检测方法:
    1. 检查响应头中的Server字段是否包含'cloudflare'
    2. 检查响应头中的Server字段是否匹配'cloudflare[-_]nginx'模式
    3. 检查响应头中是否包含'cf-ray'字段
    4. 检查响应中是否包含'__cfduid' Cookie
    
    返回:
    如果检测到Cloudflare WAF则返回True，否则返回False
    """
    # 检查Server头部是否为'cloudflare'
    if self.matchHeader(('server', 'cloudflare')):
        return True

    # 检查Server头部是否匹配'cloudflare[-_]nginx'模式
    if self.matchHeader(('server', r'cloudflare[-_]nginx')):
        return True

    # 检查是否包含'cf-ray'头部
    if self.matchHeader(('cf-ray', r'.+?')):
        return True

    # 检查是否包含'__cfduid' Cookie
    if self.matchCookie('__cfduid'):
        return True

    # 未检测到Cloudflare WAF
    return False