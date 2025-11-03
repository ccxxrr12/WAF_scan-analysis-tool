#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Copyright (C) 2024, WAFW00F Developers.
See the LICENSE file for copying permission.
'''

# 导入所需模块
from dataclasses import dataclass  # 用于创建数据类
from random import randint         # 用于生成随机整数

# 导入项目版本信息
from wafw00f import __version__


@dataclass
class Color:
    """ANSI颜色代码类，用于终端彩色输出"""
    # 白色
    W: str = '\033[1;97m'
    # 黄色
    Y: str = '\033[1;93m'
    # 绿色
    G: str = '\033[1;92m'
    # 红色
    R: str = '\033[1;91m'
    # 蓝色
    B: str = '\033[1;94m'
    # 青色
    C: str = '\033[1;96m'
    # 结束颜色代码
    E: str = '\033[0m'

    @classmethod
    def disable(cls):
        """禁用所有颜色输出"""
        cls.W = ''
        cls.Y = ''
        cls.G = ''
        cls.R = ''
        cls.B = ''
        cls.C = ''
        cls.E = ''

    @classmethod
    def unpack(cls):
        """解包并返回颜色值
        用于简化使用，例如：
        (W,Y,G,R,B,C,E) = Color.unpack()
        """
        return (
            cls.W,
            cls.Y,
            cls.G,
            cls.R,
            cls.B,
            cls.C,
            cls.E
        )


def randomArt():
    # 终端颜色设置
    (W,Y,G,R,B,C,E) = Color.unpack()

    #ASCII艺术字
    woof = r'''
        powered by SherryCHEN @SC
        SCNOEK is NOt geEK
'''



    # 将所有艺术字放入列表中
    arts = [woof]
    # 随机返回一个艺术字
    return arts[randint(0, len(arts)-1)]
