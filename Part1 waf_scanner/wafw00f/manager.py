#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Copyright (C) 2024, WAFW00F Developers.
See the LICENSE file for copying permission.
'''

# 导入所需模块
import os  # 用于操作系统相关功能
from functools import partial  # 用于创建偏函数
from pluginbase import PluginBase  # 用于插件管理

def load_plugins():
    """
    加载所有WAF插件
    
    返回:
    包含所有插件的字典，键为插件名称，值为插件对象
    """
    # 获取当前文件的绝对路径目录
    here = os.path.abspath(os.path.dirname(__file__))
    # 创建路径拼接函数
    get_path = partial(os.path.join, here)
    # 插件目录路径
    plugin_dir = get_path('plugins')

    # 创建插件基础对象
    plugin_base = PluginBase(
        package='wafw00f.plugins', searchpath=[plugin_dir]
    )
    # 创建插件源
    plugin_source = plugin_base.make_plugin_source(
        searchpath=[plugin_dir], persist=True
    )

    # 存储插件的字典
    plugin_dict = {}
    # 遍历所有插件名称
    for plugin_name in plugin_source.list_plugins():
        # 加载插件并存储到字典中
        plugin_dict[plugin_name] = plugin_source.load_plugin(plugin_name)

    # 返回插件字典
    return plugin_dict