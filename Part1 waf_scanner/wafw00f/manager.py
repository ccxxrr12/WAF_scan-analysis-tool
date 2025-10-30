#!/usr/bin/env python3
'''
版权所有 (C) 2024, WAFW00F 开发者。
请参阅 LICENSE 文件以了解复制权限。

此文件定义了插件管理器，用于加载和管理 wafw00f 的插件。
'''

import os
from functools import partial
from pluginbase import PluginBase

def load_plugins():
    '''
    加载 wafw00f 的所有插件。

    返回：
        dict: 包含插件名称和插件模块的字典。
    '''
    # 获取当前文件所在目录的绝对路径
    here = os.path.abspath(os.path.dirname(__file__))

    # 定义一个函数，用于生成插件目录的路径
    get_path = partial(os.path.join, here)

    # 插件目录路径
    plugin_dir = get_path('plugins')

    # 初始化插件基础配置
    plugin_base = PluginBase(
        package='wafw00f.plugins',  # 插件包的名称
        searchpath=[plugin_dir]  # 插件搜索路径
    )

    # 创建插件源，用于加载插件
    plugin_source = plugin_base.make_plugin_source(
        searchpath=[plugin_dir],  # 插件搜索路径
        persist=True  # 是否持久化插件源
    )

    # 存储插件的字典
    plugin_dict = {}

    # 遍历插件名称并加载插件
    for plugin_name in plugin_source.list_plugins():
        plugin_dict[plugin_name] = plugin_source.load_plugin(plugin_name)

    return plugin_dict
