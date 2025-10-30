#!/usr/bin/env python3
'''
版权所有 (C) 2024, WAFW00F 开发者。
请参阅 LICENSE 文件以了解复制权限。

此脚本用于设置 WAFW00F 项目。它定义了项目的元数据、依赖项和安装配置。
'''

import io
from setuptools import setup, find_packages
from os import path

# 获取当前目录的绝对路径
this_directory = path.abspath(path.dirname(__file__))

# 读取 README.md 文件的内容作为项目的长描述
with io.open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    desc = f.read()

# 调用 setuptools 的 setup 函数来配置项目
setup(
    # 项目名称
    name='wafw00f',

    # 项目版本号，从 wafw00f 包中导入
    version=__import__('wafw00f').__version__,

    # 项目的长描述，通常用于 PyPI 页面
    long_description=desc,
    long_description_content_type='text/markdown',

    # 作者信息
    author='Sandro Gauci',
    author_email='sandro@enablesecurity.com',

    # 项目许可证
    license='BSD License',

    # 项目主页 URL
    url='https://github.com/enablesecurity/wafw00f',

    # 项目相关的其他 URL
    project_urls={
        "Bug Tracker": "https://github.com/EnableSecurity/wafw00f/issues",
        "Documentation": "https://github.com/EnableSecurity/wafw00f/wiki",
        "Source Code": "https://github.com/EnableSecurity/wafw00f/tree/master"
    },

    # 自动查找项目中的所有包
    packages=find_packages(),

    # 项目运行所需的依赖项
    install_requires=[
        'requests',  # 用于 HTTP 请求
        'requests[socks]',  # 用于 SOCKS 代理支持
        'pluginbase'  # 用于插件管理
    ],

    # 分类信息，用于描述项目的用途和受众
    classifiers=[
        'Development Status :: 5 - Production/Stable',  # 项目开发状态
        'Intended Audience :: System Administrators',  # 目标用户
        'Intended Audience :: Information Technology',
        'Topic :: Internet',  # 项目主题
        'Topic :: Security',
        'Topic :: System :: Networking :: Firewalls',
        'License :: OSI Approved :: BSD License',  # 开源许可证
        'Programming Language :: Python :: 3',  # 支持的编程语言
        'Operating System :: OS Independent'  # 操作系统兼容性
    ],

    # 项目的关键词
    keywords='waf firewall detector fingerprint',

    # 可选依赖项
    extras_require={
        'dev': [
            'prospector'  # 用于代码质量检查
        ],
        'docs': [
            'Sphinx'  # 用于文档生成
        ]
    },

    # 定义控制台脚本入口点
    entry_points={
        'console_scripts': [
            'wafw00f = wafw00f.main:main'  # 将 wafw00f.main.main 方法作为命令行工具入口
        ]
    }
)
