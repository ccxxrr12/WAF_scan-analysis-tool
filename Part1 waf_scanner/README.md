* -*- coding: utf-8 -*-
  
```
  Copyright (C) 2024, WAFW00F Developers.
  See the LICENSE file for copying permission.
```

# WAF指纹识别引擎 (Part1)

## 目录结构

```
Part1 waf_scanner/
├── docs/                     # 文档目录
├── wafw00f/                  # 核心代码目录
│   ├── bin/                  # 可执行文件目录
│   ├── lib/                  # 库文件目录
│   ├── plugins/              # WAF插件目录
│   ├── __init__.py           # Python包初始化文件
│   ├── main.py               # 主程序文件
│   ├── manager.py            # 插件管理器
│   └── wafprio.py            # WAF优先级配置
├── README.md                 # 项目说明文件
├── setup.py                  # 安装配置文件
├── Makefile                  # 构建文件
└── LICENSE                   # 许可证文件
```

## 模块功能介绍

| 模块名称 | 功能描述 | 主要文件 |
|---------|---------|---------|
| 主程序 | WAF检测核心逻辑，协调各模块工作 | main.py |
| 插件管理器 | 负责加载和管理WAF识别插件 | manager.py |
| WAF插件 | 各种WAF产品的识别规则集合 | plugins/*.py |
| 库文件 | 提供基础工具和功能函数 | lib/ |
| 优先级配置 | 定义WAF检测的优先级顺序 | wafprio.py |

### 核心模块详解

#### 主程序模块 (main.py)
这是WAF指纹识别引擎的核心模块，实现了检测逻辑和主要功能：

1. **正常请求发送**：向目标网站发送正常的HTTP请求，获取基准响应
2. **攻击载荷测试**：构造多种攻击载荷（XSS、SQL注入、文件包含等）进行测试
3. **响应分析**：对比正常响应和攻击响应的差异，识别WAF特征
4. **插件调度**：根据响应特征调用相应的WAF识别插件
5. **结果聚合**：汇总各插件的识别结果，输出最终判定

#### 插件管理模块 (manager.py)
负责管理和加载所有WAF识别插件：

1. **插件发现**：自动扫描plugins目录中的插件文件
2. **插件加载**：动态加载插件并注册到系统中
3. **插件调用**：提供统一接口供主程序调用各插件

#### WAF插件模块 (plugins/)
每个插件文件对应一种WAF产品的识别规则，具有统一的结构：

1. **NAME变量**：定义WAF产品名称和厂商信息
2. **is_waf函数**：实现具体的检测逻辑，返回布尔值表示是否检测到该WAF
3. **检测方法**：通常包括Header匹配、Cookie匹配、响应内容匹配、状态码匹配等

#### 优先级配置模块 (wafprio.py)
定义WAF检测的优先级顺序，影响检测效率和准确性：

1. **优先级列表**：按照市场占有率和重要性排列WAF产品
2. **检测顺序控制**：确保高优先级的WAF产品优先被检测

## How to build
开发者模式： make install
normal： make
详情见Makefile

## How to use
命令`wafw00f -h`查看帮助
```
  Usage: wafw00f url1 [url2 [url3 ... ]]
example: wafw00f http://www.victim.org/

Options:
  -h, --help            show this help message and exit
  -v, --verbose         Enable verbosity, multiple -v options increase
                        verbosity
  -a, --findall         Find all WAFs which match the signatures, do not stop
                        testing on the first one
  -r, --noredirect      Do not follow redirections given by 3xx responses
  -t TEST, --test=TEST  Test for one specific WAF
  -o OUTPUT, --output=OUTPUT
                        Write output to csv, json or text file depending on
                        file extension. For stdout, specify - as filename.
  -f FORMAT, --format=FORMAT
                        Force output format to csv, json or text.
  -i INPUT, --input-file=INPUT
                        Read targets from a file. Input format can be csv,
                        json or text. For csv and json, a `url` column name or
                        element is required.
  -l, --list            List all WAFs that WAFW00F is able to detect
  -p PROXY, --proxy=PROXY
                        Use an HTTP proxy to perform requests, examples:
                        http://hostname:8080, socks5://hostname:1080,
                        http://user:pass@hostname:8080
  -V, --version         Print out the current version of WafW00f and exit.
  -H HEADERS, --headers=HEADERS
                        Pass custom headers via a text file to overwrite the
                        default header set.
  -T TIMEOUT, --timeout=TIMEOUT
                        Set the timeout for the requests.
  --no-colors           Disable ANSI colors in output.
  ```