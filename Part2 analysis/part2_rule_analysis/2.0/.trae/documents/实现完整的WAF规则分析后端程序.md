# 实现完整的WAF规则分析后端程序

## 1. 项目概述

我们需要基于 `msc_pyparser.py` 实现一个完整的WAF规则分析后端程序，该程序能够解析、分析、存储和可视化ModSecurity规则。

## 2. 修改计划

### 2.1 创建主程序入口

创建一个主程序 `main.py`，用于协调各个模块的工作流程：
- 解析规则文件
- 调用各个分析器
- 将结果存储到数据库
- 提供API接口

### 2.2 适配分析器模块

#### 2.2.1 修改 `semantic_analyzer.py`
- 适配 `msc_pyparser.py` 的输出格式
- 调整分析逻辑，使用正确的规则结构

#### 2.2.2 修改 `dependency_analyzer.py`
- 适配 `msc_pyparser.py` 的输出格式
- 调整依赖分析逻辑

#### 2.2.3 修改 `conflict_analyzer.py`
- 适配 `msc_pyparser.py` 的输出格式
- 调整冲突分析逻辑

### 2.3 调整数据库模块

修改 `database.py`：
- 确保正确处理 `msc_pyparser.py` 生成的规则结构
- 优化数据库存储结构，确保与用户要求的字段匹配

### 2.4 调整可视化模块

修改 `visualizer.py`：
- 移除对 ANTLR 的依赖，使用 `msc_pyparser.py` 进行解析
- 简化可视化逻辑，适配新的规则结构

### 2.5 创建测试程序

创建一个测试程序 `test_parser.py`：
- 用于测试规则解析功能
- 验证各个模块的协同工作
- 生成测试报告

### 2.6 验证规则解析

使用 `rules` 目录下的规则文件验证解析功能：
- 解析所有规则文件
- 存储到数据库
- 生成分析报告

## 3. 实现步骤

1. 创建 `main.py` 作为主程序入口
2. 修改各个分析器模块，适配 `msc_pyparser.py` 的输出格式
3. 调整 `database.py` 以正确存储解析结果
4. 简化 `visualizer.py`，移除 ANTLR 依赖
5. 创建 `test_parser.py` 用于测试
6. 运行测试程序，验证规则解析功能
7. 生成测试报告

## 4. 预期结果

- 能够成功解析所有规则文件
- 各个分析器能够正确分析规则
- 分析结果能够正确存储到数据库
- 能够生成可视化分析结果
- 提供完整的API接口

## 5. 技术栈

- Python 3
- SQLite 数据库
- PLY (Python Lex and Yacc) 用于规则解析
- 用于可视化的 pydot 和 networkx 库

这个计划将确保我们能够基于 `msc_pyparser.py` 实现一个完整的WAF规则分析后端程序，满足用户的需求。