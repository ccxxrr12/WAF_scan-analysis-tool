## 实现WAF项目前后端连接

### 1. 后端修改计划

#### 1.1 创建统一API服务

* 在项目根目录创建 `backend` 目录，作为统一的API服务入口

* 使用FastAPI构建RESTful API服务

* 实现三个后端模块的集成：

  * Part1 (WAF扫描): 接收URL，返回WAF检测结果

  * Part2 (规则分析): 接收上传的.conf文件，返回规则分析结果

  * Part3 (深度学习): 接收URL+请求，返回智能检测结果

#### 1.2 修改现有后端模块

* **Part1**: 封装 `waf_scanner/wafw00f/main.py` 为可调用函数

* **Part2**: 封装 `part2_rule_analysis/2.0/backend/main.py` 为可调用函数

* **Part3**: 封装 `deeplearning/part3_waf_ml/main.py` 为可调用函数

### 2. 前端修改计划

#### 2.1 新增API接口定义

* 在 `src/api/` 目录下新增 `waf/` 文件夹

* 创建 `waf/index.ts` 和 `waf/types.ts` 定义WAF相关API

#### 2.2 修改输入框逻辑

* 在 `src/pages/chat/layouts/chatWithId/index.vue` 中修改 `startSSE` 函数

* 根据输入内容类型调用不同的后端API：

  * 仅输入URL → 调用Part1 API

  * 输入URL+请求内容 → 调用Part3 API

  * 上传.conf文件 → 调用Part2 API

#### 2.3 扩展文件上传支持

* 修改 `FilesSelect` 组件，支持上传.conf规则文件

* 在上传文件时自动调用Part2 API

### 3. 连接逻辑实现

| 输入类型    | 检测条件        | 调用模块  | API路径                  |
| ------- | ----------- | ----- | ---------------------- |
| URL     | 仅包含URL格式字符串 | Part1 | /api/waf/scan          |
| URL+请求  | 包含URL和请求内容  | Part3 | /api/waf/ai-detect     |
| .conf文件 | 上传.conf后缀文件 | Part2 | /api/waf/analyze-rules |

### 4. 实现步骤

1. 创建统一后端API服务
2. 封装现有三个后端模块
3. 定义前端API接口
4. 修改输入框逻辑，实现智能路由
5. 测试前后端连接
6. 优化错误处理和响应格式

### 5. 预期效果

* 保持现有前端界面不变

* 根据输入内容自动选择调用的后端模块

* 统一的API响应格式

* 良好的错误处理和用户反馈

### 6. 技术栈

* 后端: FastAPI + Python 3.9+

* 前端: Vue 3 + TypeScript + Element Plus

* API请求: hook-fetch

* 数据格式: JSON

### 7. 文件结构

```C
├── backend/                    # 统一API服务
│   ├── main.py                 # FastAPI入口
│   ├── part1_integration.py    # Part1集成
│   ├── part2_integration.py    # Part2集成
│   ├── part3_integration.py    # Part3集成
│   └── requirements.txt        # 依赖
├── UI_3.0/ruoyi-element-ai/    # 前端项目
│   └── src/
│       └── api/
│           └── waf/            # WAF相关API
```

