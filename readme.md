# WAF扫描分析工具

## 1. 项目概述

### 1.1 项目简介
WAF扫描分析工具是一个集WAF指纹识别、规则分析和智能检测于一体的综合性Web应用防火墙(WAF)分析系统。该工具能够帮助安全研究人员、网站管理员和开发者快速识别目标网站使用的WAF类型，分析WAF规则的有效性和冲突，并使用机器学习技术预测HTTP请求是否会被WAF拦截。

### 1.2 项目目标
- 提供高效准确的WAF指纹识别功能
- 实现WAF规则的自动化分析和优化建议
- 利用机器学习技术智能预测WAF拦截行为
- 提供直观易用的Web界面，方便用户操作和查看结果
- 支持多种WAF类型和规则格式

### 1.3 应用场景
- 安全研究人员对目标网站进行WAF检测和分析
- 网站管理员评估自身WAF配置的有效性
- 开发者在部署应用前测试WAF规则的合理性
- 安全厂商评估不同WAF产品的防护能力

## 2. 项目结构

### 2.1 目录结构
```
WAF_scan-analysis-tool/
├── Part1 waf_scanner/           # WAF指纹识别引擎
│   ├── docs/                    # 文档目录
│   ├── wafw00f/                 # 核心代码目录
│   │   ├── lib/                 # 库文件目录
│   │   ├── plugins/             # WAF插件目录
│   │   ├── __init__.py          # Python包初始化文件
│   │   ├── main.py              # 主程序文件
│   │   ├── manager.py           # 插件管理器
│   │   └── wafprio.py           # WAF优先级配置
│   ├── .gitignore
│   ├── CODE_OF_CONDUCT.md
│   ├── CREDITS.txt
│   ├── LICENSE
│   ├── MANIFEST.in
│   ├── Makefile
│   ├── README.md
│   └── setup.py
├── Part2 analysis/              # WAF规则分析模块
│   ├── lib/                     # 第三方库目录
│   └── part2_rule_analysis/     # 规则分析核心模块
│       ├── 1.0/                 # 旧版本（不推荐使用）
│       └── 2.0/                 # 最新版本
│           ├── backend/         # 后端分析代码
│           ├── rules/           # 规则文件目录
│           └── rules.db         # 规则数据库
├── Part3 deeplearning/          # 智能检测与机器学习模块
│   ├── models/                  # 模型文件目录
│   ├── part3_waf_ml/            # 核心代码目录
│   ├── Part3_智能检测与机器学习集成方案.md
│   ├── Prompt_for_AI.md
│   ├── http_request_example.json
│   ├── malicious_http_request_example.json
│   ├── module_dependencies_report.md
│   ├── module_verification_report.md
│   ├── readme.md
│   ├── requirements.txt
│   ├── self_check_report_20251213_191627.md
│   ├── test_data.csv
│   ├── 使用说明.md
│   └── 开发进度.md
├── UI/                          # 旧版UI
├── UI_2.0_frontend/             # 2.0版本前端
├── UI_3.0/                      # 最新版本前端
│   └── ruoyi-element-ai/        # 基于Vue3.5+Element-Plus-X的前端项目
├── backend/                     # 后端服务
│   ├── main.py                  # 主程序入口
│   ├── part1_integration.py     # Part1集成模块
│   ├── part2_integration.py     # Part2集成模块
│   ├── part3_integration.py     # Part3集成模块
│   └── requirements.txt         # 依赖包列表
└── .gitignore
```

### 2.2 模块关系

WAF扫描分析工具采用前后端分离的架构设计，各模块之间通过API进行通信，形成一个完整的工作流：

1. **前端**：提供用户界面，接收用户输入并展示分析结果
2. **后端服务**：整合Part1、Part2和Part3的功能，提供统一的API接口
3. **Part1 waf_scanner**：负责WAF指纹识别
4. **Part2 analysis**：负责WAF规则分析
5. **Part3 deeplearning**：负责智能检测和机器学习预测

模块间的数据流如下：
- 用户通过前端界面输入目标URL或上传WAF规则文件
- 前端将请求发送到后端服务
- 后端服务根据请求类型调用相应的模块（Part1、Part2或Part3）
- 各模块执行相应的分析任务
- 分析结果返回给后端服务
- 后端服务将结果返回给前端展示

## 3. 技术栈

### 3.1 后端技术栈
| 技术/框架 | 版本 | 用途 | 来源 |
|----------|------|------|------|
| Python | 3.7+ | 核心编程语言 | 系统内置 |
| FastAPI | 最新 | Web框架，提供API接口 | backend/requirements.txt |
| SQLite | 3.0+ | 数据库，存储规则分析结果 | 系统内置 |
| scikit-learn | 最新 | 机器学习算法库 | Part3 deeplearning/requirements.txt |
| XGBoost | 最新 | 梯度提升算法 | Part3 deeplearning/requirements.txt |
| pandas | 最新 | 数据处理 | Part3 deeplearning/requirements.txt |
| numpy | 最新 | 数值计算 | Part3 deeplearning/requirements.txt |

### 3.2 前端技术栈
| 技术/框架 | 版本 | 用途 | 来源 |
|----------|------|------|------|
| Vue | 3.5 | 前端框架 | UI_3.0/ruoyi-element-ai/package.json |
| Element-Plus-X | 最新 | UI组件库 | UI_3.0/ruoyi-element-ai/package.json |
| TypeScript | 5.8 | 编程语言 | UI_3.0/ruoyi-element-ai/package.json |
| Vite | 5 | 构建工具 | UI_3.0/ruoyi-element-ai/package.json |
| Pinia | 3 | 状态管理 | UI_3.0/ruoyi-element-ai/package.json |
| VueRouter | 最新 | 路由管理 | UI_3.0/ruoyi-element-ai/package.json |
| Hook-Fetch | 最新 | HTTP请求库 | UI_3.0/ruoyi-element-ai/package.json |

### 3.3 其他技术
| 技术/工具 | 用途 |
|----------|------|
| Git | 版本控制 |
| ESLint | 代码质量检查 |
| Stylelint | CSS代码检查 |
| Husky | Git钩子工具 |
| Commitlint | 提交信息规范检查 |

## 4. 功能模块

### 4.1 WAF指纹识别引擎（Part1）

#### 4.1.1 功能概述
WAF指纹识别引擎基于WAFW00F项目开发，能够识别超过200种不同类型的WAF产品。该模块通过向目标网站发送特定的HTTP请求，分析响应头、响应内容和状态码等特征，与内置的WAF指纹库进行匹配，从而确定目标网站使用的WAF类型。

#### 4.1.2 核心功能
- **多WAF支持**：支持识别超过200种WAF产品
- **高效检测**：采用优先级机制，先检测市场占有率高的WAF产品
- **多种检测方法**：结合正常请求和攻击载荷测试，提高检测准确性
- **详细报告**：提供检测结果的详细说明，包括检测到的WAF类型、厂商信息和检测方法

#### 4.1.3 工作原理
1. 向目标网站发送正常的HTTP请求，获取基准响应
2. 构造多种攻击载荷（XSS、SQL注入、文件包含等）进行测试
3. 对比正常响应和攻击响应的差异，识别WAF特征
4. 根据响应特征调用相应的WAF识别插件
5. 汇总各插件的识别结果，输出最终判定

### 4.2 WAF规则分析模块（Part2）

#### 4.2.1 功能概述
WAF规则分析模块主要用于ModSecurity规则的自动化分析，包括规则解析、语义分析、依赖分析和冲突分析。该模块能够帮助用户理解WAF规则的工作原理，发现规则之间的冲突和冗余，并提供优化建议。

#### 4.2.2 核心功能

1. **规则解析**
   - 将ModSecurity规则文本解析为结构化JSON数据
   - 支持多种编码格式（UTF-8、GBK等）
   - 处理复杂的规则语法，包括链式规则

2. **语义分析**
   - 识别规则的检测变量（如REQUEST_URI、REQUEST_HEADERS等）
   - 分析规则的操作符（如@rx、@contains等）
   - 提取规则的动作（如deny、log、redirect等）
   - 识别规则的严重程度和标签

3. **依赖分析**
   - 分析规则之间的执行依赖关系
   - 确定规则的执行顺序
   - 识别规则组和链式规则

4. **冲突分析**
   - 检测规则之间的冗余
   - 识别规则冲突
   - 发现规则优先级问题

5. **结果存储**
   - 将分析结果存储到SQLite数据库
   - 支持结果的导入导出
   - 提供结果查询接口

6. **可视化**
   - 生成规则处理流程图
   - 生成攻击类型分布图
   - 生成冲突分析图
   - 生成依赖关系图

### 4.3 智能检测与机器学习模块（Part3）

#### 4.3.1 功能概述
智能检测与机器学习模块利用传统机器学习算法，基于WAF规则数据和HTTP请求特征，训练模型来预测HTTP请求是否会被WAF拦截。该模块支持多种机器学习算法，并针对不同类型的WAF提供特化模型。

#### 4.3.2 核心功能

1. **数据处理**
   - 从原始HTTP请求中提取特征
   - 处理WAF指纹信息，标准化WAF类型
   - 支持CSV格式数据集加载
   - 数据预处理：去重和缺失值处理
   - 基于规则数据自动生成训练样本

2. **模型定义**
   - 逻辑回归模型
   - 随机森林模型
   - XGBoost模型

3. **模型训练**
   - 支持多种训练模式
   - 实现分层K折交叉验证
   - 模型序列化和保存
   - 支持增量训练

4. **智能预测**
   - 支持单个和批量HTTP请求预测
   - 根据WAF类型自动选择最适合的模型
   - 提供预测结果的置信度

5. **模型评估**
   - 计算准确率、精确率、召回率、F1分数和AUC等指标
   - 支持模型性能对比

### 4.4 前端界面（UI_3.0）

#### 4.4.1 功能概述
前端界面基于Vue3.5 + Element-Plus-X + TypeScript开发，提供了直观易用的用户界面，方便用户操作和查看分析结果。

#### 4.4.2 核心功能
- **WAF扫描**：输入目标URL，执行WAF指纹识别
- **规则分析**：上传WAF规则文件，执行规则分析
- **智能检测**：输入HTTP请求，使用机器学习模型预测WAF拦截行为
- **结果展示**：展示扫描结果、规则分析报告和智能检测结果
- **可视化**：展示规则处理流程图、攻击类型分布图和冲突分析图
- **历史记录**：保存用户的分析历史，方便后续查看

## 5. 安装与配置

### 5.1 环境要求
- **操作系统**：Windows/Linux/macOS
- **Python版本**：3.7或更高版本
- **Node.js版本**：16.0或更高版本
- **包管理器**：npm或pnpm（推荐）

### 5.2 后端安装

1. **安装依赖**
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

2. **启动服务**
   ```bash
   python main.py
   ```
   服务将在 http://0.0.0.0:8000 启动

### 5.3 前端安装

1. **安装依赖**
   ```bash
   cd UI_3.0/ruoyi-element-ai
   pnpm install
   ```

2. **开发模式**
   ```bash
   pnpm run dev
   ```
   前端将在 http://localhost:5173 启动

3. **生产构建**
   ```bash
   pnpm build
   ```
   构建后的文件将输出到 dist 目录

### 5.4 配置说明

#### 5.4.1 后端配置
后端配置主要通过环境变量和配置文件进行管理，关键配置项包括：
- `PORT`：后端服务监听的端口，默认为8000
- `CORS_ORIGINS`：允许的跨域来源，默认为*（生产环境应限制具体域名）
- `DB_PATH`：SQLite数据库文件路径，默认为`Part2 analysis/part2_rule_analysis/2.0/backend/analysis_results/rules.db`

#### 5.4.2 前端配置
前端配置主要在`.env.development`和`.env.production`文件中进行管理，关键配置项包括：
- `VITE_API_BASE_URL`：后端API的基础URL，默认为`http://localhost:8000`
- `VITE_APP_TITLE`：应用标题，默认为"WAF扫描分析工具"

## 6. 使用说明

### 6.1 WAF扫描

1. 在前端界面的"WAF扫描"页面，输入目标URL（例如：https://www.example.com）
2. 点击"开始扫描"按钮
3. 等待扫描完成，查看扫描结果
4. 结果将显示目标网站使用的WAF类型、厂商信息和检测方法

### 6.2 规则分析

1. 在前端界面的"规则分析"页面，点击"上传文件"按钮
2. 选择要分析的ModSecurity规则文件（支持.conf、.txt、.rules格式）
3. 点击"开始分析"按钮
4. 等待分析完成，查看分析结果
5. 结果将显示规则的基本信息、语义分析、依赖关系和冲突情况
6. 可以查看生成的可视化图表，包括规则处理流程图、攻击类型分布图和冲突分析图
7. 可以下载详细的规则分析报告

### 6.3 智能检测

1. 在前端界面的"智能检测"页面，选择要使用的模型
2. 输入或上传HTTP请求数据
3. 点击"开始检测"按钮
4. 等待检测完成，查看检测结果
5. 结果将显示该HTTP请求是否会被WAF拦截，以及预测的置信度

### 6.4 API使用

WAF扫描分析工具提供了RESTful API，可以直接通过API调用各模块的功能。

#### 6.4.1 WAF扫描API
```
POST /api/waf/scan
请求体：{"url": "https://www.example.com"}
响应：{"success": true, "data": {"waf_type": "Cloudflare", "vendor": "Cloudflare Inc.", "method": "Header matching"}}
```

#### 6.4.2 规则分析API
```
POST /api/waf/analyze-rules
请求体：multipart/form-data，包含要上传的规则文件
响应：{"success": true, "data": {"files": [...], "total_rules": 100}}
```

#### 6.4.3 智能检测API
```
POST /api/waf/ai-detect
请求体：{"url": "https://www.example.com", "request_content": "GET /admin HTTP/1.1\r\nHost: www.example.com\r\n\r\n"}
响应：{"success": true, "data": {"prediction": "blocked", "confidence": 0.95}}
```

## 7. 开发指南

### 7.1 代码规范

#### 7.1.1 Python代码规范
- 遵循PEP 8代码风格指南
- 使用类型注解提高代码可读性和可维护性
- 函数和模块应有详细的文档字符串
- 代码注释应清晰明了，解释代码的功能和逻辑

#### 7.1.2 JavaScript/TypeScript代码规范
- 遵循ESLint和Stylelint规则
- 使用TypeScript类型注解
- 组件和函数应有详细的文档注释
- 代码风格统一，缩进为2个空格

### 7.2 开发流程

1. **克隆仓库**
   ```bash
   git clone https://github.com/your-username/WAF_scan-analysis-tool.git
   ```

2. **创建分支**
   ```bash
   git checkout -b feature/your-feature
   ```

3. **开发代码**
   - 遵循代码规范
   - 编写单元测试
   - 更新文档

4. **提交代码**
   ```bash
   git add .
   git commit -m "feat: add new feature"
   ```

5. **推送分支**
   ```bash
   git push origin feature/your-feature
   ```

6. **创建Pull Request**
   - 描述功能变更和实现细节
   - 关联相关Issue
   - 等待代码审查

### 7.3 测试

#### 7.3.1 Python测试
- 使用pytest框架进行单元测试
- 测试文件命名为`test_*.py`
- 测试用例应覆盖主要功能和边缘情况

#### 7.3.2 JavaScript/TypeScript测试
- 使用Vitest框架进行单元测试
- 测试文件命名为`*.test.ts`或`*.spec.ts`
- 测试用例应覆盖组件和工具函数

## 8. 部署说明

### 8.1 开发环境部署
按照5.2和5.3节的步骤安装和启动后端服务和前端应用即可。

### 8.2 生产环境部署

#### 8.2.1 后端部署
1. 使用Docker容器化部署
   ```dockerfile
   FROM python:3.10-slim
   WORKDIR /app
   COPY backend/requirements.txt .
   RUN pip install -r requirements.txt
   COPY backend/ .
   EXPOSE 8000
   CMD ["python", "main.py"]
   ```

2. 使用Nginx或Apache作为反向代理
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;
       
       location / {
           proxy_pass http://localhost:8000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       }
   }
   ```

#### 8.2.2 前端部署
1. 构建生产版本
   ```bash
   cd UI_3.0/ruoyi-element-ai
   pnpm build
   ```

2. 使用Nginx或Apache部署静态文件
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;
       
       location / {
           root /path/to/dist;
           index index.html;
           try_files $uri $uri/ /index.html;
       }
       
       location /api {
           proxy_pass http://localhost:8000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       }
   }
   ```

## 9. 维护与更新

### 9.1 定期更新
- 定期更新Part1的WAF插件库，支持新的WAF产品
- 定期更新Part3的机器学习模型，提高预测准确性
- 定期更新依赖库，修复安全漏洞和性能问题

### 9.2 问题反馈
- 通过GitHub Issues提交问题和建议
- 参与项目讨论和开发
- 贡献代码和文档

### 9.3 版本管理
项目采用语义化版本号管理，版本格式为X.Y.Z：
- X：主版本号，重大功能变更或架构调整
- Y：次版本号，新增功能或改进
- Z：修订号，bug修复或小改进

## 10. 安全注意事项

1. **数据安全**
   - 规则文件可能包含敏感信息，分析过程中请注意保护
   - 建议在安全环境中运行分析程序
   - 分析结果应妥善保存，避免泄露敏感数据

2. **合规性**
   - 使用该工具扫描目标网站时，请确保遵守相关法律法规
   - 获得目标网站所有者的授权后再进行扫描和分析
   - 不要将该工具用于非法用途

3. **系统安全**
   - 定期更新系统和依赖库，修复安全漏洞
   - 使用强密码保护数据库和管理界面
   - 配置适当的访问控制，限制API的访问范围

## 11. 许可证

本项目采用MIT许可证，详细信息请查看LICENSE文件。

## 12. 贡献者

- [项目团队成员1] - 负责Part1 waf_scanner开发
- [项目团队成员2] - 负责Part2 analysis开发
- [项目团队成员3] - 负责Part3 deeplearning开发
- [项目团队成员4] - 负责前端UI开发
- [项目团队成员5] - 负责后端服务开发

## 13. 联系方式

- 项目仓库：https://github.com/your-username/WAF_scan-analysis-tool
- 问题反馈：https://github.com/your-username/WAF_scan-analysis-tool/issues
- 邮箱：contact@example.com
- 论坛：https://forum.example.com

## 14. 致谢

- 感谢WAFW00F项目提供的WAF指纹识别基础
- 感谢所有为项目贡献代码和文档的开发者
- 感谢所有测试和使用本项目的用户

## 15. 附录

### 15.1 常见问题解答

#### Q1: 为什么扫描结果显示"未检测到WAF"？
A1: 可能的原因包括：
- 目标网站确实没有使用WAF
- 目标WAF采用了高级的绕过技术
- 目标WAF不在当前支持的WAF列表中
- 网络连接问题导致扫描失败

#### Q2: 如何添加新的WAF类型支持？
A2: 在Part1 waf_scanner/wafw00f/plugins目录下创建新的插件文件，实现is_waf函数和相关检测逻辑。

#### Q3: 为什么规则分析结果显示有冲突？
A3: 规则冲突通常是由于两个或多个规则的匹配条件重叠，或者规则执行顺序导致的。建议根据分析结果调整规则的优先级或修改规则的匹配条件。

### 15.2 术语表

- **WAF**：Web Application Firewall，Web应用防火墙
- **ModSecurity**：一个开源的WAF引擎
- **指纹识别**：通过识别特定特征来确定WAF类型的过程
- **规则分析**：对WAF规则的结构、语义和依赖关系进行分析的过程
- **机器学习**：一种人工智能技术，通过训练模型来预测结果
- **HTTP请求**：客户端向服务器发送的请求，包含URL、请求头和请求体等信息
- **响应头**：服务器返回的HTTP响应中的头部信息
- **状态码**：HTTP响应中表示请求处理结果的数字代码
- **攻击载荷**：用于测试WAF防护能力的恶意请求内容

### 15.3 参考文献

1. WAFW00F项目：https://github.com/EnableSecurity/wafw00f
2. ModSecurity官方文档：https://modsecurity.org/documentation.html
3. FastAPI官方文档：https://fastapi.tiangolo.com/
4. Vue.js官方文档：https://vuejs.org/
5. Element Plus官方文档：https://element-plus.org/
6. scikit-learn官方文档：https://scikit-learn.org/stable/
7. XGBoost官方文档：https://xgboost.readthedocs.io/

---

**文档更新日期**：2025年12月14日
**文档版本**：1.0
**作者**：项目开发团队