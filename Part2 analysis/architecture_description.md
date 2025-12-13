# Part2 WAF规则分析模块架构说明

## 1. 目录结构

```
Part2 analysis/
├── lib/                          # 第三方库目录
└── part2_rule_analysis/          # 规则分析核心模块
    ├── 1.0/                      # 旧版本（不推荐使用）
    └── 2.0/                      # 最新版本
        ├── backend/              # 后端分析代码
        │   ├── analysis_results/ # 分析结果输出目录
        │   ├── compare_rules.py  # 规则比较工具
        │   ├── conflict_analyzer.py  # 冲突分析器
        │   ├── database.py       # 数据库操作模块
        │   ├── db_to_json.py     # 数据库转JSON工具
        │   ├── dependency_analyzer.py # 依赖分析器
        │   ├── main.py           # 主程序入口
        │   ├── msc_pyparser.py   # ModSecurity规则解析器
        │   ├── parsetab.py       # 解析表文件
        │   ├── semantic_analyzer.py # 语义分析器
        │   ├── setup.py          # 安装脚本
        │   ├── test_database.py  # 数据库测试脚本
        │   ├── test_visualizer.py # 可视化测试脚本
        │   └── visualizer.py     # 可视化生成器
        ├── rules/                # 规则文件目录
        └── rules.db              # 规则数据库
```

## 2. 模块功能介绍

| 模块名称 | 功能描述 | 主要文件 |
|---------|---------|---------|
| 规则解析器 | 解析ModSecurity规则语法，将规则文本转换为结构化数据 | msc_pyparser.py |
| 语义分析器 | 分析规则的语义，识别规则的检测目标、动作和优先级 | semantic_analyzer.py |
| 依赖分析器 | 分析规则之间的依赖关系，识别规则执行顺序 | dependency_analyzer.py |
| 冲突分析器 | 检测规则之间的冲突，如规则冗余、规则冲突等 | conflict_analyzer.py |
| 数据库模块 | 存储和管理规则分析结果 | database.py |
| 可视化生成器 | 生成规则流程图、攻击类型分布等可视化图表 | visualizer.py |
| 主程序 | 协调各个模块，执行完整的规则分析流程 | main.py |

## 3. 程序入口

### 3.1 独立运行入口
- **文件路径**: `Part2 analysis/part2_rule_analysis/2.0/backend/main.py`
- **入口函数**: `main()`
- **功能**: 执行完整的规则分析流程，包括规则解析、语义分析、依赖分析、冲突分析、结果存储和可视化生成

### 3.2 集成接口
- **文件路径**: `backend/part2_integration.py`
- **主要函数**: `analyze_rules_file(file_content: bytes, filename: str) -> Dict[str, Any]`
- **功能**: 提供给主系统的集成接口，用于分析上传的规则文件

## 4. 功能说明

### 4.1 核心功能

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

### 4.2 功能示例

#### 规则解析示例

输入：
```apache
SecRule REQUEST_URI "@rx /admin/" "id:100,phase:1,deny,msg:'Admin access denied'"
```

输出：
```json
{
  "rule_info": {
    "id": "100",
    "phase": "1",
    "variables": ["REQUEST_URI"],
    "operator": "@rx",
    "pattern": "/admin/",
    "actions": ["id:100", "phase:1", "deny", "msg:'Admin access denied'"],
    "is_chain": false
  }
}
```

#### 冲突分析示例

输入：两个重叠的规则
```apache
SecRule REQUEST_URI "@rx /admin/" "id:100,phase:1,deny"
SecRule REQUEST_URI "@rx /admin/.*" "id:101,phase:1,deny"
```

输出：
```json
{
  "conflicts": [
    {
      "rule1": "100",
      "rule2": "101",
      "conflict_type": "冗余规则",
      "description": "规则101的匹配模式包含规则100的匹配模式"
    }
  ]
}
```

## 5. 依赖关系

### 5.1 内部依赖

| 模块 | 依赖模块 |
|-----|---------|
| main.py | msc_pyparser, semantic_analyzer, dependency_analyzer, conflict_analyzer, database, visualizer |
| semantic_analyzer.py | 无直接依赖 |
| dependency_analyzer.py | 无直接依赖 |
| conflict_analyzer.py | 无直接依赖 |
| database.py | sqlite3 |
| visualizer.py | 无直接依赖 |

### 5.2 外部依赖

- Python 3.7+：核心编程语言
- sqlite3：数据库支持（Python标准库）
- json：JSON处理（Python标准库）
- tempfile：临时文件处理（Python标准库）
- os, sys：系统操作（Python标准库）

## 6. 构建方法

### 6.1 环境要求

- 操作系统：Windows/Linux/macOS
- Python版本：3.7或更高版本

### 6.2 安装步骤

1. 克隆项目到本地
2. 进入项目根目录
3. 安装依赖（本模块无特殊依赖，使用Python标准库即可）

```bash
# 无需额外安装依赖，使用Python标准库即可运行
```

## 7. 使用示例

### 7.1 独立运行

```bash
# 进入后端目录
cd Part2 analysis/part2_rule_analysis/2.0/backend

# 运行主程序
python main.py

# 分析结果将输出到 analysis_results/ 目录
```

### 7.2 集成使用

```python
from part2_integration import analyze_rules_file

# 读取规则文件
with open("rules.conf", "rb") as f:
    content = f.read()

# 调用分析函数
result = analyze_rules_file(content, "rules.conf")

# 处理分析结果
if result["success"]:
    print(f"分析成功，共处理 {result['data']['rule_count']} 条规则")
    print(f"发现 {result['data']['conflict_count']} 个冲突")
else:
    print(f"分析失败：{result['error']}")
```

### 7.3 API调用

```bash
# 使用curl调用API端点
curl -X POST "http://localhost:8000/api/waf/analyze-rules" \
  -F "file=@rules.conf"
```

## 8. 代码注释规范

### 8.1 函数注释

```python
def analyze_rules_file(file_content: bytes, filename: str) -> Dict[str, Any]:
    """
    分析上传的WAF规则文件
    
    Args:
        file_content: 文件内容的字节流
        filename: 文件名
        
    Returns:
        包含规则分析结果的字典
    """
    # 函数实现...
```

### 8.2 模块注释

```python
"""
规则冲突分析器

该模块负责分析WAF规则之间的冲突，包括规则冗余、冲突和优先级问题
"""

# 模块实现...
```

### 8.3 代码行注释

```python
# 清空数据库中的所有规则，确保只有当前文件中的规则
conn = sqlite3.connect(db_path)
cursor = conn.cursor()
cursor.execute("DELETE FROM rules")  # 删除所有现有规则
conn.commit()
conn.close()
```

## 9. 扩展建议

1. **支持更多规则格式**：目前仅支持ModSecurity规则，可扩展支持其他WAF规则格式
2. **增强冲突检测算法**：改进冲突检测逻辑，提高检测准确性
3. **增加规则优化建议**：根据分析结果，提供规则优化建议
4. **支持分布式分析**：对于大规模规则集，支持分布式并行分析
5. **增强可视化效果**：提供更多种类的可视化图表，改进交互体验

## 10. 版本历史

- **2.0版本**：2025年12月发布，重构了整个模块架构，提升了分析性能和准确性
- **1.0版本**：早期版本，功能相对简单，已不再推荐使用

## 11. 维护说明

- 主要维护人员：项目开发团队
- 代码仓库：https://github.com/your-repo/WAF_scan-analysis-tool
- 问题反馈：通过GitHub Issues提交
- 更新频率：根据需求不定期更新

## 12. 安全注意事项

1. 规则文件可能包含敏感信息，分析过程中请注意保护
2. 建议在安全环境中运行分析程序
3. 分析结果应妥善保存，避免泄露敏感数据
4. 定期更新分析工具，确保支持最新的规则语法

---

**文档更新日期**：2025年12月13日
**文档版本**：1.0
**作者**：项目开发团队