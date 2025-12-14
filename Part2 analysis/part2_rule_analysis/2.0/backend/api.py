from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
import os
import tempfile
import json
from datetime import datetime

# Add the project directory to the Python path
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'msc_pyparser-master'))

from msc_pyparser import MSCParser
from semantic_analyzer import SemanticAnalyzer
from dependency_analyzer import DependencyAnalyzer
from database import RuleDatabase

app = FastAPI(title="WAF Rule Analysis API", version="1.0.0")

# 数据库路径
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "analysis_results", "rules.db")

# 初始化数据库连接
db = RuleDatabase(db_path=db_path, auto_backup=False)

# 初始化分析器
semantic_analyzer = SemanticAnalyzer()
dependency_analyzer = DependencyAnalyzer()

def parse_rule_details(rule):
    """Extract detailed information from a parsed SecRule"""
    rule_info = {
        'id': "Unknown",
        'phase': "Unknown",
        'variables': [],
        'operator': "",
        'pattern': "",
        'actions': [],
        'tags': [],
        'message': "",
        'severity': "",
        'is_chain': rule.get('chained', False)
    }
    
    # Extract variables
    for v in rule['variables']:
        var_str = v['variable']
        if v['variable_part']:
            var_str += f":{v['variable_part']}"
        rule_info['variables'].append(var_str)
    
    # Extract operator and pattern
    operator = rule['operator']
    if rule['operator_negated']:
        operator = f"!{operator}"
    rule_info['operator'] = operator
    rule_info['pattern'] = rule['operator_argument']
    
    # Extract actions and action-specific details
    for action in rule.get('actions', []):
        act_name = action['act_name']
        act_arg = action['act_arg']
        
        # Add to actions list
        rule_info['actions'].append(f"{act_name}:{act_arg}" if act_arg else act_name)
        
        # Extract specific action values
        if act_name == 'id':
            rule_info['id'] = act_arg
        elif act_name == 'phase':
            rule_info['phase'] = act_arg
        elif act_name == 'msg':
            rule_info['message'] = act_arg
        elif act_name == 'severity':
            rule_info['severity'] = act_arg
        elif act_name == 'tag':
            rule_info['tags'].append(act_arg)
    
    return rule_info

@app.post("/api/analyze-rules")
async def analyze_rules(file: UploadFile = File(...)):
    """
    接收前端上传的规则文件，解析并插入到数据库
    - 支持的文件格式：.conf, .txt, .rules
    - 保持数据库不变，只插入新数据，相同id的规则会被更新
    """
    try:
        # 验证文件格式
        file_ext = os.path.splitext(file.filename)[1].lower()
        if file_ext not in ['.conf', '.txt', '.rules']:
            raise HTTPException(status_code=400, detail="不支持的文件格式，仅支持 .conf, .txt, .rules 文件")
        
        # 读取文件内容
        content = await file.read()
        
        # 创建临时文件用于解析
        with tempfile.NamedTemporaryFile(mode='w+b', suffix=file_ext, delete=False) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name
        
        try:
            # 尝试使用utf-8编码读取文件
            try:
                with open(temp_file_path, 'r', encoding='utf-8') as f:
                    file_content = f.read()
            except UnicodeDecodeError:
                # 尝试使用gbk编码
                with open(temp_file_path, 'r', encoding='gbk') as f:
                    file_content = f.read()
            
            # 解析规则文件
            parser = MSCParser()
            parser.parser.parse(file_content)
            
            # 获取所有SecRule
            secrules = [item for item in parser.configlines if item['type'] == 'SecRule']
            
            if not secrules:
                raise HTTPException(status_code=400, detail="文件中未找到任何SecRule规则")
            
            # 分析规则
            analyzed_rules = []
            raw_rules = []
            
            for i, rule in enumerate(secrules):
                # 提取规则详情
                rule_info = parse_rule_details(rule)
                
                # 创建完整规则对象
                full_rule = {
                    'rule_info': rule_info,
                    'file_name': file.filename,
                    'rule_index': i
                }
                
                # 语义分析
                semantic_result = semantic_analyzer.analyze(full_rule)
                full_rule['semantic_analysis'] = semantic_result
                
                # 依赖分析
                dependency_result = dependency_analyzer.analyze(full_rule, str(rule))
                full_rule['dependency_analysis'] = dependency_result
                
                analyzed_rules.append(full_rule)
                raw_rules.append(str(rule))
            
            # 批量插入或更新规则到数据库
            db.batch_insert(analyzed_rules, "success", raw_rules)
            
            # 构造响应
            response = {
                "success": True,
                "message": f"规则分析成功",
                "data": {
                    "filename": file.filename,
                    "rule_count": len(analyzed_rules),
                    "processed_time": datetime.now().isoformat()
                }
            }
            
            return JSONResponse(content=response, status_code=200)
            
        finally:
            # 删除临时文件
            os.unlink(temp_file_path)
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"规则分析失败: {str(e)}")

@app.get("/api/rules/count")
async def get_rules_count():
    """
    获取数据库中的规则总数
    """
    try:
        all_rules = db.get_all_rules()
        return JSONResponse(
            content={
                "success": True,
                "data": {
                    "total_rules": len(all_rules),
                    "db_path": db_path
                }
            },
            status_code=200
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取规则总数失败: {str(e)}")

@app.post("/api/rules/insert")
async def insert_rule(rule: dict):
    """
    插入或更新单条规则
    """
    try:
        # 验证规则格式
        if 'rule_info' not in rule:
            raise HTTPException(status_code=400, detail="规则格式无效，缺少rule_info字段")
        
        # 插入或更新规则
        result = db.insert(rule, "success", rule.get('raw_rule'))
        
        return JSONResponse(
            content={
                "success": True,
                "message": "规则插入/更新成功" if result else "规则已存在且内容未变化",
                "data": {
                    "rule_id": rule['rule_info'].get('id', 'Unknown'),
                    "action": "updated" if result else "unchanged"
                }
            },
            status_code=200
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"插入规则失败: {str(e)}")

@app.get("/api/health")
async def health_check():
    """
    健康检查
    """
    return JSONResponse(
        content={
            "success": True,
            "message": "WAF Rule Analysis API is running",
            "data": {
                "timestamp": datetime.now().isoformat(),
                "version": "1.0.0"
            }
        },
        status_code=200
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)