from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn
import os
import sys
import json
from datetime import datetime

# 添加项目根目录和backend目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

app = FastAPI(
    title="WAF Analysis API",
    description="统一WAF扫描、规则分析和深度学习检测API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 在生产环境中应该限制具体的域名
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 定义请求模型
class ScanRequest(BaseModel):
    url: str

class AIDetectRequest(BaseModel):
    url: str
    request_content: str

# Part2数据库路径配置
part2_db_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'Part2 analysis',
    'part2_rule_analysis',
    '2.0',
    'backend',
    'analysis_results',
    'rules.db'
)

# 分析结果存储目录
analysis_results_dir = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'analysis_results'
)

# 确保分析结果目录存在
if not os.path.exists(analysis_results_dir):
    os.makedirs(analysis_results_dir)

# 健康检查路由
@app.get("/health")
async def health_check():
    return {"status": "ok", "message": "WAF Analysis API is running"}

# 导入Part1集成模块
from part1_integration import scan_waf as part1_scan

# Part1: WAF扫描路由
@app.post("/api/waf/scan")
async def scan_waf(request: ScanRequest, sessionId: str = "default"):
    """扫描指定URL的WAF类型"""
    try:
        # 创建会话目录
        session_dir = os.path.join(analysis_results_dir, sessionId)
        if not os.path.exists(session_dir):
            os.makedirs(session_dir)
        
        result = part1_scan(request.url)
        if result.get("success"):
            return JSONResponse(status_code=200, content=result)
        else:
            return JSONResponse(status_code=400, content=result)
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": f"WAF扫描失败: {str(e)}"}
        )



# 导入Part3集成模块
from part3_integration import ai_detect as part3_ai_detect

# Part3: 深度学习检测路由
@app.post("/api/waf/ai-detect")
async def ai_detect(request: AIDetectRequest, sessionId: str = "default"):
    """使用深度学习检测WAF"""
    # 创建会话目录
    session_dir = os.path.join(analysis_results_dir, sessionId)
    if not os.path.exists(session_dir):
        os.makedirs(session_dir)
    
    result = part3_ai_detect(request.url, request.request_content)
    return result

# 获取可用模型列表
@app.get("/system/model/modelList")
async def get_model_list():
    """获取可用的WAF检测模型列表"""
    try:
        # 获取Part3的models目录
        part3_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Part3 deeplearning')
        model_dir = os.path.join(part3_path, "models")
        
        # 列出models目录下的所有模型文件
        model_files = [f for f in os.listdir(model_dir) if f.endswith('.pkl')]
        
        # 构建模型列表
        models = []
        for model_file in model_files:
            # 提取模型名称（去除扩展名）
            model_name = model_file.replace('.pkl', '')
            models.append({
                "id": model_name,
                "modelName": model_name,
                "remark": f"WAF检测模型: {model_name}"
            })
        
        return {"code": 200, "msg": "获取模型列表成功", "data": models}
    except Exception as e:
        return {"code": 500, "msg": f"获取模型列表失败: {str(e)}", "data": []}

# 导入Part2集成模块
from part2_integration import analyze_rules_file as part2_analyze, get_rules_count as part2_get_count, insert_rule as part2_insert_rule

# Part2: 规则分析路由
@app.post("/api/waf/analyze-rules")
async def analyze_rules(files: list[UploadFile] = File(...), sessionId: str = "default"):
    """
    接收前端上传的规则文件，解析并插入到数据库
    - 支持的文件格式：.conf, .txt, .rules
    - 保持数据库不变，只插入新数据，相同id的规则会被更新
    - 支持多个文件同时上传
    - 为每个会话创建唯一的子目录来存储分析结果
    """
    try:
        # 检查是否有文件上传
        if not files:
            raise HTTPException(status_code=400, detail="未上传任何文件")
        
        # 创建会话目录
        session_dir = os.path.join(analysis_results_dir, sessionId)
        if not os.path.exists(session_dir):
            os.makedirs(session_dir)
        
        all_results = {
            "success": True,
            "message": "规则分析成功",
            "data": {
                "files": [],
                "total_rules": 0
            }
        }
        
        total_rules = 0
        all_rules = []
        all_raw_rules = []
        
        # 处理每个上传的文件
        for file in files:
            # 验证文件格式
            file_ext = os.path.splitext(file.filename)[1].lower()
            if file_ext not in ['.conf', '.txt', '.rules']:
                # 跳过不支持的文件格式
                continue
            
            # 读取文件内容
            content = await file.read()
            
            # 尝试使用utf-8编码读取文件
            try:
                file_content = content.decode('utf-8')
            except UnicodeDecodeError:
                # 尝试使用gbk编码
                file_content = content.decode('gbk')
            
            # 调用Part2的规则分析函数
            result = part2_analyze(file_content, file.filename, part2_db_path)
            
            if result["success"]:
                # 累积结果
                all_results["data"]["files"].append(result["data"])
                total_rules += result["data"]["rule_count"]
                # 收集所有规则，用于后续分析
                if result["data"]["rules"]:
                    all_rules.extend(result["data"]["rules"])
            else:
                # 如果有任何一个文件失败，整个请求失败
                all_results["success"] = False
                all_results["message"] = f"部分文件分析失败: {result['error']}"
        
        all_results["data"]["total_rules"] = total_rules
        
        # 如果所有文件分析成功，进行冲突分析和可视化生成
        if all_results["success"] and all_rules:
            try:
                # 1. 冲突分析
                from conflict_analyzer import ConflictAnalyzer
                conflict_analyzer = ConflictAnalyzer()
                conflicts = conflict_analyzer.batch_analyze(all_rules)
                
                # 2. 生成可视化图像
                from visualizer import RuleFlowVisualizer, AttackTypeVisualizer, ConflictVisualizer
                
                # 规则处理流程可视化
                ruleflow_visualizer = RuleFlowVisualizer()
                ruleflow_file = os.path.join(session_dir, "rule_processing_flow.html")
                ruleflow_visualizer.save_ruleflow_file(all_rules, ruleflow_file)
                
                # 攻击类型分布可视化
                attack_visualizer = AttackTypeVisualizer()
                attack_file = os.path.join(session_dir, "attack_type_distribution.html")
                attack_visualizer.save_attack_type_file(all_rules, attack_file)
                
                # 冲突分析可视化
                conflict_visualizer = ConflictVisualizer()
                conflict_viz_file = os.path.join(session_dir, "conflict_analysis.html")
                conflict_visualizer.save_conflict_file(conflicts, conflict_viz_file)
                
                # 3. 生成详细报告
                detailed_report_file = os.path.join(session_dir, "detailed_rules_report.md")
                generate_detailed_report(all_results["data"]["files"], all_rules, detailed_report_file)
                
                # 保存冲突分析结果
                conflict_file = os.path.join(session_dir, "detailed_rules_conflicts.json")
                with open(conflict_file, 'w', encoding='utf-8') as f:
                    json.dump(conflicts, f, indent=2, ensure_ascii=False)
                    
            except Exception as e:
                print(f"生成可视化和报告时出错: {e}")
                import traceback
                traceback.print_exc()
                # 即使可视化生成失败，也不影响主要分析结果
        
        if all_results["success"]:
            return JSONResponse(status_code=200, content=all_results)
        else:
            return JSONResponse(status_code=400, content=all_results)
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"规则分析失败: {str(e)}")

# 生成详细报告的辅助函数
def generate_detailed_report(files_results, all_rules, output_file):
    """
    生成详细的规则分析报告
    """
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# Detailed ModSecurity Rules Parsing Report\n\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total files: {len(files_results)}\n")
        f.write(f"Total rules: {len(all_rules)}\n\n")
        f.write("="*100 + "\n\n")
        
        # 1. 总体规则统计
        f.write("## Overall Rule Statistics\n\n")
        
        # 攻击类型分布统计
        attack_type_count = {}
        for rule in all_rules:
            attack_types = rule.get('semantic_analysis', {}).get('attack_types', [])
            for attack_type in attack_types:
                attack_type_count[attack_type] = attack_type_count.get(attack_type, 0) + 1
        
        f.write("### Attack Type Distribution\n")
        for attack_type, count in attack_type_count.items():
            f.write(f"- {attack_type}: {count} rules\n")
        f.write("\n")
        
        # 规则类型分布统计
        rule_type_count = {}
        for rule in all_rules:
            rule_type = rule.get('semantic_analysis', {}).get('rule_classification', {}).get('rule_type', 'unknown')
            rule_type_count[rule_type] = rule_type_count.get(rule_type, 0) + 1
        
        f.write("### Rule Type Distribution\n")
        for rule_type, count in rule_type_count.items():
            f.write(f"- {rule_type}: {count} rules\n")
        f.write("\n")
        
        f.write("="*100 + "\n\n")
        
        # 2. 每个文件的详细分析
        for file_result in files_results:
            f.write(f"## File: {file_result['filename']}\n\n")
            f.write(f"### File Summary\n")
            f.write(f"- Total rules: {file_result['rule_count']}\n")
            f.write(f"- Processed time: {file_result['processed_time']}\n\n")
            
            if file_result['rules']:
                f.write(f"### All Rules in File\n\n")
                
                for i, rule in enumerate(file_result['rules']):
                    rule_info = rule['rule_info']
                    semantic_analysis = rule.get('semantic_analysis', {})
                    dependency_analysis = rule.get('dependency_analysis', {})
                    
                    f.write(f"#### Rule {i+1}: {rule_info['id']}\n")
                    
                    # 基本规则信息
                    f.write(f"##### Basic Information\n")
                    f.write(f"- **Phase**: {rule_info['phase']}\n")
                    f.write(f"- **Variables**: {', '.join(rule_info['variables'])}\n")
                    f.write(f"- **Operator**: {rule_info['operator']}\n")
                    f.write(f"- **Pattern**: {rule_info['pattern']}\n")
                    f.write(f"- **Is Chain**: {rule_info['is_chain']}\n")
                    f.write(f"- **Message**: {rule_info['message']}\n")
                    f.write(f"- **Severity**: {rule_info['severity']}\n")
                    f.write(f"- **Actions**: {', '.join(rule_info['actions'])}\n")
                    f.write(f"- **Tags**: {', '.join(rule_info['tags']) if rule_info['tags'] else 'None'}\n\n")
                    
                    # 语义分析结果
                    f.write(f"##### Semantic Analysis\n")
                    attack_types = semantic_analysis.get('attack_types', [])
                    f.write(f"- **Attack Types**: {', '.join(attack_types) if attack_types else 'None'}\n")
                    
                    classification = semantic_analysis.get('rule_classification', {})
                    if classification:
                        f.write(f"- **Protection Layer**: {classification.get('protection_layer', 'unknown')}\n")
                        f.write(f"- **Matching Method**: {classification.get('matching_method', 'unknown')}\n")
                        f.write(f"- **Scenario**: {classification.get('scenario', 'unknown')}\n")
                        f.write(f"- **Rule Type**: {classification.get('rule_type', 'unknown')}\n")
                    f.write("\n")
                    
                    # 依赖分析结果
                    f.write(f"##### Dependency Analysis\n")
                    variable_deps = dependency_analysis.get('variable_dependencies', [])
                    f.write(f"- **Variable Dependencies**: {', '.join(variable_deps) if variable_deps else 'None'}\n")
                    
                    marker_deps = dependency_analysis.get('marker_dependencies', [])
                    f.write(f"- **Marker Dependencies**: {', '.join(marker_deps) if marker_deps else 'None'}\n")
                    
                    include_deps = dependency_analysis.get('include_dependencies', [])
                    f.write(f"- **Include Dependencies**: {', '.join(include_deps) if include_deps else 'None'}\n")
                    f.write("\n")
                    f.write("-"*50 + "\n\n")
            
            f.write("="*100 + "\n\n")
    
    print(f"Detailed report generated: {output_file}")

# 获取规则总数
@app.get("/api/waf/rules/count")
async def get_rules_count():
    """
    获取数据库中的规则总数
    """
    result = part2_get_count(part2_db_path)
    return JSONResponse(content=result, status_code=200 if result["success"] else 500)

# 插入或更新单条规则
@app.post("/api/waf/rules/insert")
async def insert_rule(rule: dict):
    """
    插入或更新单条规则
    """
    result = part2_insert_rule(rule, part2_db_path)
    return JSONResponse(content=result, status_code=200 if result["success"] else 500)

# 可视化图像路由
from fastapi.responses import FileResponse

@app.get("/api/waf/visualizations/{visualization_type}")
async def get_visualization(visualization_type: str, sessionId: str = "default"):
    """
    获取规则可视化图像
    - visualization_type: 可视化类型，支持 rule_processing_flow, attack_type_distribution, conflict_analysis
    - sessionId: 会话ID，用于确定文件存储的目录
    """
    try:
        # 可视化文件路径
        visualization_files = {
            "rule_processing_flow": "rule_processing_flow.html",
            "attack_type_distribution": "attack_type_distribution.html",
            "conflict_analysis": "conflict_analysis.html"
        }
        
        if visualization_type not in visualization_files:
            return JSONResponse(status_code=404, content={"success": False, "error": "无效的可视化类型"})
        
        # 获取会话目录
        session_dir = os.path.join(analysis_results_dir, sessionId)
        file_name = visualization_files[visualization_type]
        file_path = os.path.join(session_dir, file_name)
        
        if not os.path.exists(file_path):
            # 如果会话目录中没有文件，尝试从默认目录或Part2目录中复制
            default_file_path = os.path.join(analysis_results_dir, "default", file_name)
            if os.path.exists(default_file_path):
                import shutil
                shutil.copy(default_file_path, file_path)
            else:
                # 尝试从Part2目录中复制
                part2_visualization_path = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    'Part2 analysis',
                    'part2_rule_analysis',
                    '2.0',
                    'backend',
                    'analysis_results',
                    file_name
                )
                if os.path.exists(part2_visualization_path):
                    import shutil
                    shutil.copy(part2_visualization_path, file_path)
                else:
                    return JSONResponse(status_code=404, content={"success": False, "error": f"可视化文件 {file_name} 不存在"})
        
        return FileResponse(file_path, media_type="text/html")
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": f"获取可视化图像失败: {str(e)}"})

# 报告下载路由
@app.get("/api/waf/reports/{report_type}")
async def get_report(report_type: str, sessionId: str = "default"):
    """
    获取规则分析报告
    - report_type: 报告类型，目前支持 detailed_rules_report
    - sessionId: 会话ID，用于确定文件存储的目录
    """
    try:
        # 报告文件路径
        report_files = {
            "detailed_rules_report": "detailed_rules_report.md"
        }
        
        if report_type not in report_files:
            return JSONResponse(status_code=404, content={"success": False, "error": "无效的报告类型"})
        
        # 获取会话目录
        session_dir = os.path.join(analysis_results_dir, sessionId)
        file_name = report_files[report_type]
        file_path = os.path.join(session_dir, file_name)
        
        if not os.path.exists(file_path):
            # 如果会话目录中没有文件，尝试从默认目录或Part2目录中复制
            default_file_path = os.path.join(analysis_results_dir, "default", file_name)
            if os.path.exists(default_file_path):
                import shutil
                shutil.copy(default_file_path, file_path)
            else:
                # 尝试从Part2目录中复制
                part2_report_path = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    'Part2 analysis',
                    'part2_rule_analysis',
                    '2.0',
                    'backend',
                    'analysis_results',
                    file_name
                )
                if os.path.exists(part2_report_path):
                    import shutil
                    shutil.copy(part2_report_path, file_path)
                else:
                    return JSONResponse(status_code=404, content={"success": False, "error": f"报告文件 {file_name} 不存在"})
        
        return FileResponse(file_path, media_type="text/markdown", filename=file_name)
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": f"获取报告失败: {str(e)}"})

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000
    )
