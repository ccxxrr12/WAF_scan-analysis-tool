from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn
import os
import sys

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

# 健康检查路由
@app.get("/health")
async def health_check():
    return {"status": "ok", "message": "WAF Analysis API is running"}

# 导入Part1集成模块
from part1_integration import scan_waf as part1_scan

# Part1: WAF扫描路由
@app.post("/api/waf/scan")
async def scan_waf(request: ScanRequest):
    """扫描指定URL的WAF类型"""
    try:
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
async def ai_detect(request: AIDetectRequest):
    """使用深度学习检测WAF"""
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
async def analyze_rules(files: list[UploadFile] = File(...)):
    """
    接收前端上传的规则文件，解析并插入到数据库
    - 支持的文件格式：.conf, .txt, .rules
    - 保持数据库不变，只插入新数据，相同id的规则会被更新
    - 支持多个文件同时上传
    """
    try:
        # 检查是否有文件上传
        if not files:
            raise HTTPException(status_code=400, detail="未上传任何文件")
        
        all_results = {
            "success": True,
            "message": "规则分析成功",
            "data": {
                "files": [],
                "total_rules": 0
            }
        }
        
        total_rules = 0
        
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
            else:
                # 如果有任何一个文件失败，整个请求失败
                all_results["success"] = False
                all_results["message"] = f"部分文件分析失败: {result['error']}"
        
        all_results["data"]["total_rules"] = total_rules
        
        if all_results["success"]:
            return JSONResponse(status_code=200, content=all_results)
        else:
            return JSONResponse(status_code=400, content=all_results)
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"规则分析失败: {str(e)}")

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

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000
    )
