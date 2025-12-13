from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn
import os
import sys

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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

# 导入Part2集成模块
from part2_integration import analyze_rules_file as part2_analyze

# Part2: 规则分析路由
@app.post("/api/waf/analyze-rules")
async def analyze_rules(file: UploadFile = File(...)):
    """分析上传的WAF规则文件"""
    try:
        # 读取文件内容
        file_content = await file.read()
        # 调用Part2的分析函数
        result = part2_analyze(file_content, file.filename)
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}

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

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000
    )
