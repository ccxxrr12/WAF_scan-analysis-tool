import sys
import os
import json
from typing import Dict, Any

# 添加Part3目录到Python路径
part3_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Part3 deeplearning', 'part3_waf_ml')
sys.path.insert(0, part3_path)

# 导入Part3的主要功能模块
try:
    from predictor import Predictor
except ImportError as e:
    print(f"导入Part3模块时出错: {e}")
    # 定义一个占位符类，以便在导入失败时仍能运行
    class Predictor:
        def __init__(self):
            pass
        
        def load_model(self, model_path, waf_type):
            pass
        
        def predict(self, sample_request, waf_info=None):
            return "unknown", 0.0

def ai_detect(url: str, request_content: str, waf_info: dict = None) -> Dict[str, Any]:
    """
    使用深度学习检测WAF
    
    Args:
        url: 目标URL
        request_content: 请求内容
        waf_info: WAF指纹信息（可选）
        
    Returns:
        包含检测结果的字典
    """
    try:
        # 初始化预测器
        predictor = Predictor()
        
        # 尝试加载默认模型
        try:
            # 检查默认模型文件是否存在
            part3_root = os.path.dirname(part3_path)
            model_dir = os.path.join(part3_root, "models")
            modsecurity_model = os.path.join(model_dir, "modsecurity_model.pkl")
            generic_model = os.path.join(model_dir, "generic_model.pkl")
            
            # 加载可用的模型
            if os.path.exists(modsecurity_model):
                predictor.load_model(modsecurity_model, "modsecurity")
            if os.path.exists(generic_model):
                predictor.load_model(generic_model, "generic")
        except Exception as e:
            print(f"加载模型时出错: {e}")
            # 模型加载失败不影响程序运行，继续执行
        
        # 构建预测所需的样本请求
        sample_request = {
            "request": request_content,
            "response_status": 200  # 默认响应状态码
        }
        
        # 进行预测
        prediction, confidence = predictor.predict(sample_request, waf_info)
        
        # 构建最终结果
        final_result = {
            "url": url,
            "prediction": prediction,
            "confidence": float(confidence),
            "request_content": request_content
        }
        
        return {
            "success": True,
            "data": final_result
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

# 测试函数
if __name__ == "__main__":
    # 测试代码
    test_url = "https://example.com"
    test_request = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    result = ai_detect(test_url, test_request)
    print(f"AI检测结果: {json.dumps(result, indent=2, ensure_ascii=False)}")
