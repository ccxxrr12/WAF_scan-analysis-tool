import type { ScanRequest, ScanResponse, AIDetectRequest, AIDetectResponse, AnalyzeRulesResponse } from './types';
import { post } from '@/utils/request';

// WAF扫描
export const scanWaf = (data: ScanRequest, sessionId?: string) => {
  const url = sessionId ? `/api/waf/scan?sessionId=${sessionId}` : '/api/waf/scan';
  return post<ScanResponse>(url, data);
};

// WAF规则分析
export const analyzeRules = async (files: File[], sessionId: string): Promise<AnalyzeRulesResponse> => {
  const formData = new FormData();
  
  // 添加所有文件到FormData
  for (const file of files) {
    formData.append('files', file);
  }
  
  // 使用原生fetch API发送文件上传请求，添加sessionId参数
  const response = await fetch(`${import.meta.env.VITE_API_URL}/api/waf/analyze-rules?sessionId=${sessionId}`, {
    method: 'POST',
    body: formData,
    headers: {
      // 不要手动设置Content-Type，浏览器会自动处理
    },
  });
  
  // 解析响应
  return response.json();
};

// WAF深度学习检测
export const aiDetect = (data: AIDetectRequest, sessionId?: string) => {
  const url = sessionId ? `/api/waf/ai-detect?sessionId=${sessionId}` : '/api/waf/ai-detect';
  return post<AIDetectResponse>(url, data);
};
