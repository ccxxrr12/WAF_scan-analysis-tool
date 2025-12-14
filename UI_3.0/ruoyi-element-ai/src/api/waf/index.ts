import type { ScanRequest, ScanResponse, AIDetectRequest, AIDetectResponse, AnalyzeRulesResponse } from './types';
import { post } from '@/utils/request';

// WAF扫描
export const scanWaf = (data: ScanRequest) => post<ScanResponse>('/api/waf/scan', data);

// WAF规则分析
export const analyzeRules = async (files: File[]): Promise<AnalyzeRulesResponse> => {
  const formData = new FormData();
  
  // 添加所有文件到FormData
  for (const file of files) {
    formData.append('files', file);
  }
  
  // 使用原生fetch API发送文件上传请求
  const response = await fetch(import.meta.env.VITE_API_URL + '/api/waf/analyze-rules', {
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
export const aiDetect = (data: AIDetectRequest) => post<AIDetectResponse>('/api/waf/ai-detect', data);
