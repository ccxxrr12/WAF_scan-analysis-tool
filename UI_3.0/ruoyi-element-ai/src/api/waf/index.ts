import type { ScanRequest, ScanResponse, AIDetectRequest, AIDetectResponse, AnalyzeRulesResponse } from './types';
import { post } from '@/utils/request';

// WAF扫描
export const scanWaf = (data: ScanRequest) => post<ScanResponse>('/api/waf/scan', data);

// WAF规则分析
export const analyzeRules = (file: File) => {
  const formData = new FormData();
  formData.append('file', file);
  return post<AnalyzeRulesResponse>('/api/waf/analyze-rules', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
};

// WAF深度学习检测
export const aiDetect = (data: AIDetectRequest) => post<AIDetectResponse>('/api/waf/ai-detect', data);
