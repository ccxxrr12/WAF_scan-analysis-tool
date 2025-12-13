// WAF API 类型定义

// WAF扫描请求类型
export interface ScanRequest {
  url: string;
}

// WAF扫描响应类型
export interface ScanResponse {
  success: boolean;
  data?: {
    url: string;
    detected: boolean;
    wafs: Array<{
      name: string;
      manufacturer: string;
      trigger_url: string;
    }>;
    request_count: number;
    knowledge_base: {
      generic: {
        found: boolean;
        reason: string;
      };
      wafname: string[];
    };
  };
  error?: string;
}

// AI检测请求类型
export interface AIDetectRequest {
  url: string;
  request_content: string;
}

// AI检测响应类型
export interface AIDetectResponse {
  success: boolean;
  data?: {
    url: string;
    prediction: string;
    confidence: number;
    request_content: string;
  };
  error?: string;
}

// 规则分析响应类型
export interface AnalyzeRulesResponse {
  success: boolean;
  data?: {
    filename: string;
    rule_count: number;
    conflict_count: number;
    rules: Array<any>;
    conflicts: Array<any>;
  };
  error?: string;
}
