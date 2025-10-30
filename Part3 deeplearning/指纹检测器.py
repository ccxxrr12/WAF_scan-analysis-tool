# Part1_WAFFingerprint/lib/fingerprint_detector.py
# -*- coding: utf-8 -*-
"""
WAF指纹检测器主类
整合被动检测和主动探测功能
"""

import json
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime

from config import FingerprintConfig, ActiveProbeConfig
from feature_extractor import WAFFeatureExtractor
from ml_classifier import WAFClassifier

class WAFFingerprintDetector:
    """WAF指纹检测器主类"""
    
    def __init__(self, model_path: str = None):
        """
        初始化指纹检测器
        
        参数:
            model_path: 预训练模型路径
        """
        self.config = FingerprintConfig()
        self.probe_config = ActiveProbeConfig()
        self.feature_extractor = WAFFeatureExtractor()
        self.classifier = WAFClassifier()
        
        # 加载WAF指纹数据库
        self.fingerprint_db = self._load_fingerprint_db()
        
        # 加载模型（如果提供路径）
        if model_path:
            self.classifier.load_model(model_path)
    
    def _load_fingerprint_db(self) -> Dict[str, Any]:
        """
        加载WAF指纹数据库
        
        返回:
            指纹数据库字典
        """
        try:
            with open(self.config.FINGERPRINT_DB, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            print("警告: 指纹数据库文件未找到，使用空数据库")
            return {}
        except Exception as e:
            print(f"加载指纹数据库失败: {e}")
            return {}
    
    def passive_detection(self, target_url: str) -> Dict[str, Any]:
        """
        被动WAF检测
        
        参数:
            target_url: 目标URL
            
        返回:
            检测结果字典
        """
        try:
            # 发送正常请求收集信息
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(
                target_url, 
                headers=headers, 
                timeout=self.config.PROBE_TIMEOUT,
                verify=False
            )
            
            # 提取HTTP数据
            http_data = {
                'target_url': target_url,
                'headers': dict(response.headers),
                'cookies': dict(response.cookies),
                'response_text': response.text,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds()
            }
            
            # 使用机器学习分类器进行检测
            if self.classifier.is_trained:
                ml_result = self.classifier.predict(http_data)
            else:
                ml_result = {'error': '模型未训练'}
            
            # 基于规则的检测
            rule_based_result = self._rule_based_detection(http_data)
            
            return {
                'target_url': target_url,
                'detection_method': 'passive',
                'timestamp': datetime.now().isoformat(),
                'ml_detection': ml_result,
                'rule_based_detection': rule_based_result,
                'http_data': http_data
            }
            
        except requests.RequestException as e:
            return {
                'target_url': target_url,
                'error': f'请求失败: {str(e)}',
                'detection_method': 'passive'
            }
        except Exception as e:
            return {
                'target_url': target_url,
                'error': f'检测失败: {str(e)}',
                'detection_method': 'passive'
            }
    
    def active_detection(self, target_url: str) -> Dict[str, Any]:
        """
        主动WAF探测
        
        参数:
            target_url: 目标URL
            
        返回:
            探测结果字典
        """
        try:
            probe_results = []
            
            # 对每个恶意载荷进行探测
            for payload in self.probe_config.MALICIOUS_PAYLOADS[:3]:  # 限制探测数量
                for path in self.probe_config.TARGET_PATHS[:2]:      # 限制路径数量
                    probe_result = self._send_probe_request(target_url, path, payload)
                    probe_results.append(probe_result)
            
            # 提取探测特征
            http_data = {
                'target_url': target_url,
                'probe_results': probe_results
            }
            
            # 使用机器学习分类器进行检测
            if self.classifier.is_trained:
                ml_result = self.classifier.predict(http_data)
            else:
                ml_result = {'error': '模型未训练'}
            
            # 基于规则的检测
            rule_based_result = self._analyze_probe_results(probe_results)
            
            return {
                'target_url': target_url,
                'detection_method': 'active',
                'timestamp': datetime.now().isoformat(),
                'ml_detection': ml_result,
                'rule_based_detection': rule_based_result,
                'probe_results': probe_results
            }
            
        except Exception as e:
            return {
                'target_url': target_url,
                'error': f'主动探测失败: {str(e)}',
                'detection_method': 'active'
            }
    
    def comprehensive_detection(self, target_url: str) -> Dict[str, Any]:
        """
        综合WAF检测（被动+主动）
        
        参数:
            target_url: 目标URL
            
        返回:
            综合检测结果字典
        """
        # 执行被动检测
        passive_result = self.passive_detection(target_url)
        
        # 执行主动检测
        active_result = self.active_detection(target_url)
        
        # 合并结果
        comprehensive_result = {
            'target_url': target_url,
            'detection_method': 'comprehensive',
            'timestamp': datetime.now().isoformat(),
            'passive_detection': passive_result,
            'active_detection': active_result
        }
        
        # 生成最终结论
        comprehensive_result['final_conclusion'] = self._generate_final_conclusion(
            passive_result, 
            active_result
        )
        
        return comprehensive_result
    
    def _send_probe_request(self, base_url: str, path: str, payload: str) -> Dict[str, Any]:
        """
        发送探测请求
        
        参数:
            base_url: 基础URL
            path: 请求路径
            payload: 恶意载荷
            
        返回:
            探测结果字典
        """
        try:
            target_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            # 发送包含恶意载荷的请求
            data = {'input': payload, 'search': payload}
            
            response = requests.post(
                target_url,
                data=data,
                headers=headers,
                timeout=self.config.PROBE_TIMEOUT,
                verify=False
            )
            
            return {
                'url': target_url,
                'payload': payload,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'response_text': response.text[:500],  # 限制响应文本长度
                'response_time': response.elapsed.total_seconds(),
                'blocked': response.status_code in [403, 406, 418, 429]
            }
            
        except requests.RequestException as e:
            return {
                'url': target_url,
                'payload': payload,
                'error': str(e),
                'blocked': False
            }
    
    def _rule_based_detection(self, http_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        基于规则的WAF检测
        
        参数:
            http_data: HTTP数据字典
            
        返回:
            规则检测结果字典
        """
        result = {
            'detected_wafs': [],
            'confidence': 0.0,
            'evidence': []
        }
        
        headers = http_data.get('headers', {})
        response_text = http_data.get('response_text', '')
        
        # 检查Cloudflare特征
        if any('cloudflare' in key.lower() for key in headers.keys()):
            result['detected_wafs'].append('Cloudflare')
            result['evidence'].append('发现Cloudflare相关HTTP头部')
            result['confidence'] = max(result['confidence'], 0.8)
        
        if 'cf-ray' in headers:
            result['detected_wafs'].append('Cloudflare')
            result['evidence'].append('发现CF-Ray头部')
            result['confidence'] = max(result['confidence'], 0.9)
        
        # 检查AWS WAF特征
        if 'aws' in response_text.lower() and 'waf' in response_text.lower():
            result['detected_wafs'].append('AWS WAF')
            result['evidence'].append('响应内容包含AWS WAF标识')
            result['confidence'] = max(result['confidence'], 0.7)
        
        # 检查Imperva特征
        if 'imperva' in response_text.lower():
            result['detected_wafs'].append('Imperva')
            result['evidence'].append('响应内容包含Imperva标识')
            result['confidence'] = max(result['confidence'], 0.8)
        
        # 去重
        result['detected_wafs'] = list(set(result['detected_wafs']))
        
        return result
    
    def _analyze_probe_results(self, probe_results: List[Dict]) -> Dict[str, Any]:
        """
        分析主动探测结果
        
        参数:
            probe_results: 探测结果列表
            
        返回:
            分析结果字典
        """
        result = {
            'detected_wafs': [],
            'block_ratio': 0.0,
            'evidence': []
        }
        
        if not probe_results:
            return result
        
        # 计算拦截比率
        blocked_count = sum(1 for r in probe_results if r.get('blocked', False))
        result['block_ratio'] = blocked_count / len(probe_results)
        
        # 基于拦截模式判断WAF类型
        if result['block_ratio'] > 0.7:
            # 高拦截率，可能是Cloudflare或AWS WAF
            result['detected_wafs'].extend(['Cloudflare', 'AWS WAF', 'Imperva'])
            result['evidence'].append('高恶意请求拦截率')
        
        # 检查特定响应模式
        for probe in probe_results:
            response_text = probe.get('response_text', '').lower()
            
            if 'cloudflare' in response_text:
                result['detected_wafs'].append('Cloudflare')
                result['evidence'].append('探测响应包含Cloudflare标识')
            
            if 'aws' in response_text and 'waf' in response_text:
                result['detected_wafs'].append('AWS WAF')
                result['evidence'].append('探测响应包含AWS WAF标识')
        
        # 去重
        result['detected_wafs'] = list(set(result['detected_wafs']))
        
        return result
    
    def _generate_final_conclusion(self, passive_result: Dict, active_result: Dict) -> Dict[str, Any]:
        """
        生成最终检测结论
        
        参数:
            passive_result: 被动检测结果
            active_result: 主动检测结果
            
        返回:
            最终结论字典
        """
        conclusion = {
            'waf_detected': False,
            'detected_wafs': [],
            'overall_confidence': 0.0,
            'recommendation': ''
        }
        
        # 收集所有检测到的WAF
        detected_wafs = set()
        
        # 从被动检测收集
        passive_wafs = passive_result.get('rule_based_detection', {}).get('detected_wafs', [])
        detected_wafs.update(passive_wafs)
        
        # 从主动检测收集
        active_wafs = active_result.get('rule_based_detection', {}).get('detected_wafs', [])
        detected_wafs.update(active_wafs)
        
        # 从机器学习检测收集
        ml_passive = passive_result.get('ml_detection', {})
        if ml_passive.get('is_detected', False) and ml_passive.get('waf_type') != 'Unknown':
            detected_wafs.add(ml_passive['waf_type'])
        
        ml_active = active_result.get('ml_detection', {})
        if ml_active.get('is_detected', False) and ml_active.get('waf_type') != 'Unknown':
            detected_wafs.add(ml_active['waf_type'])
        
        conclusion['detected_wafs'] = list(detected_wafs)
        conclusion['waf_detected'] = len(detected_wafs) > 0
        
        # 计算总体置信度
        confidences = []
        if ml_passive.get('confidence'):
            confidences.append(ml_passive['confidence'])
        if ml_active.get('confidence'):
            confidences.append(ml_active['confidence'])
        
        if confidences:
            conclusion['overall_confidence'] = np.mean(confidences)
        
        # 生成建议
        if conclusion['waf_detected']:
            conclusion['recommendation'] = f"检测到WAF: {', '.join(conclusion['detected_wafs'])}。建议针对特定WAF调整渗透测试策略。"
        else:
            conclusion['recommendation'] = "未检测到明显的WAF防护。目标可能没有WAF或使用未知的WAF解决方案。"
        
        return conclusion