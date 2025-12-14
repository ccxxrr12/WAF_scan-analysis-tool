import requests
import os

# 测试API的URL
url = "http://localhost:8000/api/waf/analyze-rules"

# 测试文件路径列表
test_file_paths = [
    r"d:\github\Repository\WAF_scan-analysis-tool\Part2 analysis\part2_rule_analysis\2.0\rules\REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
    r"d:\github\Repository\WAF_scan-analysis-tool\Part2 analysis\part2_rule_analysis\2.0\rules\REQUEST-911-METHOD-ENFORCEMENT.conf"
]

# 检查文件是否存在
for file_path in test_file_paths:
    if not os.path.exists(file_path):
        print(f"测试文件不存在: {file_path}")
        exit(1)

# 准备要上传的文件
files_to_upload = []
for file_path in test_file_paths:
    files_to_upload.append(('files', open(file_path, 'rb')))

# 发送POST请求
print(f"正在测试API: {url}")
print(f"测试文件: {[os.path.basename(f) for f in test_file_paths]}")
response = requests.post(url, files=files_to_upload)

# 关闭文件
for file_tuple in files_to_upload:
    file_tuple[1].close()
    
print(f"\n响应状态码: {response.status_code}")
print(f"响应内容: {response.text}")
