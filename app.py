"""
漏洞验证平台 - 统一入口
支持多种漏洞类型的验证工具
"""

import os
import sys
from flask import Flask, request, jsonify, render_template_string
from werkzeug.utils import secure_filename

# 导入各个漏洞验证模块
from vuln_xxe import XXEVulnerabilityTool
# 未来可以添加更多漏洞模块
# from vuln_sqli import SQLIVulnerabilityTool
# from vuln_xss import XSSVulnerabilityTool

app = Flask(__name__)

# 配置
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'xlsx', 'xml', 'json', 'html', 'sql'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 最大16MB

# 确保上传目录存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 注册所有漏洞验证工具
VULN_TOOLS = {
    'xxe': XXEVulnerabilityTool(),
    # 'sqli': SQLIVulnerabilityTool(),
    # 'xss': XSSVulnerabilityTool(),
}


def allowed_file(filename):
    """检查文件扩展名是否允许"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# HTML模板
INDEX_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>漏洞验证平台</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { font-size: 2em; margin-bottom: 10px; }
        .container { max-width: 1200px; margin: 30px auto; padding: 0 20px; }
        .vuln-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 20px; }
        .vuln-card { background: white; border-radius: 10px; padding: 25px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .vuln-card h2 { color: #333; margin-bottom: 15px; display: flex; align-items: center; gap: 10px; }
        .vuln-card p { color: #666; margin-bottom: 20px; line-height: 1.6; }
        .upload-area { border: 2px dashed #ddd; border-radius: 8px; padding: 20px; text-align: center; margin-bottom: 15px; }
        .upload-area:hover { border-color: #667eea; background: #f8f9ff; }
        input[type="file"] { margin-bottom: 10px; }
        button { background: #667eea; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-size: 14px; }
        button:hover { background: #5568d3; }
        .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; }
        .badge-xml { background: #fff3cd; color: #856404; }
        .badge-high { background: #f8d7da; color: #721c24; }
        .footer { text-align: center; padding: 20px; color: #999; margin-top: 40px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ 漏洞验证平台</h1>
        <p>Web应用安全漏洞验证与演示工具集</p>
    </div>
    <div class="container">
        <div class="vuln-grid">
            {% for key, tool in tools.items() %}
            <div class="vuln-card">
                <h2>{{ tool.icon }} {{ tool.name }} <span class="badge badge-xml">{{ tool.category }}</span></h2>
                <p>{{ tool.description }}</p>
                <form action="/upload/{{ key }}" method="post" enctype="multipart/form-data">
                    <div class="upload-area">
                        <p>选择{{ tool.accept }}文件上传：</p>
                        <input type="file" name="file" accept="{{ tool.accept_ext }}" required>
                        <br><br>
                        <button type="submit">上传并验证</button>
                    </div>
                </form>
            </div>
            {% endfor %}
        </div>
        <div class="footer">
            <p>⚠️ 本工具仅用于安全教育和授权测试 | 请勿用于非法用途</p>
        </div>
    </div>
</body>
</html>
'''


@app.route('/')
def index():
    """主页 - 显示所有漏洞验证工具"""
    return render_template_string(INDEX_TEMPLATE, tools=VULN_TOOLS)


@app.route('/upload/<vuln_type>', methods=['POST'])
def upload(vuln_type):
    """通用上传接口"""
    if vuln_type not in VULN_TOOLS:
        return jsonify({'error': '不支持的漏洞类型'}), 404
    
    if 'file' not in request.files:
        return jsonify({'error': '没有选择文件'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '没有选择文件'}), 400
    
    tool = VULN_TOOLS[vuln_type]
    
    # 检查文件扩展名
    if not allowed_file(file.filename):
        return jsonify({'error': f'只支持{tool.accept_ext}文件'}), 400
    
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{vuln_type}_{filename}")
    file.save(file_path)
    
    try:
        # 调用漏洞工具的验证方法
        result = tool.verify(file_path)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
    finally:
        # 清理上传的文件
        if os.path.exists(file_path):
            os.remove(file_path)


if __name__ == '__main__':
    print("=" * 60)
    print("🛡️ 漏洞验证平台已启动")
    print(f"📋 已加载 {len(VULN_TOOLS)} 个漏洞验证工具:")
    for key, tool in VULN_TOOLS.items():
        print(f"   - {tool.name} ({key})")
    print("=" * 60)
    print("请访问: http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)
