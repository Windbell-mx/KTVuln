"""
XXE漏洞验证工具 - Excel文件上传
演示如何通过构造恶意的xlsx文件（XML内部实体注入）触发XXE漏洞
"""

import os
import zipfile
import xml.etree.ElementTree as ET
from io import BytesIO
from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)

# 配置
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'xlsx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 最大16MB

# 确保上传目录存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    """检查文件扩展名是否允许"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def parse_excel_vulnerable(file_path):
    """
    【漏洞版本】使用不安全的XML解析器，容易受到XXE攻击
    xlsx文件本质上是ZIP压缩包，包含多个XML文件
    """
    try:
        # xlsx文件是ZIP格式，读取其中的XML内容
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            # 获取所有XML文件
            xml_files = [name for name in zip_ref.namelist() if name.endswith('.xml')]
            
            results = {}
            errors = {}
            for xml_file in xml_files:
                # 读取XML内容
                xml_content = zip_ref.read(xml_file)
                
                # 【漏洞点】使用lxml库，默认允许外部实体解析
                try:
                    from lxml import etree
                    # 创建不安全的解析器 - 允许DTD和外部实体
                    # 关键配置：resolve_entities=True 允许解析实体引用
                    # no_network=False 允许访问网络和本地文件
                    parser = etree.XMLParser(
                        load_dtd=True,
                        dtd_validation=False,
                        resolve_entities=True,
                        no_network=False,
                        recover='ignore'
                    )
                    tree = etree.fromstring(xml_content, parser)
                    results[xml_file] = etree.tostring(tree, encoding='unicode', pretty_print=True)[:2000]
                except ImportError:
                    # 如果没有lxml，使用标准库的ET
                    try:
                        tree = ET.fromstring(xml_content)
                        results[xml_file] = ET.tostring(tree, encoding='unicode')[:2000]
                    except ET.ParseError as e:
                        errors[xml_file] = str(e)
                except Exception as e:
                    errors[xml_file] = str(e)
            
            return {
                'parsed': results,
                'errors': errors,
                'note': '使用lxml解析器，默认允许外部实体加载。如果XML中包含有效的外部实体声明，将会读取文件内容。'
            }, None
            
    except Exception as e:
        return None, str(e)


def parse_excel_secure(file_path):
    """
    【安全版本】使用安全的XML解析器，禁用外部实体
    """
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            xml_files = [name for name in zip_ref.namelist() if name.endswith('.xml')]
            
            results = {}
            for xml_file in xml_files:
                xml_content = zip_ref.read(xml_file)
                
                # 【安全修复】使用defusedxml库，该库专门设计用于安全地解析不受信任的XML输入
                try:
                    from defusedxml.lxml import fromstring as defused_fromstring
                    tree = defused_fromstring(xml_content)
                    from lxml import etree
                    results[xml_file] = etree.tostring(tree, encoding='unicode', pretty_print=True)[:2000]
                except Exception as e:
                    results[xml_file] = f"[Blocked by defusedxml] {str(e)}"
            
            return results, None
            
    except Exception as e:
        return None, str(e)


@app.route('/')
def index():
    """主页 - 显示使用说明"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>XXE漏洞验证工具</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
            h1 { color: #333; }
            .vulnerable { color: #d32f2f; background: #ffebee; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .secure { color: #388e3c; background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 20px 0; }
            button { background: #1976d2; color: white; border: none; padding: 10px 20px; 
                     border-radius: 5px; cursor: pointer; margin: 5px; }
            button:hover { background: #1565c0; }
            .upload-area { border: 2px dashed #ccc; padding: 40px; text-align: center; margin: 20px 0; }
            pre { background: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto; }
        </style>
    </head>
    <body>
        <h1>🔓 XXE漏洞验证工具</h1>
        <p>本项目用于演示和验证通过Excel文件上传触发的XXE（XML External Entity）漏洞。</p>
        
        <div class="vulnerable">
            <h2>⚠️ 漏洞版本</h2>
            <p>使用不安全的XML解析器，可以解析恶意构造的外部实体。</p>
            <form action="/upload/vulnerable" method="post" enctype="multipart/form-data" class="upload-area">
                <p>选择xlsx文件上传：</p>
                <input type="file" name="file" accept=".xlsx" required>
                <br><br>
                <button type="submit">上传并测试（漏洞版本）</button>
            </form>
        </div>
        
        <div class="secure">
            <h2>✅ 安全版本</h2>
            <p>使用安全的XML解析器，禁用外部实体解析。</p>
            <form action="/upload/secure" method="post" enctype="multipart/form-data" class="upload-area">
                <p>选择xlsx文件上传：</p>
                <input type="file" name="file" accept=".xlsx" required>
                <br><br>
                <button type="submit">上传并测试（安全版本）</button>
            </form>
        </div>
        
        <h2>📖 关于XXE攻击</h2>
        <p>XXE（XML External Entity）攻击是一种针对XML解析器的攻击方式。当应用配置不当，允许解析外部实体时，攻击者可以：</p>
        <ul>
            <li>读取服务器上的敏感文件</li>
            <li>发起SSRF（服务器端请求伪造）攻击</li>
            <li>导致拒绝服务（DoS）</li>
            <li>在某些情况下执行远程代码</li>
        </ul>
        
        <h2>🧪 测试说明</h2>
        <p>项目包含两个恶意构造的xlsx文件示例：</p>
        <ul>
            <li><code>malicious_test.xlsx</code> - 尝试读取系统文件（/etc/passwd 或 C:\\Windows\\system.ini）</li>
            <li><code>ssrf_test.xlsx</code> - 尝试访问内网服务（SSRF攻击）</li>
        </ul>
        <p>这些文件在XML内容中注入了外部实体，尝试读取服务器上的文件或访问内网服务。</p>
        
        <h2>📁 项目结构</h2>
        <pre>
xxevuln/
├── app.py              # Flask应用主文件
├── malicious_test.xlsx # 恶意测试文件（已包含）
├── create_malicious.py # 生成恶意xlsx文件的脚本
├── uploads/            # 上传文件目录（自动创建）
└── requirements.txt    # 依赖包列表
        </pre>
    </body>
    </html>
    '''


@app.route('/upload/vulnerable', methods=['POST'])
def upload_vulnerable():
    """上传文件并使用漏洞版本的解析器"""
    if 'file' not in request.files:
        return jsonify({'error': '没有选择文件'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '没有选择文件'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': '只支持xlsx文件'}), 400
    
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    
    # 使用漏洞版本的解析器
    results, error = parse_excel_vulnerable(file_path)
    
    # 清理上传的文件
    if os.path.exists(file_path):
        os.remove(file_path)
    
    if error:
        return jsonify({
            'status': 'error',
            'parser': 'vulnerable',
            'message': error
        }), 500
    
    return jsonify({
        'status': 'success',
        'parser': 'vulnerable',
        'filename': filename,
        'results': results.get('parsed', {}),
        'errors': results.get('errors', {}),
        'note': results.get('note', ''),
        'explanation': '漏洞版本：使用lxml解析器，默认允许DTD和外部实体加载。如果XML中包含外部实体声明（如&xxe;），解析器会尝试读取指定文件的内容并替换实体引用。成功读取的文件内容将显示在results中。'
    })


@app.route('/upload/secure', methods=['POST'])
def upload_secure():
    """上传文件并使用安全版本的解析器"""
    if 'file' not in request.files:
        return jsonify({'error': '没有选择文件'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '没有选择文件'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': '只支持xlsx文件'}), 400
    
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    
    # 使用安全版本的解析器
    results, error = parse_excel_secure(file_path)
    
    # 清理上传的文件
    if os.path.exists(file_path):
        os.remove(file_path)
    
    if error:
        return jsonify({
            'status': 'error',
            'parser': 'secure',
            'message': error
        }), 500
    
    return jsonify({
        'status': 'success',
        'parser': 'secure',
        'filename': filename,
        'results': results,
        'explanation': '安全版本：使用defusedxml库，该库专门设计用于安全地解析不受信任的XML输入，会自动阻止外部实体解析和XXE攻击。'
    })


if __name__ == '__main__':
    print("=" * 60)
    print("XXE漏洞验证工具已启动")
    print("请访问: http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)
