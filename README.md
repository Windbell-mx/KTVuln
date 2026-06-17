# XXE漏洞验证工具

## 📖 项目简介

本项目用于演示和验证通过Excel文件（.xlsx）上传触发的XXE（XML External Entity）漏洞。

### 什么是XXE漏洞？

XXE（XML外部实体）漏洞是一种Web安全漏洞，当应用程序解析用户提供的XML输入时，如果未正确配置XML解析器禁用外部实体，攻击者就可以构造恶意的XML内容来：

- 📄 **读取服务器敏感文件**（如配置文件、密码文件等）
- 🔗 **发起SSRF攻击**（访问内网服务）
- 💥 **导致拒绝服务（DoS）**
- ⚡ **在某些情况下执行远程代码**

### 为什么Excel文件会触发XXE？

.xlsx文件本质上是一个ZIP压缩包，内部包含多个XML文件：
- `xl/worksheets/sheet1.xml` - 工作表数据
- `xl/workbook.xml` - 工作簿结构
- `[Content_Types].xml` - 内容类型定义
- 等等...

当后端使用不安全的XML解析器处理这些文件时，就可能被注入恶意的外部实体。

## 🚀 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 生成测试文件

```bash
python create_malicious.py
```

这将创建两个测试文件：
- `malicious_test.xlsx` - 文件读取型XXE测试
- `ssrf_test.xlsx` - SSRF型XXE测试

### 3. 启动应用

```bash
python app.py
```

应用将在 `http://localhost:5000` 启动。

### 4. 进行测试

1. 打开浏览器访问 `http://localhost:5000`
2. 选择生成的恶意xlsx文件上传
3. 分别测试"漏洞版本"和"安全版本"

## 📁 项目结构

```
xxevuln/
├── app.py                  # Flask Web应用（包含漏洞和安全两种解析方式）
├── create_malicious.py     # 恶意xlsx文件生成器
├── requirements.txt        # Python依赖
├── README.md               # 项目说明文档
├── malicious_test.xlsx     # XXE文件读取测试文件（自动生成）
├── ssrf_test.xlsx          # SSRF测试文件（自动生成）
└── uploads/                # 临时上传目录（自动创建）
```

## 🔍 代码说明

### 漏洞版本 (`parse_excel_vulnerable`)

```python
# 不安全的XML解析 - 允许外部实体
parser = ET.XMLParser()
tree = ET.fromstring(xml_content)
```

这种配置下，XML解析器会尝试解析和加载外部实体声明，导致XXE漏洞。

### 安全版本 (`parse_excel_secure`)

```python
# 安全的XML解析 - 禁止外部实体
parser = ET.XMLParser(resolve_entities=False, forbid_external=True)
tree = ET.fromstring(xml_content, parser)
```

通过禁用实体解析和外部实体访问，可以有效防止XXE攻击。

## 🧪 测试场景

### 场景1: 文件读取（Local File Inclusion）

恶意xlsx文件中的外部实体尝试读取服务器文件：

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

在漏洞版本中，解析器会尝试读取该文件内容并返回。

### 场景2: SSRF（Server-Side Request Forgery）

恶意xlsx文件中的外部实体尝试访问内网服务：

```xml
<!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">
```

在漏洞版本中，解析器会尝试访问该URL。

## 🛡️ 如何防御XXE攻击

1. **禁用外部实体解析**
   ```python
   parser = ET.XMLParser(resolve_entities=False, forbid_external=True)
   ```

2. **使用安全的XML解析库**
   - Python: `lxml` with security options
   - Java: `XMLConstants.FEATURE_SECURE_PROCESSING`
   - PHP: `LIBXML_NOENT` 不要使用

3. **输入验证和过滤**
   - 验证文件类型和内容
   -  sanitization用户输入

4. **最小权限原则**
   - 限制XML解析器的文件系统访问
   - 网络访问控制

## ⚠️ 免责声明

本项目仅用于**安全教育和渗透测试练习**。请勿将此类技术用于非法用途。

- ✅ 合法用途：学习安全知识、渗透测试（获得授权）、安全研究
- ❌ 非法用途：未经授权的系统攻击、数据窃取

## 📚 参考资料

- [OWASP XXE Injection](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- [Python XML Processing Security](https://docs.python.org/3/library/xml.html)
