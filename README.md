# 漏洞验证平台

## 📖 项目简介

本项目是一个统一的Web应用安全漏洞验证平台，支持多种漏洞类型的演示和测试。

### 已支持的漏洞类型

| 漏洞类型 | 标识 | 描述 |
|---------|------|------|
| XXE (XML外部实体注入) | `xxe` | 通过Excel文件上传触发XML外部实体注入漏洞 |

### 什么是XXE漏洞？

XXE（XML External Entity）漏洞是一种Web安全漏洞，当应用程序解析用户提供的XML输入时，如果未正确配置XML解析器禁用外部实体，攻击者就可以构造恶意的XML内容来：

- 📄 **读取服务器敏感文件**（如配置文件、密码文件等）
- 🔗 **发起SSRF攻击**（访问内网服务）
- 💥 **导致拒绝服务（DoS）**
- ⚡ **在某些情况下执行远程代码**

## 🚀 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 生成测试文件

```bash
python create_malicious.py
```

这将创建恶意xlsx文件 `malicious_test.xlsx`，包含XXE攻击载荷。

### 3. 启动应用

```bash
python app.py
```

应用将在 `http://localhost:5000` 启动。

### 4. 进行测试

1. 打开浏览器访问 `http://localhost:5000`
2. 选择生成的恶意xlsx文件上传
3. 查看漏洞验证结果

## 📁 项目结构

```
KTVuln/
├── app.py                  # 主应用入口（统一平台）
├── create_malicious.py     # 测试文件生成器
├── requirements.txt        # Python依赖
├── README.md               # 项目说明文档
├── .gitignore              # Git忽略配置
└── vuln/                   # 漏洞验证模块目录
    ├── __init__.py         # 模块包
    └── xxe.py              # XXE漏洞验证模块
```

## 🔧 添加新漏洞模块

要添加新的漏洞验证模块，只需以下步骤：

### 1. 在 `vuln/` 目录下创建新模块

```python
# vuln/sqli.py
class SQLIVulnerabilityTool:
    name = "SQL注入验证"
    icon = "💉"
    category = "注入攻击"
    description = "..."
    accept = "SQL"
    accept_ext = ".sql"
    
    def verify(self, file_path):
        # 实现验证逻辑
        pass
```

### 2. 在主应用中注册模块

编辑 `app.py`，在 `VULN_TOOLS` 字典中添加：

```python
from vuln.sqli import SQLIVulnerabilityTool

VULN_TOOLS = {
    'xxe': XXEVulnerabilityTool(),
    'sqli': SQLIVulnerabilityTool(),  # 新增
}
```

### 3. 更新依赖

如果有新的依赖包，添加到 `requirements.txt` 中。

## 🧪 XXE漏洞详解

### 漏洞原理

.xlsx文件本质上是一个ZIP压缩包，内部包含多个XML文件：
- `xl/workbook.xml` - 工作簿结构
- `xl/worksheets/sheet1.xml` - 工作表数据
- `[Content_Types].xml` - 内容类型定义
- 等等...

当后端使用不安全的XML解析器处理这些文件时，就可能被注入恶意的外部实体。

### 攻击示例

恶意xlsx文件中的 `xl/workbook.xml` 包含：

```xml
<!DOCTYPE worksheet [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<workbook>
  ...
  <test>&xxe;</test>
</workbook>
```

当使用不安全的解析器时，`&xxe;` 会被替换为 `win.ini` 文件的内容。

## 🛡️ 防御措施

1. **禁用外部实体解析**
   ```python
   from defusedxml.lxml import fromstring
   tree = fromstring(xml_content)  # 自动阻止XXE
   ```

2. **使用安全的XML解析库**
   - Python: `defusedxml`
   - Java: `XMLConstants.FEATURE_SECURE_PROCESSING`
   - PHP: 不要使用 `LIBXML_NOENT`

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
