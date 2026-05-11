# pocsuite3 格式 PoC

本目录存放符合 [pocsuite3](https://github.com/knownsec/pocsuite3) 框架规范的 PoC 脚本。

## 目录结构

```
pocsuite3/
├── n8n/
│   ├── cve_2026_21858_lfi_poc.py
│   └── cve_2026_21858_rce_poc.py
└── react/
    └── CVE-2025-55182.py
```

## 使用方式

```bash
# 验证漏洞是否存在
pocsuite3 -r pocsuite3/n8n/cve_2026_21858_rce_poc.py -u http://<target>

# 批量扫描
pocsuite3 -r pocsuite3/n8n/cve_2026_21858_rce_poc.py -f targets.txt

# 攻击模式（反弹 shell）
pocsuite3 -r pocsuite3/n8n/cve_2026_21858_rce_poc.py -u http://<target> --attack
```

## 编写规范

每个 PoC 必须包含：

1. **`pocInfo`** 字典：name, vulID, author, vulType, references
2. **`_verify()`** 方法：仅验证漏洞是否存在，不执行破坏操作
3. **`_attack()`** 方法：执行利用（如命令执行、反弹 shell）
4. **`register_poc()`** 调用：注册到 pocsuite3 框架

示例模板：

```python
from pocsuite3.api import Output, POCBase, register_poc, requests, logger, VUL_TYPE

class DemoPOC(POCBase):
    pocInfo = {
        'name': 'CVE-XXXX-XXXXX 产品名 漏洞类型',
        'vulID': 'CVE-XXXX-XXXXX',
        'author': 'your-name',
        'vulType': VUL_TYPE.CODE_EXECUTION,
        'references': ['https://example.com/advisory'],
    }

    def _verify(self):
        # 验证逻辑
        pass

    def _attack(self):
        # 利用逻辑
        pass

register_poc(DemoPOC)
```
