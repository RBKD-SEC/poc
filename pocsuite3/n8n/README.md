# n8n PoCs

n8n 工作流自动化平台的漏洞验证 PoC，pocsuite3 格式。

## 文件清单

| 文件 | 漏洞编号 | 类型 | 说明 |
|------|---------|------|------|
| `cve_2026_21858_lfi_poc.py` | CVE-2026-21858 | LFI (任意文件读取) | 通过表单上传端点的路径遍历读取服务器任意文件 |
| `cve_2026_21858_rce_poc.py` | CVE-2026-21858 + CVE-2025-68613 | 全链 RCE | 组合利用：文件读取 → Admin Token 伪造 → 沙箱绕过 → RCE |

## 用法

```bash
# 验证模式
pocsuite3 -r cve_2026_21858_lfi_poc.py -u http://<target>

# 攻击模式（RCE PoC）
pocsuite3 -r cve_2026_21858_rce_poc.py -u http://<target> --attack
```

## 参考

- https://github.com/Chocapikk/CVE-2026-21858
