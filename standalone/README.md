# 独立运行脚本

本目录存放不依赖 pocsuite3 框架、可直接 `python3` 运行的漏洞利用/扫描脚本。

## 目录结构

```
standalone/
├── 1panel/
│   ├── CVE-2025-54424.py    # 1Panel 客户端证书绕过 RCE
│   └── README.md            # 漏洞详细说明
└── ruoyi/
    └── CVE-2023-49371.py    # RuoYi 漏洞
```

## 使用方式

每个产品目录下均有独立的 `README.md`，包含漏洞原理、影响版本、使用说明。

### 1Panel RCE (CVE-2025-54424)

```bash
cd standalone/1panel
pip install websocket-client cryptography PySocks requests

# 单点利用
python3 CVE-2025-54424.py -u <target>:9999

# 批量扫描
python3 CVE-2025-54424.py -f targets.txt -t 20 -o result.txt
```

## 编写规范

1. **文件头部注释**必须包含：CVE 编号、漏洞简述、作者、依赖安装命令
2. **必须支持命令行参数**（推荐 `argparse`）
3. **目录内附 README.md**，包含漏洞简介、影响版本、使用示例
4. **禁止硬编码敏感信息**（密钥、Token、内网地址等）
