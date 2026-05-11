# RuoYi SQL Injection PoC

CVE-2023-49371 — 若依 (RuoYi) 系统 SQL 注入漏洞。

## 说明

通过 pocsuite3 框架利用若依系统的 SQL 注入漏洞。支持 `extractvalue`、`updatexml`、时间盲注等多种注入方式。

## 用法

```bash
# 验证（需登录 Cookie）
pocsuite3 -r CVE-2023-49371.py -u http://<target> --verify --acookie "JSESSIONID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

## 注意

- 此 PoC 需要有效的登录 Session（JSESSIONID）
- 仅用于授权测试
