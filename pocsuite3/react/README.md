# React Server Components PoC

CVE-2025-55182 — React Server Components 远程代码执行漏洞。

## 说明

React Server Components 中的一个严重漏洞，允许未经身份验证的远程代码执行。

参考：Assetnote, maple3142, Facebook Security research

## 用法

```bash
pocsuite3 -r CVE-2025-55182.py -u http://<target>
pocsuite3 -r CVE-2025-55182.py -u http://<target> --attack
```
