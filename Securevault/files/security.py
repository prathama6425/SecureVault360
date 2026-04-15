"""
File Security Module - Performs malware scan, data check, and type check
"""
import hashlib
import os
import mimetypes
import re
from typing import Tuple, Dict, List
from cryptography.fernet import Fernet

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'txt', 'csv', 'json', 'xml',
    'jpg', 'jpeg', 'png', 'gif', 'bmp',
    'zip', 'rar', '7z',
    'mp3', 'wav', 'flac',
    'mp4', 'avi', 'mkv'
}

# Sensitive data patterns
SENSITIVE_PATTERNS = {
    'credit_card': {
        'pattern': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'description': 'Credit Card Number'
    },
    'ssn': {
        'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
        'description': 'Social Security Number'
    },
    'email': {
        'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'description': 'Email Address'
    },
    'phone': {
        'pattern': r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
        'description': 'Phone Number'
    },
    'password_patterns': {
        'pattern': r'(?i)(password|passwd|pwd|secret|key|token|api_key)\s*[:=]\s*[^\s]+',
        'description': 'Potential Password/API Key'
    },
    'bank_account': {
        'pattern': r'\b(?:account|routing)\s*(?:number|#)?[:=\s]*\d{8,17}\b',
        'description': 'Bank Account Number'
    }
}


class FileSecurityChecker:
    """Handles all file security checks"""
    
    def __init__(self, file_obj, filename: str):
        self.file_obj = file_obj
        self.filename = filename
        self.errors = []
        self.warnings = []
        self.scan_results = {}
    
    def _initialize_clamav_client(self, pyclamd_module):
        host = os.getenv('CLAMD_HOST', '127.0.0.1')
        port_value = os.getenv('CLAMD_PORT')
        try:
            port = int(port_value) if port_value else 3310
        except ValueError:
            port = 3310
        socket_path = os.getenv('CLAMD_UNIX_SOCKET')
        attempts = []
        if hasattr(pyclamd_module, 'ClamdUnixSocket'):
            if socket_path:
                attempts.append(('unix', {'filename': socket_path}))
            attempts.append(('unix', {}))
        if hasattr(pyclamd_module, 'ClamdNetworkSocket'):
            attempts.append(('network', {'host': host, 'port': port}))
        if hasattr(pyclamd_module, 'ClamdAgnostic'):
            attempts.append(('agnostic', {}))
        for kind, kwargs in attempts:
            try:
                if kind == 'unix':
                    client = pyclamd_module.ClamdUnixSocket(**kwargs)
                elif kind == 'network':
                    client = pyclamd_module.ClamdNetworkSocket(**kwargs)
                else:
                    client = pyclamd_module.ClamdAgnostic()
                if client.ping():
                    return client
            except Exception:
                continue
        return None
        
    def check_file_type(self) -> bool:
        """
        Check if file type is allowed
        Returns: True if safe, False otherwise
        """
        # Get file extension
        file_ext = self.filename.rsplit('.', 1)[-1].lower() if '.' in self.filename else ''
        
        if not file_ext:
            self.errors.append("File must have an extension")
            return False
            
        if file_ext not in ALLOWED_EXTENSIONS:
            self.errors.append(
                f"File type '.{file_ext}' is not allowed. "
                f"Allowed types: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
            )
            return False
        
        self.scan_results['file_type'] = {
            'status': 'SAFE',
            'extension': file_ext,
            'message': f'File type .{file_ext} is allowed'
        }
        return True
    
    def check_file_size(self, max_size_mb: int = 50) -> bool:
        """
        Check if file size is within limits
        Returns: True if safe, False otherwise
        """
        max_size_bytes = max_size_mb * 1024 * 1024
        file_size = self.file_obj.size
        
        if file_size > max_size_bytes:
            self.errors.append(
                f"File size ({file_size / 1024 / 1024:.2f}MB) exceeds maximum "
                f"allowed size ({max_size_mb}MB)"
            )
            return False
        
        self.scan_results['file_size'] = {
            'status': 'SAFE',
            'size_mb': f'{file_size / 1024 / 1024:.2f}',
            'message': f'File size is acceptable'
        }
        return True
    
    def scan_sensitive_data(self, content: bytes) -> Dict:
        """
        Scan file content for sensitive data patterns
        Returns: Dictionary with findings
        """
        findings = []
        
        try:
            # Try to decode as text for pattern matching
            text_content = content.decode('utf-8', errors='ignore')
        except Exception as e:
            # Binary file, can't scan for sensitive data
            self.scan_results['sensitive_data'] = {
                'status': 'SKIPPED',
                'message': 'Binary file - sensitive data scan skipped',
                'findings': []
            }
            return findings
        
        # Search for each pattern
        for pattern_key, pattern_info in SENSITIVE_PATTERNS.items():
            matches = re.finditer(
                pattern_info['pattern'],
                text_content,
                re.MULTILINE | re.IGNORECASE
            )
            
            for match in matches:
                findings.append({
                    'type': pattern_key,
                    'description': pattern_info['description'],
                    'example': match.group()[:50]  # First 50 chars for privacy
                })
        
        if findings:
            self.warnings.append(
                f"Found {len(findings)} potential sensitive data patterns. "
                "Please review before upload."
            )
        
        self.scan_results['sensitive_data'] = {
            'status': 'COMPLETED',
            'findings_count': len(findings),
            'findings': findings,
            'message': f'Found {len(findings)} potential sensitive data patterns'
        }
        
        return findings
    
    def scan_malware(self, content: bytes) -> bool:
        """
        Scan file for malware using ClamAV
        Returns: True if safe, False if malicious
        """
        try:
            import pyclamd
            clam = self._initialize_clamav_client(pyclamd)
            if not clam:
                self.scan_results['malware'] = {
                    'status': 'UNAVAILABLE',
                    'message': 'ClamAV daemon not available - malware scan skipped',
                    'is_malicious': False
                }
                return True
            connection_error_cls = getattr(pyclamd, 'ConnectionError', None)
            try:
                result = clam.scan_stream(content)
            except Exception as exc:
                if connection_error_cls and isinstance(exc, connection_error_cls):
                    self.scan_results['malware'] = {
                        'status': 'UNAVAILABLE',
                        'message': f'ClamAV connection error: {str(exc)}',
                        'is_malicious': False
                    }
                    return True
                raise
            if result is None:
                self.scan_results['malware'] = {
                    'status': 'CLEAN',
                    'message': 'No malware detected',
                    'is_malicious': False
                }
                return True
            self.errors.append(f"Malware detected: {result}")
            self.scan_results['malware'] = {
                'status': 'INFECTED',
                'message': str(result),
                'is_malicious': True
            }
            return False
        except ImportError:
            self.scan_results['malware'] = {
                'status': 'SKIPPED',
                'message': 'ClamAV library not installed - malware scan skipped',
                'is_malicious': False
            }
            return True
        except Exception as e:
            self.scan_results['malware'] = {
                'status': 'ERROR',
                'message': f'Malware scan error: {str(e)}',
                'is_malicious': False
            }
            return True
    
    def compute_file_hash(self, content: bytes) -> str:
        """Compute SHA256 hash of file content"""
        return hashlib.sha256(content).hexdigest()
    
    def run_full_check(self, content: bytes) -> Dict:
        """
        Run all security checks
        Returns: Dictionary with check results and recommendations
        """
        results = {
            'is_safe': True,
            'errors': [],
            'warnings': [],
            'scan_results': {}
        }
        
        # Type check
        if not self.check_file_type():
            results['is_safe'] = False
        
        # Size check
        if not self.check_file_size():
            results['is_safe'] = False
        
        # Sensitive data scan
        self.scan_sensitive_data(content)
        
        # Malware scan
        if not self.scan_malware(content):
            results['is_safe'] = False
        
        # Compute hash
        file_hash = self.compute_file_hash(content)
        
        results['errors'] = self.errors
        results['warnings'] = self.warnings
        results['scan_results'] = self.scan_results
        results['file_hash'] = file_hash
        results['recommendation'] = self._get_recommendation()
        
        return results
    
    def _get_recommendation(self) -> str:
        """Get security recommendation based on checks"""
        if self.errors:
            return "REJECT"
        elif self.warnings:
            return "WARN"
        else:
            return "ACCEPT"


def encrypt_file(content: bytes, key: bytes) -> bytes:
    """
    Encrypt file content using Fernet encryption

    Args:
        content: The file content to encrypt
        key: The Fernet key for encryption

    Returns:
        Encrypted content as bytes
    """
    fernet = Fernet(key)
    return fernet.encrypt(content)


def decrypt_file(encrypted_content: bytes, key: bytes) -> bytes:
    """
    Decrypt file content using Fernet encryption

    Args:
        encrypted_content: The encrypted file content
        key: The Fernet key for decryption

    Returns:
        Decrypted content as bytes
    """
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_content)


class CodeSecurityScanner:
    """
    Scans code files for insecure coding practices
    """

    def __init__(self, content: str, filename: str):
        self.content = content
        self.filename = filename
        self.issues = []
        self.lines = content.split('\n')

    def scan(self) -> Dict:
        """
        Run all security scans on the code
        """
        self._scan_hardcoded_secrets()
        self._scan_weak_crypto()
        self._scan_dangerous_functions()
        self._scan_injection_vulnerabilities()
        self._scan_file_permissions()
        self._scan_input_validation()
        self._scan_vulnerable_packages()
        self._scan_hardcoded_urls()
        self._scan_output_encoding()
        self._scan_debug_code()

        return {
            'filename': self.filename,
            'issues_found': len(self.issues),
            'issues': self.issues,
            'total_lines': len(self.lines)
        }

    def _add_issue(self, line_number: int, issue_type: str, description: str, severity: str, code_snippet: str = ""):
        """Add a security issue to the findings"""
        self.issues.append({
            'line_number': line_number,
            'type': issue_type,
            'description': description,
            'severity': severity,
            'code_snippet': code_snippet.strip()
        })

    def _scan_hardcoded_secrets(self):
        """Scan for hardcoded secrets like passwords, API keys, tokens"""
        secret_patterns = [
            r'(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']',
            r'(api_key|apikey|secret|token|key)\s*=\s*["\'][^"\']+["\']',
            r'(db_password|database_password)\s*=\s*["\'][^"\']+["\']',
            r'(aws_access_key|aws_secret_key)\s*=\s*["\'][^"\']+["\']',
            r'(private_key|public_key)\s*=\s*["\'][^"\']+["\']'
        ]

        for i, line in enumerate(self.lines, 1):
            for pattern in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_issue(i, 'Hardcoded Secret', 'Potential hardcoded secret detected', 'HIGH', line)

    def _scan_weak_crypto(self):
        """Scan for weak cryptography or hashing algorithms"""
        weak_crypto_patterns = [
            r'import\s+(md5|sha1|des|rc4)',
            r'hashlib\.(md5|sha1)\(',
            r'cryptography\.hazmat\.primitives\.ciphers\.algorithms\.(DES|RC4)',
            r'DES\.|RC4\.|MD5\.|SHA1\.'
        ]

        for i, line in enumerate(self.lines, 1):
            for pattern in weak_crypto_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_issue(i, 'Weak Cryptography', 'Use of weak or deprecated cryptographic algorithm', 'HIGH', line)

    def _scan_dangerous_functions(self):
        """Scan for dangerous functions and system calls"""
        dangerous_patterns = [
            r'\beval\s*\(',
            r'\bexec\s*\(',
            r'os\.system\s*\(',
            r'subprocess\.(call|Popen|run)\s*\([^)]*shell\s*=\s*True',
            r'subprocess\.(call|Popen|run)\s*\([^)]*shell\s*=True',
            r'pickle\.(loads|load)',
            r'yaml\.(load|safe_load)',
            r'input\s*\('  # In Python 2, input() is dangerous
        ]

        for i, line in enumerate(self.lines, 1):
            for pattern in dangerous_patterns:
                if re.search(pattern, line):
                    self._add_issue(i, 'Dangerous Function', 'Use of potentially dangerous function', 'HIGH', line)

    def _scan_injection_vulnerabilities(self):
        """Scan for injection vulnerabilities"""
        injection_patterns = [
            r'cursor\.execute\s*\([^,)]*\+',
            r'connection\.execute\s*\([^,)]*\+',
            r'query\s*\+=',
            r'sql\s*=.*\+',
            r'html\s*=.*\+[^+]*request',
            r'render\s*\([^,)]*\+',
            r'jinja2\.Template\s*\(',
            r'Markup\s*\([^)]*\+'
        ]

        for i, line in enumerate(self.lines, 1):
            for pattern in injection_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_issue(i, 'Injection Vulnerability', 'Potential injection vulnerability detected', 'HIGH', line)

    def _scan_file_permissions(self):
        """Scan for insecure file and directory permissions"""
        permission_patterns = [
            r'chmod\s*\(.*0o777.*\)',
            r'chmod\s*\(.*777.*\)',
            r'open\s*\([^,)]*w\+',
            r'os\.makedirs\s*\(.*0o777.*\)',
            r'os\.chmod\s*\(.*0o777.*\)'
        ]

        for i, line in enumerate(self.lines, 1):
            for pattern in permission_patterns:
                if re.search(pattern, line):
                    self._add_issue(i, 'Insecure Permissions', 'Potentially insecure file or directory permissions', 'MEDIUM', line)

    def _scan_input_validation(self):
        """Scan for missing input validation"""
        # This is a simple check - look for user input without validation
        input_patterns = [
            r'request\.(GET|POST|args|get_json)\s*\[',
            r'input\s*\(',
            r'raw_input\s*\(',
            r'sys\.argv'
        ]

        validation_patterns = [
            r'validate|clean|sanitize|escape',
            r'isinstance\s*\(',
            r'type\s*\(',
            r'len\s*\('
        ]

        for i, line in enumerate(self.lines, 1):
            has_input = any(re.search(pattern, line) for pattern in input_patterns)
            has_validation = any(re.search(pattern, line, re.IGNORECASE) for pattern in validation_patterns)

            if has_input and not has_validation:
                # Check surrounding lines for validation
                start_line = max(0, i - 3)
                end_line = min(len(self.lines), i + 3)
                surrounding_lines = self.lines[start_line:end_line]
                has_validation_nearby = any(
                    any(re.search(pattern, nearby_line, re.IGNORECASE) for pattern in validation_patterns)
                    for nearby_line in surrounding_lines
                )

                if not has_validation_nearby:
                    self._add_issue(i, 'Missing Validation', 'User input without apparent validation', 'MEDIUM', line)

    def _scan_vulnerable_packages(self):
        """Scan for known vulnerable packages"""
        vulnerable_packages = [
            'django',  # Check for very old versions
            'flask',
            'requests',
            'urllib3',
            'cryptography',
            'pycrypto',  # Deprecated
            'paramiko'
        ]

        for i, line in enumerate(self.lines, 1):
            if line.strip().startswith('import ') or line.strip().startswith('from '):
                for package in vulnerable_packages:
                    if re.search(rf'\b{re.escape(package)}\b', line):
                        self._add_issue(i, 'Vulnerable Package', f'Import of potentially vulnerable package: {package}', 'LOW', line)

    def _scan_hardcoded_urls(self):
        """Scan for hardcoded URLs or endpoints"""
        url_patterns = [
            r'https?://[^\s"\']+',
            r'localhost:\d+',
            r'127\.0\.0\.1:\d+',
            r'0\.0\.0\.0:\d+'
        ]

        for i, line in enumerate(self.lines, 1):
            for pattern in url_patterns:
                matches = re.findall(pattern, line)
                for match in matches:
                    if not any(skip in match for skip in ['example.com', 'localhost:8000', '127.0.0.1:8000']):
                        self._add_issue(i, 'Hardcoded URL', 'Hardcoded URL or endpoint detected', 'MEDIUM', line)
                        break

    def _scan_output_encoding(self):
        """Scan for lack of output encoding"""
        output_patterns = [
            r'print\s*\([^)]*\+',
            r'return\s+.*\+.*',
            r'render_template\s*\([^)]*\+',
            r'jsonify\s*\([^)]*\+'
        ]

        encoding_patterns = [
            r'escape\(|html\.escape|bleach\.clean|sanitize'
        ]

        for i, line in enumerate(self.lines, 1):
            has_output = any(re.search(pattern, line, re.IGNORECASE) for pattern in output_patterns)
            has_encoding = any(re.search(pattern, line, re.IGNORECASE) for pattern in encoding_patterns)

            if has_output and not has_encoding:
                self._add_issue(i, 'Missing Output Encoding', 'User data rendered without apparent encoding', 'MEDIUM', line)

    def _scan_debug_code(self):
        """Scan for debugging code left in production"""
        debug_patterns = [
            r'\bprint\s*\(',
            r'debug\s*=\s*True',
            r'DEBUG\s*=\s*True',
            r'console\.log\s*\(',
            r'logging\.debug\s*\(',
            r'pdb\.set_trace\s*\(',
            r'import\s+pdb'
        ]

        for i, line in enumerate(self.lines, 1):
            for pattern in debug_patterns:
                if re.search(pattern, line):
                    self._add_issue(i, 'Debug Code', 'Debugging code detected in production', 'LOW', line)
                    break