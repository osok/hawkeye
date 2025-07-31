# Credential and Secret Management

## 🔐 Executive Summary

HawkEye implements a comprehensive credential and secret management system that provides secure storage, retrieval, and rotation of sensitive information including API keys, certificates, and authentication tokens. This document outlines the architecture, implementation, and best practices for managing credentials throughout the application lifecycle.

## Credential Management Architecture

### 1. Multi-Backend Storage System

**Credential Storage Backends**:
```mermaid
classDiagram
    class CredentialManager {
        +str storage_backend
        +Dict~str, str~ encrypted_keys
        +store_credential(key, value)
        +retrieve_credential(key)
        +delete_credential(key)
        +list_credentials()
        +rotate_encryption_key()
    }
    
    class KeyringBackend {
        +store_password(service, username, password)
        +get_password(service, username)
        +delete_password(service, username)
        +list_passwords()
    }
    
    class FileBackend {
        +Path credential_file
        +str encryption_key
        +encrypt_data(data)
        +decrypt_data(encrypted_data)
        +save_encrypted_file()
        +load_encrypted_file()
    }
    
    class EnvironmentBackend {
        +str env_prefix
        +validate_env_vars()
        +load_from_environment()
        +sanitize_env_vars()
    }
    
    class VaultBackend {
        +str vault_url
        +str vault_token
        +str vault_path
        +authenticate()
        +read_secret(path)
        +write_secret(path, data)
        +rotate_token()
    }
    
    CredentialManager --> KeyringBackend
    CredentialManager --> FileBackend
    CredentialManager --> EnvironmentBackend
    CredentialManager --> VaultBackend
```

### 2. Secure Credential Manager Implementation

**Core Credential Management Class**:
```python
class SecureCredentialManager:
    """Manages secure storage and retrieval of credentials across multiple backends."""
    
    def __init__(self, config: SecuritySettings):
        self.config = config
        self.backend = self._initialize_backend()
        self.encryption_key = self._get_or_create_encryption_key()
        self.logger = get_logger(__name__)
        
    def _initialize_backend(self) -> CredentialBackend:
        """Initialize the appropriate credential storage backend."""
        
        backend_type = self.config.credential_storage_backend
        
        backend_map = {
            'keyring': KeyringCredentialBackend,
            'file': lambda: FileCredentialBackend(self.config.credential_file_path),
            'environment': EnvironmentCredentialBackend,
            'vault': lambda: VaultCredentialBackend(self.config.vault_config)
        }
        
        if backend_type not in backend_map:
            raise ConfigurationError(f"Unsupported credential backend: {backend_type}")
        
        return backend_map[backend_type]()
```

## Backend Implementation Details

### 1. Keyring Backend (Recommended for Desktop)

**System Keyring Integration**:
```python
class KeyringCredentialBackend(CredentialBackend):
    """Secure credential storage using system keyring services."""
    
    def __init__(self):
        self.service_name = "hawkeye-security-tool"
        self.logger = get_logger(__name__)
        
        # Verify keyring availability
        if not self._is_keyring_available():
            raise CredentialBackendError("System keyring not available")
    
    def store_credential(self, key: str, value: str) -> None:
        """Store credential in system keyring."""
        
        try:
            # Use service name and key as username for organization
            keyring.set_password(self.service_name, key, value)
            self.logger.info(f"Stored credential in keyring: {key}")
            
        except keyring.errors.PasswordSetError as e:
            raise CredentialBackendError(f"Failed to store credential: {e}")
    
    def retrieve_credential(self, key: str) -> Optional[str]:
        """Retrieve credential from system keyring."""
        
        try:
            value = keyring.get_password(self.service_name, key)
            if value:
                self.logger.debug(f"Retrieved credential from keyring: {key}")
            return value
            
        except keyring.errors.PasswordGetError as e:
            self.logger.error(f"Failed to retrieve credential: {e}")
            return None
    
    def delete_credential(self, key: str) -> bool:
        """Delete credential from system keyring."""
        
        try:
            keyring.delete_password(self.service_name, key)
            self.logger.info(f"Deleted credential from keyring: {key}")
            return True
            
        except keyring.errors.PasswordDeleteError as e:
            self.logger.error(f"Failed to delete credential: {e}")
            return False
    
    def _is_keyring_available(self) -> bool:
        """Check if system keyring is available and functional."""
        
        try:
            # Test keyring functionality
            test_key = "hawkeye_test_key"
            test_value = "test_value"
            
            keyring.set_password(self.service_name, test_key, test_value)
            retrieved = keyring.get_password(self.service_name, test_key)
            keyring.delete_password(self.service_name, test_key)
            
            return retrieved == test_value
            
        except Exception:
            return False
```

### 2. Encrypted File Backend

**File-Based Encrypted Storage**:
```python
class FileCredentialBackend(CredentialBackend):
    """Encrypted file-based credential storage."""
    
    def __init__(self, credential_file_path: Path):
        self.credential_file = Path(credential_file_path)
        self.logger = get_logger(__name__)
        
        # Ensure credential directory exists with proper permissions
        self.credential_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        
        # Initialize encryption
        self.cipher_suite = self._initialize_encryption()
    
    def _initialize_encryption(self) -> Fernet:
        """Initialize encryption for credential file."""
        
        key_file = self.credential_file.parent / '.hawkeye_key'
        
        if key_file.exists():
            # Load existing encryption key
            with open(key_file, 'rb') as f:
                key = f.read()
        else:
            # Generate new encryption key
            key = Fernet.generate_key()
            
            # Store key with restricted permissions
            with open(key_file, 'wb') as f:
                f.write(key)
            key_file.chmod(0o600)
            
            self.logger.info("Generated new encryption key for credential storage")
        
        return Fernet(key)
    
    def store_credential(self, key: str, value: str) -> None:
        """Store encrypted credential in file."""
        
        credentials = self._load_credentials()
        
        # Encrypt the credential value
        encrypted_value = self.cipher_suite.encrypt(value.encode()).decode()
        credentials[key] = {
            'value': encrypted_value,
            'created_at': datetime.utcnow().isoformat(),
            'last_accessed': datetime.utcnow().isoformat()
        }
        
        self._save_credentials(credentials)
        self.logger.info(f"Stored encrypted credential: {key}")
    
    def retrieve_credential(self, key: str) -> Optional[str]:
        """Retrieve and decrypt credential from file."""
        
        credentials = self._load_credentials()
        
        if key not in credentials:
            return None
        
        try:
            # Decrypt credential value
            encrypted_value = credentials[key]['value'].encode()
            decrypted_value = self.cipher_suite.decrypt(encrypted_value).decode()
            
            # Update last accessed time
            credentials[key]['last_accessed'] = datetime.utcnow().isoformat()
            self._save_credentials(credentials)
            
            self.logger.debug(f"Retrieved credential: {key}")
            return decrypted_value
            
        except Exception as e:
            self.logger.error(f"Failed to decrypt credential {key}: {e}")
            return None
    
    def _load_credentials(self) -> Dict[str, Any]:
        """Load credentials from encrypted file."""
        
        if not self.credential_file.exists():
            return {}
        
        try:
            with open(self.credential_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            self.logger.error(f"Failed to load credentials file: {e}")
            return {}
    
    def _save_credentials(self, credentials: Dict[str, Any]) -> None:
        """Save credentials to encrypted file."""
        
        try:
            # Write to temporary file first, then rename (atomic operation)
            temp_file = self.credential_file.with_suffix('.tmp')
            
            with open(temp_file, 'w') as f:
                json.dump(credentials, f, indent=2)
            
            # Set restrictive permissions
            temp_file.chmod(0o600)
            
            # Atomic rename
            temp_file.rename(self.credential_file)
            
        except IOError as e:
            self.logger.error(f"Failed to save credentials file: {e}")
            raise CredentialBackendError(f"Failed to save credentials: {e}")
```

### 3. Environment Variable Backend

**Environment-Based Credential Management**:
```python
class EnvironmentCredentialBackend(CredentialBackend):
    """Environment variable-based credential storage."""
    
    def __init__(self, env_prefix: str = "HAWKEYE"):
        self.env_prefix = env_prefix
        self.logger = get_logger(__name__)
        
        # Validate environment security
        self._validate_environment_security()
    
    def store_credential(self, key: str, value: str) -> None:
        """Store credential as environment variable."""
        
        env_key = f"{self.env_prefix}_{key.upper()}"
        os.environ[env_key] = value
        
        self.logger.info(f"Stored credential in environment: {env_key}")
        
        # Security warning for environment storage
        self.logger.warning(
            f"Credential stored in environment variable {env_key}. "
            "Consider using more secure storage for production environments."
        )
    
    def retrieve_credential(self, key: str) -> Optional[str]:
        """Retrieve credential from environment variable."""
        
        env_key = f"{self.env_prefix}_{key.upper()}"
        value = os.environ.get(env_key)
        
        if value:
            self.logger.debug(f"Retrieved credential from environment: {env_key}")
        
        return value
    
    def delete_credential(self, key: str) -> bool:
        """Remove credential from environment."""
        
        env_key = f"{self.env_prefix}_{key.upper()}"
        
        if env_key in os.environ:
            del os.environ[env_key]
            self.logger.info(f"Deleted credential from environment: {env_key}")
            return True
        
        return False
    
    def _validate_environment_security(self) -> None:
        """Validate environment variable security."""
        
        security_warnings = []
        
        # Check for common security issues
        sensitive_patterns = ['secret', 'password', 'key', 'token']
        
        for env_var, value in os.environ.items():
            var_lower = env_var.lower()
            
            # Check for potentially exposed secrets
            if any(pattern in var_lower for pattern in sensitive_patterns):
                if value and len(value) > 0:
                    security_warnings.append(f"Sensitive data in environment variable: {env_var}")
        
        # Log security warnings
        for warning in security_warnings:
            self.logger.warning(warning)
```

### 4. HashiCorp Vault Backend

**Enterprise Vault Integration**:
```python
class VaultCredentialBackend(CredentialBackend):
    """HashiCorp Vault credential storage backend."""
    
    def __init__(self, vault_config: Dict[str, Any]):
        self.vault_url = vault_config['url']
        self.vault_token = vault_config.get('token')
        self.vault_path = vault_config.get('path', 'hawkeye/credentials')
        self.verify_ssl = vault_config.get('verify_ssl', True)
        
        self.client = self._initialize_vault_client()
        self.logger = get_logger(__name__)
    
    def _initialize_vault_client(self) -> hvac.Client:
        """Initialize HashiCorp Vault client."""
        
        try:
            client = hvac.Client(
                url=self.vault_url,
                token=self.vault_token,
                verify=self.verify_ssl
            )
            
            # Verify authentication
            if not client.is_authenticated():
                raise CredentialBackendError("Vault authentication failed")
            
            self.logger.info("Successfully authenticated with Vault")
            return client
            
        except Exception as e:
            raise CredentialBackendError(f"Failed to initialize Vault client: {e}")
    
    def store_credential(self, key: str, value: str) -> None:
        """Store credential in Vault."""
        
        secret_path = f"{self.vault_path}/{key}"
        
        try:
            # Store credential with metadata
            secret_data = {
                'value': value,
                'created_at': datetime.utcnow().isoformat(),
                'created_by': 'hawkeye-tool'
            }
            
            self.client.secrets.kv.v2.create_or_update_secret(
                path=secret_path,
                secret=secret_data
            )
            
            self.logger.info(f"Stored credential in Vault: {secret_path}")
            
        except Exception as e:
            raise CredentialBackendError(f"Failed to store credential in Vault: {e}")
    
    def retrieve_credential(self, key: str) -> Optional[str]:
        """Retrieve credential from Vault."""
        
        secret_path = f"{self.vault_path}/{key}"
        
        try:
            response = self.client.secrets.kv.v2.read_secret_version(path=secret_path)
            
            if response and 'data' in response:
                value = response['data']['data'].get('value')
                if value:
                    self.logger.debug(f"Retrieved credential from Vault: {secret_path}")
                return value
            
            return None
            
        except hvac.exceptions.InvalidPath:
            # Secret doesn't exist
            return None
        except Exception as e:
            self.logger.error(f"Failed to retrieve credential from Vault: {e}")
            return None
    
    def delete_credential(self, key: str) -> bool:
        """Delete credential from Vault."""
        
        secret_path = f"{self.vault_path}/{key}"
        
        try:
            self.client.secrets.kv.v2.delete_metadata_and_all_versions(path=secret_path)
            self.logger.info(f"Deleted credential from Vault: {secret_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to delete credential from Vault: {e}")
            return False
```

## API Key and Token Management

### 1. AI Provider API Key Management

**Secure API Key Storage and Retrieval**:
```python
class AIProviderCredentialManager:
    """Specialized credential management for AI providers."""
    
    def __init__(self, credential_manager: SecureCredentialManager):
        self.credential_manager = credential_manager
        self.logger = get_logger(__name__)
        
        # Define supported AI providers
        self.supported_providers = {
            'openai': 'OpenAI API Key',
            'anthropic': 'Anthropic API Key',
            'azure_openai': 'Azure OpenAI API Key',
            'local_llm': 'Local LLM Endpoint Token'
        }
    
    def store_api_key(self, provider: str, api_key: str) -> None:
        """Store AI provider API key securely."""
        
        if provider not in self.supported_providers:
            raise ValueError(f"Unsupported AI provider: {provider}")
        
        # Validate API key format
        if not self._validate_api_key_format(provider, api_key):
            raise ValueError(f"Invalid API key format for provider: {provider}")
        
        credential_key = f"ai_api_key_{provider}"
        
        # Store encrypted API key
        self.credential_manager.store_credential(credential_key, api_key)
        
        # Update in-memory cache with masked value for logging
        masked_key = self._mask_api_key(api_key)
        self.logger.info(f"Stored API key for {provider}: {masked_key}")
    
    def retrieve_api_key(self, provider: str) -> Optional[str]:
        """Retrieve AI provider API key securely."""
        
        if provider not in self.supported_providers:
            self.logger.error(f"Unsupported AI provider: {provider}")
            return None
        
        credential_key = f"ai_api_key_{provider}"
        
        try:
            api_key = self.credential_manager.retrieve_credential(credential_key)
            
            if api_key:
                # Validate retrieved key
                if self._validate_api_key_format(provider, api_key):
                    self.logger.debug(f"Retrieved valid API key for {provider}")
                    return api_key
                else:
                    self.logger.error(f"Retrieved invalid API key for {provider}")
                    return None
            
            # Fallback to environment variables
            env_key = f"AI_{provider.upper()}_API_KEY"
            fallback_key = os.environ.get(env_key)
            
            if fallback_key:
                self.logger.info(f"Using fallback API key from environment for {provider}")
                return fallback_key
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve API key for {provider}: {e}")
            return None
    
    def _validate_api_key_format(self, provider: str, api_key: str) -> bool:
        """Validate API key format for specific providers."""
        
        validation_patterns = {
            'openai': r'^sk-[A-Za-z0-9]{48}$',
            'anthropic': r'^sk-ant-[A-Za-z0-9\-_]{32,}$',
            'azure_openai': r'^[A-Za-z0-9]{32}$',
            'local_llm': r'^.+$'  # Local LLM tokens can be various formats
        }
        
        pattern = validation_patterns.get(provider)
        if not pattern:
            return True  # Allow unknown providers
        
        import re
        return bool(re.match(pattern, api_key))
    
    def _mask_api_key(self, api_key: str) -> str:
        """Mask API key for logging purposes."""
        
        if len(api_key) <= 8:
            return '*' * len(api_key)
        
        return f"{api_key[:4]}{'*' * (len(api_key) - 8)}{api_key[-4:]}"
```

### 2. Certificate and SSL Management

**SSL Certificate Secure Storage**:
```python
class CertificateManager:
    """Manage SSL certificates and private keys securely."""
    
    def __init__(self, credential_manager: SecureCredentialManager):
        self.credential_manager = credential_manager
        self.logger = get_logger(__name__)
    
    def store_certificate(self, name: str, cert_data: str, private_key: Optional[str] = None) -> None:
        """Store SSL certificate and optional private key."""
        
        # Validate certificate format
        if not self._validate_certificate_format(cert_data):
            raise ValueError("Invalid certificate format")
        
        # Store certificate
        cert_key = f"ssl_certificate_{name}"
        self.credential_manager.store_credential(cert_key, cert_data)
        
        # Store private key if provided
        if private_key:
            if not self._validate_private_key_format(private_key):
                raise ValueError("Invalid private key format")
            
            key_key = f"ssl_private_key_{name}"
            self.credential_manager.store_credential(key_key, private_key)
        
        self.logger.info(f"Stored SSL certificate: {name}")
    
    def retrieve_certificate(self, name: str) -> Optional[Dict[str, str]]:
        """Retrieve SSL certificate and private key."""
        
        cert_key = f"ssl_certificate_{name}"
        key_key = f"ssl_private_key_{name}"
        
        cert_data = self.credential_manager.retrieve_credential(cert_key)
        private_key = self.credential_manager.retrieve_credential(key_key)
        
        if cert_data:
            result = {'certificate': cert_data}
            if private_key:
                result['private_key'] = private_key
            return result
        
        return None
    
    def _validate_certificate_format(self, cert_data: str) -> bool:
        """Validate SSL certificate format."""
        
        try:
            # Basic PEM format validation
            if '-----BEGIN CERTIFICATE-----' in cert_data and '-----END CERTIFICATE-----' in cert_data:
                return True
            
            # Could add more sophisticated validation using cryptography library
            from cryptography import x509
            x509.load_pem_x509_certificate(cert_data.encode())
            return True
            
        except Exception:
            return False
    
    def _validate_private_key_format(self, private_key: str) -> bool:
        """Validate private key format."""
        
        try:
            # Basic PEM format validation
            pem_headers = [
                '-----BEGIN PRIVATE KEY-----',
                '-----BEGIN RSA PRIVATE KEY-----',
                '-----BEGIN EC PRIVATE KEY-----'
            ]
            
            return any(header in private_key for header in pem_headers)
            
        except Exception:
            return False
```

## Security Best Practices

### 1. Credential Lifecycle Management

**Credential Rotation Strategy**:
```python
class CredentialRotationManager:
    """Manage credential rotation and expiration."""
    
    def __init__(self, credential_manager: SecureCredentialManager):
        self.credential_manager = credential_manager
        self.logger = get_logger(__name__)
    
    def schedule_rotation(self, credential_key: str, rotation_interval: timedelta) -> None:
        """Schedule credential rotation."""
        
        metadata = {
            'rotation_interval': rotation_interval.total_seconds(),
            'next_rotation': (datetime.utcnow() + rotation_interval).isoformat(),
            'rotation_count': 0
        }
        
        metadata_key = f"{credential_key}_metadata"
        self.credential_manager.store_credential(metadata_key, json.dumps(metadata))
        
        self.logger.info(f"Scheduled rotation for credential: {credential_key}")
    
    def check_rotation_due(self, credential_key: str) -> bool:
        """Check if credential rotation is due."""
        
        metadata_key = f"{credential_key}_metadata"
        metadata_json = self.credential_manager.retrieve_credential(metadata_key)
        
        if not metadata_json:
            return False
        
        try:
            metadata = json.loads(metadata_json)
            next_rotation = datetime.fromisoformat(metadata['next_rotation'])
            
            return datetime.utcnow() >= next_rotation
            
        except (json.JSONDecodeError, KeyError, ValueError):
            return False
    
    def rotate_credential(self, credential_key: str, new_value: str) -> bool:
        """Rotate credential with new value."""
        
        try:
            # Store new credential
            self.credential_manager.store_credential(credential_key, new_value)
            
            # Update rotation metadata
            metadata_key = f"{credential_key}_metadata"
            metadata_json = self.credential_manager.retrieve_credential(metadata_key)
            
            if metadata_json:
                metadata = json.loads(metadata_json)
                interval = timedelta(seconds=metadata['rotation_interval'])
                
                metadata.update({
                    'next_rotation': (datetime.utcnow() + interval).isoformat(),
                    'rotation_count': metadata.get('rotation_count', 0) + 1,
                    'last_rotation': datetime.utcnow().isoformat()
                })
                
                self.credential_manager.store_credential(metadata_key, json.dumps(metadata))
            
            self.logger.info(f"Successfully rotated credential: {credential_key}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to rotate credential {credential_key}: {e}")
            return False
```

### 2. Access Control and Auditing

**Credential Access Auditing**:
```python
class CredentialAuditLogger:
    """Audit credential access and modifications."""
    
    def __init__(self):
        self.logger = get_logger("credential_audit")
        self.audit_file = Path("logs/credential_audit.log")
        
        # Ensure audit log directory exists
        self.audit_file.parent.mkdir(parents=True, exist_ok=True)
    
    def log_credential_access(self, credential_key: str, operation: str, 
                            user: Optional[str] = None, success: bool = True) -> None:
        """Log credential access attempt."""
        
        audit_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'credential_key': credential_key,
            'operation': operation,  # 'store', 'retrieve', 'delete', 'rotate'
            'user': user or 'system',
            'success': success,
            'process_id': os.getpid()
        }
        
        # Log to structured audit file
        with open(self.audit_file, 'a') as f:
            f.write(json.dumps(audit_entry) + '\n')
        
        # Log to application logger
        level = logging.INFO if success else logging.ERROR
        self.logger.log(level, 
            f"Credential {operation} - Key: {credential_key}, "
            f"User: {user or 'system'}, Success: {success}")
    
    def get_audit_trail(self, credential_key: Optional[str] = None, 
                       start_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Retrieve credential audit trail."""
        
        if not self.audit_file.exists():
            return []
        
        audit_entries = []
        
        try:
            with open(self.audit_file, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        
                        # Filter by credential key if specified
                        if credential_key and entry.get('credential_key') != credential_key:
                            continue
                        
                        # Filter by start time if specified
                        if start_time:
                            entry_time = datetime.fromisoformat(entry['timestamp'])
                            if entry_time < start_time:
                                continue
                        
                        audit_entries.append(entry)
                        
                    except json.JSONDecodeError:
                        continue
            
        except IOError as e:
            self.logger.error(f"Failed to read audit log: {e}")
        
        return audit_entries
```

## Configuration and Deployment

### 1. Backend Selection Strategy

**Deployment Environment Recommendations**:

| Environment | Recommended Backend | Rationale |
|-------------|-------------------|-----------|
| **Development** | Environment Variables | Simple setup, easy debugging |
| **Desktop/Laptop** | System Keyring | OS-integrated security, user-friendly |
| **Server/Production** | HashiCorp Vault | Enterprise-grade security, scalability |
| **CI/CD Pipeline** | Environment Variables | Integration simplicity, controlled environment |
| **Container Deployment** | Vault or Encrypted Files | Persistence across container restarts |

### 2. Security Configuration

**Production Security Settings**:
```yaml
# hawkeye-security.yaml
credential_management:
  # Primary backend for credential storage
  storage_backend: "vault"  # Options: keyring, file, environment, vault
  
  # Encryption settings
  encryption:
    algorithm: "AES-256-GCM"
    key_rotation_interval: "30d"
    
  # Vault configuration (if using vault backend)
  vault:
    url: "https://vault.company.com:8200"
    auth_method: "kubernetes"  # or "token", "userpass"
    mount_path: "secret/hawkeye"
    verify_ssl: true
    
  # File backend configuration (if using file backend)
  file:
    credential_file: "/secure/path/hawkeye_credentials.json"
    key_file: "/secure/path/hawkeye_key"
    file_permissions: "0600"
    
  # Audit and monitoring
  audit:
    enable_audit_logging: true
    audit_log_file: "/var/log/hawkeye/credential_audit.log"
    retention_days: 90
    
  # Security policies
  security:
    require_key_rotation: true
    max_credential_age: "90d"
    enable_access_logging: true
    mask_credentials_in_logs: true
```

## Troubleshooting and Maintenance

### 1. Common Issues and Solutions

**Credential Access Failures**:
```python
class CredentialTroubleshooter:
    """Diagnose and resolve credential management issues."""
    
    def diagnose_credential_access_failure(self, credential_key: str) -> Dict[str, Any]:
        """Diagnose credential access failures."""
        
        diagnosis = {
            'credential_key': credential_key,
            'issues_found': [],
            'recommendations': []
        }
        
        # Check backend availability
        backend_status = self._check_backend_status()
        if not backend_status['available']:
            diagnosis['issues_found'].append(f"Backend not available: {backend_status['error']}")
            diagnosis['recommendations'].append("Check backend service status and configuration")
        
        # Check credential existence
        if not self._credential_exists(credential_key):
            diagnosis['issues_found'].append("Credential not found in storage")
            diagnosis['recommendations'].append("Verify credential key and storage location")
        
        # Check permissions
        permission_issues = self._check_permissions()
        if permission_issues:
            diagnosis['issues_found'].extend(permission_issues)
            diagnosis['recommendations'].append("Review file permissions and access controls")
        
        # Check encryption key availability
        if not self._encryption_key_available():
            diagnosis['issues_found'].append("Encryption key not available")
            diagnosis['recommendations'].append("Verify encryption key file exists and is readable")
        
        return diagnosis
    
    def perform_credential_health_check(self) -> Dict[str, Any]:
        """Perform comprehensive credential system health check."""
        
        health_report = {
            'timestamp': datetime.utcnow().isoformat(),
            'overall_status': 'healthy',
            'backend_status': {},
            'credential_count': 0,
            'expired_credentials': [],
            'rotation_due': [],
            'security_issues': []
        }
        
        try:
            # Check backend health
            health_report['backend_status'] = self._check_backend_status()
            
            # Count stored credentials
            health_report['credential_count'] = self._count_credentials()
            
            # Check for expired credentials
            health_report['expired_credentials'] = self._find_expired_credentials()
            
            # Check for credentials due for rotation
            health_report['rotation_due'] = self._find_rotation_due_credentials()
            
            # Identify security issues
            health_report['security_issues'] = self._identify_security_issues()
            
            # Determine overall status
            if (health_report['expired_credentials'] or 
                not health_report['backend_status']['available'] or
                health_report['security_issues']):
                health_report['overall_status'] = 'unhealthy'
            elif health_report['rotation_due']:
                health_report['overall_status'] = 'warning'
        
        except Exception as e:
            health_report['overall_status'] = 'error'
            health_report['error'] = str(e)
        
        return health_report
```

### 2. Maintenance Procedures

**Regular Maintenance Tasks**:
- **Weekly**: Check credential health status
- **Monthly**: Rotate credentials per policy
- **Quarterly**: Review access logs and audit trails
- **Annually**: Update encryption keys and security policies

## Integration with HawkEye Components

### 1. AI Threat Analysis Integration

**Secure AI Provider Configuration**:
```python
# Integration with AI threat analysis system
def configure_ai_providers() -> Dict[str, AIProvider]:
    """Configure AI providers with secure credential management."""
    
    credential_manager = SecureCredentialManager(get_security_settings())
    ai_credential_manager = AIProviderCredentialManager(credential_manager)
    
    providers = {}
    
    # Configure OpenAI provider
    openai_key = ai_credential_manager.retrieve_api_key('openai')
    if openai_key:
        providers['openai'] = OpenAIProvider(api_key=openai_key)
    
    # Configure Anthropic provider
    anthropic_key = ai_credential_manager.retrieve_api_key('anthropic')
    if anthropic_key:
        providers['anthropic'] = AnthropicProvider(api_key=anthropic_key)
    
    return providers
```

### 2. MCP Transport Security Integration

**Secure Transport Configuration**:
```python
# Integration with MCP transport layer
def create_secure_transport(endpoint: str, auth: Optional[Dict[str, str]] = None) -> BaseTransportHandler:
    """Create secure transport with credential management."""
    
    if auth and 'token' in auth:
        # Retrieve token from secure storage
        credential_manager = SecureCredentialManager(get_security_settings())
        secure_token = credential_manager.retrieve_credential(f"mcp_token_{endpoint}")
        
        if secure_token:
            auth['token'] = secure_token
    
    # Create transport with security validation
    transport = HTTPTransport(endpoint=endpoint, auth=auth)
    
    # Validate URL security
    if not transport._validate_url(endpoint):
        raise TransportSecurityError(f"Insecure endpoint: {endpoint}")
    
    return transport
```

## Conclusion

HawkEye's credential and secret management system provides enterprise-grade security for sensitive information through multiple storage backends, comprehensive encryption, audit logging, and automated rotation capabilities. This multi-layered approach ensures that credentials remain secure throughout their lifecycle while providing the flexibility needed for various deployment environments.

The system's architecture supports seamless integration with existing security infrastructure while maintaining the highest standards of credential protection and access control. 