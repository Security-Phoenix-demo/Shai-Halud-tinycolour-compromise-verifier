#!/usr/bin/env python3
"""
Enhanced NPM Package Compromise Detection Tool with Phoenix Security API Integration
Detects compromised NPM packages and optionally imports assets and findings to Phoenix Security platform
Supports repository URL extraction and batch processing

Author: DevSecOps Security Team
Date: September 2025
Updated: Enhanced with Phoenix API integration for asset and finding management
"""

import json
import os
import re
import sys
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
import argparse
from datetime import datetime
import tempfile
import shutil
import requests
from requests.auth import HTTPBasicAuth
import configparser
import uuid
from urllib.parse import urlparse
import base64

class EnhancedNPMCompromiseDetectorPhoenix:
    def __init__(self, config_file: str = None, phoenix_config_file: str = None):
        """Initialize the detector with compromised package data and Phoenix API configuration"""
        self.config_file = config_file or "compromised_packages_2025.json"
        self.phoenix_config_file = phoenix_config_file or ".config"
        
        # Load compromise data
        self.load_compromise_data()
        
        # Initialize all attributes first
        self.findings = []
        self.scanned_files = []
        self.scanned_packages = []
        self.package_sources = {}
        self.safe_packages = []
        self.phoenix_assets = []  # Assets to be imported to Phoenix
        self.phoenix_findings = []  # Findings to be imported to Phoenix
        self.debug_mode = False  # Debug mode flag
        self.delete_local_files = False  # Delete cloned repositories after scan
        self.detail_log = False  # Show all libraries without truncation
        self.use_tmp = False  # Use /tmp for cloning (legacy mode)
        
        # Enhanced tracking for comprehensive reporting
        self.cloned_repositories = []  # Track repositories that were cloned
        self.found_repositories = []   # Track repositories that were found locally
        self.processed_repositories = []  # Track all processed repositories with details
        self.all_scanned_libraries = []  # Track all libraries found during scan
        self.clean_libraries = []     # Track clean libraries
        self.compromised_libraries = []  # Track compromised libraries
        self.api_failed_repositories = []  # Track repositories where API failed
        self.fallback_success_repositories = []  # Track repositories successfully accessed via fallback
        self.completely_failed_repositories = []  # Track repositories that failed both API and fallback
        
        self.dependency_stats = {
            'direct_dependencies': 0,
            'transitive_dependencies': 0,
            'lock_file_packages': 0,
            'tree_resolved_packages': 0,
            'safe_packages_found': 0,
            'compromised_packages_found': 0,
            'potentially_compromised_found': 0
        }
        self.full_tree_analysis = False
        self.enable_phoenix_import = False
        self.import_all_libraries = False  # Import all libraries including clean ones
        self.light_scan_mode = False
        self.github_token = None  # Will be loaded from config or environment
        self.use_embedded_credentials = False
        
        # Tag configuration
        self.additional_vuln_tags = []  # Additional tags for vulnerability findings
        self.additional_asset_tags = []  # Additional tags for asset findings
        
        # Folder organization for GitHub pulls and results
        self.timestamp = datetime.now().strftime('%Y%m%d')
        self.github_pull_dir = os.path.join('github-pull', self.timestamp)
        self.result_dir = os.path.join('result', self.timestamp)
        self.organize_folders = False
        
        # 🔐 EMBEDDED CREDENTIALS FOR LOCAL LAPTOP USE
        # Replace with your actual Phoenix Security credentials for personal use
        self.embedded_credentials = {
            'client_id': 'your_phoenix_client_id_here',
            'client_secret': 'your_phoenix_client_secret_here', 
            'api_base_url': 'https://your-phoenix-domain.com/api',
            'assessment_name': 'NPM Compromise Detection - Local Laptop',
            'import_type': 'new'
        }
        
        # Load Phoenix configuration and GitHub token after initializing all attributes
        self.phoenix_config = self.load_phoenix_config()
        self.load_github_token()
        self.load_tag_config()
        
    def load_phoenix_config(self) -> Dict:
        """Load Phoenix API configuration from embedded credentials, environment variables, or .config file"""
        config = {}
        
        # Priority 1: Check for embedded credentials
        if self.use_embedded_credentials:
            if (self.embedded_credentials['client_id'] != 'your_phoenix_client_id_here' and 
                self.embedded_credentials['client_secret'] != 'your_phoenix_client_secret_here' and
                self.embedded_credentials['api_base_url'] != 'https://your-phoenix-domain.com/api'):
                print("🔐 Using embedded Phoenix credentials")
                return self.embedded_credentials
            else:
                print("⚠️  Embedded credentials contain placeholder values. Please update the script with your actual credentials.")
        
        # Priority 2: Check environment variables
        env_client_id = os.getenv('PHOENIX_CLIENT_ID')
        env_client_secret = os.getenv('PHOENIX_CLIENT_SECRET') 
        env_api_url = os.getenv('PHOENIX_API_URL')
        
        if env_client_id and env_client_secret and env_api_url:
            print("🔐 Using Phoenix credentials from environment variables")
            return {
                'client_id': env_client_id,
                'client_secret': env_client_secret,
                'api_base_url': env_api_url,
                'assessment_name': os.getenv('PHOENIX_ASSESSMENT_NAME', 'NPM Compromise Detection - Environment'),
                'import_type': os.getenv('PHOENIX_IMPORT_TYPE', 'new')
            }
        
        # Priority 3: Check config file
        if os.path.exists(self.phoenix_config_file):
            try:
                parser = configparser.ConfigParser()
                parser.read(self.phoenix_config_file)
                
                if 'phoenix' in parser:
                    phoenix_section = parser['phoenix']
                    config = {
                        'client_id': phoenix_section.get('client_id'),
                        'client_secret': phoenix_section.get('client_secret'),
                        'api_base_url': phoenix_section.get('api_base_url'),
                        'assessment_name': phoenix_section.get('assessment_name', 'NPM Compromise Detection'),
                        'import_type': phoenix_section.get('import_type', 'new')
                    }
                    
                    print(f"✅ Loaded Phoenix API configuration from {self.phoenix_config_file}")
                else:
                    print(f"⚠️  No [phoenix] section found in {self.phoenix_config_file}")
                    
            except Exception as e:
                print(f"❌ Error loading Phoenix configuration: {str(e)}")
                
        else:
            print(f"⚠️  Phoenix configuration file {self.phoenix_config_file} not found")
            
        return config
    
    def load_github_token(self):
        """Load GitHub token from environment variable or config file"""
        # Priority 1: Environment variable
        env_token = os.getenv('GITHUB_TOKEN')
        if env_token:
            self.github_token = env_token
            print("🔗 Using GitHub token from environment variable")
            return
        
        # Priority 2: Config file
        if os.path.exists(self.phoenix_config_file):
            try:
                parser = configparser.ConfigParser()
                parser.read(self.phoenix_config_file)
                
                if 'phoenix' in parser:
                    phoenix_section = parser['phoenix']
                    # Check for various possible key names
                    github_token = (phoenix_section.get('github_token') or 
                                  phoenix_section.get('Github_token') or 
                                  phoenix_section.get('GITHUB_TOKEN'))
                    
                    if github_token and github_token.strip():
                        self.github_token = github_token.strip()
                        print(f"🔗 Using GitHub token from {self.phoenix_config_file}")
                        return
                        
            except Exception as e:
                print(f"⚠️  Error loading GitHub token from config: {str(e)}")
        
        # No token found
        print("💡 No GitHub token found - API rate limits may apply for light scan mode")
        
    def load_tag_config(self):
        """Load additional tag configuration from config file"""
        if not os.path.exists(self.phoenix_config_file):
            return
            
        try:
            parser = configparser.ConfigParser()
            parser.read(self.phoenix_config_file)
            
            if 'phoenix' in parser:
                phoenix_section = parser['phoenix']
                
                # Load vulnerability tags
                vuln_tags = phoenix_section.get('additional_vuln_tags', '')
                if vuln_tags:
                    self.additional_vuln_tags = [tag.strip() for tag in vuln_tags.split(',') if tag.strip()]
                    
                # Load asset tags  
                asset_tags = phoenix_section.get('additional_asset_tags', '')
                if asset_tags:
                    self.additional_asset_tags = [tag.strip() for tag in asset_tags.split(',') if tag.strip()]
                    
                if self.additional_vuln_tags:
                    print(f"🏷️  Loaded additional vulnerability tags: {', '.join(self.additional_vuln_tags)}")
                if self.additional_asset_tags:
                    print(f"🏷️  Loaded additional asset tags: {', '.join(self.additional_asset_tags)}")
                    
        except Exception as e:
            print(f"⚠️  Error loading tag configuration: {str(e)}")
        
    def create_config_template(self, output_path: str = ".config.example"):
        """Create a template configuration file for Phoenix API"""
        template_content = """[phoenix]
# Phoenix Security API Configuration
client_id = your_client_id_here
client_secret = your_client_secret_here
api_base_url = https://api.securityphoenix.cloud
assessment_name = NPM Compromise Detection - Shai Halud
import_type = new

# GitHub token for enhanced API rate limits (optional but recommended)
# IMPORTANT: If token is invalid/expired, automatic fallback will use direct raw access
# For public repositories: token is optional, fallback handles API failures automatically
# For private repositories: valid token is required
github_token = your_github_token_here

# Additional tags for findings and assets (comma-separated)
# These tags will be added to vulnerability findings
additional_vuln_tags = custom-scan,security-audit
# These tags will be added to asset findings  
additional_asset_tags = npm-project,dependency-scan

# Enhanced Fallback System (Automatic - No Configuration Needed):
# 1. GitHub API Search (with/without authentication)
# 2. GitHub API Fallback (direct file access)
# 3. Direct Raw Access (raw.githubusercontent.com for public repos)
# 4. Complete failure documentation in reports

# Optional settings
# For demo environment, use: https://api.demo.appsecphx.io
# For enterprise PoC, use: https://api.poc1.appsecphx.io
"""
        
        with open(output_path, 'w') as f:
            f.write(template_content)
            
        print(f"📄 Created Phoenix API configuration template: {output_path}")
        print(f"💡 Copy this to .config and fill in your credentials")
        
    def extract_repository_url(self, file_path: str) -> Optional[str]:
        """Extract repository URL from file path based on common patterns"""
        # Convert to Path object for easier manipulation
        path = Path(file_path).resolve()
        
        # Look for common repository hosting patterns in the path
        path_str = str(path)
        
        # Pattern 1: GitHub pattern /Documents/GitHub/repo-name/
        github_match = re.search(r'/GitHub/([^/]+)/', path_str)
        if github_match:
            repo_name = github_match.group(1)
            # Try to determine the organization from common patterns
            if 'SP-MVP1-Frontend' in repo_name:
                return f"https://github.com/securityphoenix/{repo_name}"
            elif 'Shai-Halud' in repo_name:
                return f"https://github.com/Security-Phoenix-demo/{repo_name}"
            else:
                # Default to a generic pattern - user can override
                return f"https://github.com/unknown-org/{repo_name}"
                
        # Pattern 2: Look for .git directory
        current_path = path.parent
        while current_path != current_path.parent:  # Stop at root
            git_dir = current_path / '.git'
            if git_dir.exists():
                # Try to read origin URL from git config
                try:
                    result = subprocess.run(
                        ['git', 'remote', 'get-url', 'origin'],
                        cwd=current_path,
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.returncode == 0:
                        origin_url = result.stdout.strip()
                        # Convert SSH to HTTPS if needed
                        if origin_url.startswith('git@github.com:'):
                            origin_url = origin_url.replace('git@github.com:', 'https://github.com/')
                            if origin_url.endswith('.git'):
                                origin_url = origin_url[:-4]
                        return origin_url
                except Exception:
                    pass
                    
                # Fallback: use directory name
                repo_name = current_path.name
                return f"https://github.com/unknown-org/{repo_name}"
                
            current_path = current_path.parent
            
        # Pattern 3: Extract from path structure
        path_parts = path.parts
        for i, part in enumerate(path_parts):
            if part.lower() in ['projects', 'repos', 'repositories', 'src', 'source']:
                if i + 1 < len(path_parts):
                    repo_name = path_parts[i + 1]
                    return f"https://github.com/unknown-org/{repo_name}"
                    
        return None
        
    def create_phoenix_asset(self, file_path: str, repo_url: str) -> Dict:
        """Create a Phoenix asset for a package file"""
        
        # Determine the buildFile path
        # If file_path is a simple repository path (no local filesystem prefix), use it directly
        if file_path and not os.path.isabs(file_path) and not file_path.startswith('/'):
            # This is already a repository-relative path (from light scan mode)
            build_file_path = file_path
        elif repo_url and "github.com" in repo_url:
            # For local files, try to extract meaningful relative path
            if os.path.isabs(file_path):
                # Try to extract relative path from local file system path
                path_parts = file_path.split(os.sep)
                relative_path = os.path.basename(file_path)
                
                # Look for meaningful directory structure
                for i, part in enumerate(path_parts):
                    if part.startswith('test') or 'package' in part.lower():
                        if i < len(path_parts):
                            relative_path = '/'.join(path_parts[i:])
                            break
                build_file_path = relative_path
            else:
                build_file_path = file_path
        else:
            # Fallback to the file path as-is
            build_file_path = file_path
            
        asset = {
            "attributes": {
                "repository": repo_url or "unknown",
                "buildFile": build_file_path,  # Use clean repository path
                "origin": "github" if "github.com" in (repo_url or "") else "unknown"
            },
            "tags": [
                {"value": "Shai-hulud"},
                {"value": "supplychain"},
                {"value": "npm-security"},
                {"value": "compromise-detection"}
            ] + [{"value": tag} for tag in self.additional_asset_tags],
            "installedSoftware": [],
            "findings": []
        }
        
        return asset
        
    def create_phoenix_finding(self, package_name: str, version: str, severity: str, 
                             compromised_versions: List[str], is_safe: bool, 
                             file_path: str, repo_url: str = None, dependency_type: str = "dependencies") -> Dict:
        """Create a Phoenix finding for a package"""
        
        # Map severity to Phoenix risk scale (1.0 - 10.0)
        risk_mapping = {
            'CRITICAL': "10.0",  # Compromised package
            'HIGH': "8.0",       # Potentially compromised
            'INFO': "1.0",       # Safe version of monitored package
            'CLEAN': "1.0"       # Clean library not affected by Shai Halud
        }
        
        risk_score = risk_mapping.get(severity, "5.0")
        
        # Create finding description with repository and file information
        repo_info = ""
        if repo_url:
            repo_info = f"Repo: {repo_url}, "
        
        # Extract just the filename/relative path for file info
        if file_path and not os.path.isabs(file_path) and not file_path.startswith('/'):
            # This is already a clean repository-relative path (from light scan mode)
            file_info = file_path
        elif os.path.isabs(file_path):
            # Try to get relative path from repository root for local files
            path_parts = file_path.split(os.sep)
            file_info = os.path.basename(file_path)  # Default to just filename
            
            # Look for test directories or other meaningful parts
            for i, part in enumerate(path_parts):
                if part.startswith('test') or 'package' in part.lower():
                    if i < len(path_parts) - 1:
                        file_info = '/'.join(path_parts[i:])
                        break
        else:
            file_info = file_path
            
        if is_safe:
            description = f"{repo_info}File: {file_info} - Safe version detected: {package_name}@{version}"
            if compromised_versions:
                description += f" (compromised versions: {', '.join(compromised_versions)})"
        elif severity == 'CLEAN':
            description = f"{repo_info}File: {file_info} - Library {package_name} version {version} is not affected by Shai Halud"
        else:
            if severity == 'CRITICAL':
                description = f"{repo_info}File: {file_info} - Compromised package detected: {package_name}@{version}"
            else:
                description = f"{repo_info}File: {file_info} - Potentially compromised package detected: {package_name}@{version}"
                
        # Create remedy recommendation
        if is_safe:
            remedy = f"Package {package_name}@{version} is using a safe version. Continue monitoring for updates."
        elif severity == 'CLEAN':
            remedy = f"Package {package_name}@{version} is clean and not affected by Shai Halud compromise. No action required, continue monitoring for future security advisories."
        else:
            if compromised_versions:
                safe_versions = [v for v in compromised_versions if v not in compromised_versions]
                if self.safe_overrides.get(package_name):
                    remedy = f"Update {package_name} to safe version {self.safe_overrides[package_name]} or latest stable version"
                else:
                    remedy = f"Remove or update {package_name} to a safe version. Avoid versions: {', '.join(compromised_versions)}"
            else:
                remedy = f"Review package {package_name} for potential security issues and consider alternatives"
                
        finding = {
            "name": f"NPM Package Security: {package_name}",
            "description": description,
            "remedy": remedy,
            "severity": risk_score,
            "location": f"{package_name}@{version}",
            "publishedDateTime": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "referenceIds": [],  # Could add CVE IDs if available
            "cwes": ["CWE-1104"],  # Use of Untrusted Inputs in a Security Decision
            "tags": [
                {"value": "Shai-hulud"},
                {"value": "supplychain"},
                {"value": "shai-hulud-compromised-package" if not is_safe and severity != 'CLEAN' else "shai-hulud-clean-library"},
                {"value": "npm-security"},
                {"value": "compromise-detection"}
            ] + [{"value": tag} for tag in self.additional_vuln_tags],
            "packages": [{"name": package_name, "version": version}],
            "details": {
                "package_name": package_name,
                "package_version": version,
                "dependency_type": dependency_type,
                "is_safe_version": is_safe or severity == 'CLEAN',
                "compromised_versions": compromised_versions,
                "scan_tool": "Shai Halud NPM Compromise Detector",
                "scan_timestamp": datetime.now().isoformat()
            }
        }
        
        return finding
        
    def get_phoenix_access_token(self) -> Optional[str]:
        """Get access token from Phoenix API"""
        if not all([self.phoenix_config.get('client_id'), 
                   self.phoenix_config.get('client_secret'),
                   self.phoenix_config.get('api_base_url')]):
            print("❌ Missing Phoenix API credentials in configuration")
            return None
            
        url = f"{self.phoenix_config['api_base_url']}/v1/auth/access_token"
        
        try:
            response = requests.get(
                url, 
                auth=HTTPBasicAuth(
                    self.phoenix_config['client_id'], 
                    self.phoenix_config['client_secret']
                ),
                timeout=30
            )
            
            if response.status_code == 200:
                token = response.json().get('token')
                print("✅ Successfully obtained Phoenix API access token")
                return token
            else:
                print(f"❌ Failed to obtain Phoenix API token: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Error obtaining Phoenix API token: {str(e)}")
            return None
            
    def import_to_phoenix(self) -> bool:
        """Import assets and findings to Phoenix Security platform"""
        if not self.enable_phoenix_import:
            return True
            
        if not self.phoenix_assets:
            print("ℹ️  No assets to import to Phoenix")
            return True
            
        token = self.get_phoenix_access_token()
        if not token:
            return False
            
        # Prepare import payload
        import_payload = {
            "importType": self.phoenix_config.get('import_type', 'new'),
            "assessment": {
                "assetType": "BUILD",
                "name": self.phoenix_config.get('assessment_name', 'NPM Compromise Detection')
            },
            "assets": self.phoenix_assets
        }
        
        # Save debug payload if debug mode is enabled
        if self.debug_mode:
            self._save_debug_payload(import_payload)
        
        url = f"{self.phoenix_config['api_base_url']}/v1/import/assets"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        try:
            print(f"🚀 Importing {len(self.phoenix_assets)} assets to Phoenix...")
            response = requests.post(
                url,
                headers=headers,
                json=import_payload,
                timeout=120
            )
            
            # Save debug response if debug mode is enabled
            if self.debug_mode:
                self._save_debug_response(response, import_payload)
            
            if response.status_code in [200, 201]:
                print("✅ Successfully imported assets and findings to Phoenix Security")
                return True
            else:
                print(f"❌ Failed to import to Phoenix: {response.status_code} - {response.text}")
                print(f"📄 Continuing with local security report generation...")
                return False
                
        except Exception as e:
            print(f"❌ Error importing to Phoenix: {str(e)}")
            print(f"📄 Continuing with local security report generation...")
            return False
    
    def _save_debug_payload(self, payload: Dict[str, Any]):
        """Save Phoenix API payload to debug file"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            debug_dir = "debug"
            
            # Save the full payload
            payload_file = os.path.join(debug_dir, f"phoenix_payload_{timestamp}.json")
            with open(payload_file, 'w', encoding='utf-8') as f:
                json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
            
            # Save assets summary
            assets_summary = {
                "total_assets": len(payload.get('assets', [])),
                "assets_with_findings": len([a for a in payload.get('assets', []) if a.get('findings')]),
                "total_findings": sum(len(a.get('findings', [])) for a in payload.get('assets', [])),
                "assessment_info": payload.get('assessment', {}),
                "import_type": payload.get('importType', 'unknown')
            }
            
            summary_file = os.path.join(debug_dir, f"phoenix_summary_{timestamp}.json")
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(assets_summary, f, indent=2, ensure_ascii=False)
            
            print(f"🐛 Debug: Payload saved to {payload_file}")
            print(f"🐛 Debug: Summary saved to {summary_file}")
            
        except Exception as e:
            print(f"⚠️  Warning: Could not save debug payload: {str(e)}")
    
    def _save_debug_response(self, response: requests.Response, original_payload: Dict[str, Any]):
        """Save Phoenix API response to debug file"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            debug_dir = "debug"
            
            # Prepare response data
            response_data = {
                "status_code": response.status_code,
                "status_text": response.reason,
                "headers": dict(response.headers),
                "url": response.url,
                "request_method": response.request.method,
                "timestamp": timestamp,
                "success": response.status_code in [200, 201]
            }
            
            # Add response body if available
            try:
                if response.text:
                    response_data["response_body"] = response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
                else:
                    response_data["response_body"] = None
            except:
                response_data["response_body"] = response.text if response.text else None
            
            # Add request summary
            response_data["request_summary"] = {
                "assets_sent": len(original_payload.get('assets', [])),
                "findings_sent": sum(len(a.get('findings', [])) for a in original_payload.get('assets', [])),
                "assessment_name": original_payload.get('assessment', {}).get('name', 'Unknown')
            }
            
            response_file = os.path.join(debug_dir, f"phoenix_response_{timestamp}.json")
            with open(response_file, 'w', encoding='utf-8') as f:
                json.dump(response_data, f, indent=2, ensure_ascii=False, default=str)
            
            print(f"🐛 Debug: Response saved to {response_file}")
            
            # Print summary to console
            if response.status_code in [200, 201]:
                print(f"🐛 Debug: ✅ Phoenix import successful (Status: {response.status_code})")
            else:
                print(f"🐛 Debug: ❌ Phoenix import failed (Status: {response.status_code})")
                print(f"🐛 Debug: Error details saved in {response_file}")
            
        except Exception as e:
            print(f"⚠️  Warning: Could not save debug response: {str(e)}")
    
    def cleanup_cloned_repositories(self):
        """Clean up cloned repositories if delete_local_files is enabled"""
        if not self.delete_local_files:
            return
            
        if not self.cloned_repositories:
            print("🗑️  No cloned repositories to clean up")
            return
            
        print(f"🗑️  Cleaning up {len(self.cloned_repositories)} cloned repositories...")
        
        for repo in self.cloned_repositories:
            repo_path = repo['local_path']
            repo_name = repo['name']
            
            try:
                if os.path.exists(repo_path) and os.path.isdir(repo_path):
                    shutil.rmtree(repo_path)
                    print(f"   ✅ Deleted: {repo_name} ({repo_path})")
                else:
                    print(f"   ⚠️  Not found: {repo_name} ({repo_path})")
            except Exception as e:
                print(f"   ❌ Failed to delete {repo_name}: {str(e)}")
                
        print(f"🗑️  Cleanup complete!")

    def load_compromise_data(self):
        """Load compromised package data from JSON configuration"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                self.incident_metadata = data.get('incident_metadata', {})
                self.compromised_packages = data.get('compromised_packages', {})
                self.potentially_compromised = set(data.get('potentially_compromised_packages', []))
                self.malicious_urls = data.get('malicious_indicators', {}).get('domains', [])
                self.crypto_indicators = data.get('crypto_indicators', [])
                self.suspicious_patterns = data.get('suspicious_patterns', [])
                self.safe_overrides = data.get('remediation', {}).get('safe_overrides', {})
                
                print(f"✅ Loaded compromise data: {len(self.compromised_packages)} packages with specific versions")
                print(f"✅ Loaded {len(self.potentially_compromised)} potentially compromised packages")
            else:
                print(f"⚠️  Configuration file {self.config_file} not found, using default data")
                self._load_default_data()
                
        except Exception as e:
            print(f"❌ Error loading compromise data: {str(e)}")
            self._load_default_data()
            
    def _load_default_data(self):
        """Load default compromise data if config file is not available"""
        self.compromised_packages = {
            "@ctrl/tinycolor": {"compromised_versions": ["4.1.1", "4.1.2"], "safe_version": "4.1.0"},
            "angulartics2": {"compromised_versions": ["14.1.1", "14.1.2"], "safe_version": "14.1.0"},
            "@ctrl/deluge": {"compromised_versions": ["7.2.1", "7.2.2"], "safe_version": "7.2.0"},
            "@ahmedhfarag/ngx-perfect-scrollbar": {"compromised_versions": ["20.0.20"], "safe_version": "20.0.19"},
            "@art-ws/common": {"compromised_versions": ["2.0.28"], "safe_version": "2.0.27"},
            "@crowdstrike/commitlint": {"compromised_versions": ["8.1.1", "8.1.2"], "safe_version": "8.1.0"},
            "@nativescript-community/text": {"compromised_versions": ["1.6.9", "1.6.10", "1.6.11", "1.6.12", "1.6.13"], "safe_version": "1.6.8"},
            "ngx-color": {"compromised_versions": ["10.0.1", "10.0.2"], "safe_version": "10.0.0"},
            "ts-gaussian": {"compromised_versions": ["3.0.5", "3.0.6"], "safe_version": "3.0.4"},
            "encounter-playground": {"compromised_versions": ["0.0.2", "0.0.3", "0.0.4", "0.0.5"], "safe_version": "0.0.1"},
        }
        self.potentially_compromised = set([])  # All packages now have specific compromised versions
        self.malicious_urls = ["npmjs.help", "support@npmjs.help"]
        self.crypto_indicators = ["cryptocurrency", "wallet", "private key", "bitcoin", "ethereum", "metamask", "web3", "blockchain"]
        self.suspicious_patterns = []
        self.safe_overrides = {
            "@ctrl/tinycolor": "4.1.0",
            "angulartics2": "14.1.0",
            "@ctrl/deluge": "7.2.0",
            "@ahmedhfarag/ngx-perfect-scrollbar": "20.0.19",
            "@art-ws/common": "2.0.27",
            "@crowdstrike/commitlint": "8.1.0",
            "@nativescript-community/text": "1.6.8",
            "ngx-color": "10.0.0",
            "ts-gaussian": "3.0.4",
            "encounter-playground": "0.0.1"
        }
        
    def log_finding(self, severity: str, message: str, file_path: str = None, details: Dict = None):
        """Log a security finding"""
        finding = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'message': message,
            'file': file_path,
            'details': details or {}
        }
        self.findings.append(finding)
        
    def enable_full_tree_analysis(self, enable: bool = True):
        """Enable or disable full dependency tree analysis"""
        self.full_tree_analysis = enable
        
    def enable_phoenix_integration(self, enable: bool = True):
        """Enable or disable Phoenix API integration"""
        self.enable_phoenix_import = enable
        
    def enable_light_scan(self, enable: bool = True):
        """Enable or disable light scan mode (NPM files only)"""
        self.light_scan_mode = enable
        
    def enable_folder_organization(self, enable: bool = True):
        """Enable or disable organized folder structure for GitHub pulls and results"""
        self.organize_folders = enable
        if enable:
            # Create directories if they don't exist
            os.makedirs(self.github_pull_dir, exist_ok=True)
            os.makedirs(self.result_dir, exist_ok=True)
            print(f"📁 Folder organization enabled:")
            print(f"   GitHub pulls: {self.github_pull_dir}")
            print(f"   Results: {self.result_dir}")
    
    def enable_debug_mode(self, enable: bool = True):
        """Enable or disable debug mode for Phoenix API payloads and responses"""
        self.debug_mode = enable
        if enable:
            # Create debug directory if it doesn't exist
            debug_dir = "debug"
            os.makedirs(debug_dir, exist_ok=True)
            print(f"🐛 Debug mode enabled: Phoenix API payloads and responses will be saved to '{debug_dir}/' directory")
    
    def enable_delete_local_files(self, enable: bool = True):
        """Enable or disable deletion of cloned repositories after scan"""
        self.delete_local_files = enable
        if enable:
            print(f"🗑️  Delete local files enabled: Cloned repositories will be removed after scanning")
    
    def enable_detail_log(self, enable: bool = True):
        """Enable or disable detailed logging (show all libraries without truncation)"""
        self.detail_log = enable
        if enable:
            print(f"📋 Detail log enabled: All libraries will be shown in the report")
    
    def enable_tmp_mode(self, enable: bool = True):
        """Enable or disable /tmp usage for cloning (legacy mode)"""
        self.use_tmp = enable
        if enable:
            print(f"📁 Legacy /tmp mode enabled: Repositories will be cloned to /tmp/")
            
    def enable_import_all(self, enable: bool = True):
        """Enable or disable importing all libraries including clean ones"""
        self.import_all_libraries = enable
        if enable:
            print(f"📦 Import all libraries enabled: Clean libraries will get CVSS 1.0 findings")
            
    def set_additional_tags(self, vuln_tags: List[str] = None, asset_tags: List[str] = None):
        """Set additional tags for vulnerabilities and assets"""
        if vuln_tags:
            self.additional_vuln_tags.extend(vuln_tags)
            print(f"🏷️  Added vulnerability tags: {', '.join(vuln_tags)}")
        if asset_tags:
            self.additional_asset_tags.extend(asset_tags)
            print(f"🏷️  Added asset tags: {', '.join(asset_tags)}")
        
    def get_repo_url_from_path(self, file_path: str) -> Optional[str]:
        """Extract repository URL from local file path"""
        try:
            # Convert to absolute path
            abs_path = os.path.abspath(file_path)
            
            # Look for .git directory in the path hierarchy
            current_path = abs_path
            while current_path and current_path != '/':
                git_dir = os.path.join(current_path, '.git')
                if os.path.exists(git_dir):
                    # Try to get remote URL from git config
                    try:
                        result = subprocess.run(
                            ['git', 'remote', 'get-url', 'origin'],
                            cwd=current_path,
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        if result.returncode == 0:
                            remote_url = result.stdout.strip()
                            # Convert SSH to HTTPS format
                            if remote_url.startswith('git@github.com:'):
                                remote_url = remote_url.replace('git@github.com:', 'https://github.com/')
                                if remote_url.endswith('.git'):
                                    remote_url = remote_url[:-4]
                            return remote_url
                    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                        pass
                    break
                current_path = os.path.dirname(current_path)
            
            # Fallback: try to infer from path patterns
            if '/GitHub/' in abs_path or '/github/' in abs_path:
                # Extract GitHub repository name from path
                parts = abs_path.split('/')
                github_index = -1
                for i, part in enumerate(parts):
                    if part.lower() == 'github':
                        github_index = i
                        break
                        
                if github_index != -1 and len(parts) > github_index + 1:
                    repo_name = parts[github_index + 1]
                    # Try to guess the organization (could be username)
                    username = parts[github_index - 1] if github_index > 0 else 'unknown'
                    return f"https://github.com/{username}/{repo_name}"
            
            # Return the directory name as fallback
            return f"local://{os.path.basename(os.path.dirname(abs_path))}"
            
        except Exception as e:
            print(f"⚠️  Could not determine repository URL for {file_path}: {str(e)}")
            return f"local://{os.path.basename(os.path.dirname(file_path))}"
        
    def normalize_version(self, version: str) -> str:
        """Normalize version string by removing prefixes like ^, ~, >=, etc."""
        if not version:
            return ""
        # Remove common npm version prefixes
        cleaned = re.sub(r'^[^\d]*', '', str(version))
        # Handle version ranges like "1.0.0 - 2.0.0"
        if ' - ' in cleaned:
            cleaned = cleaned.split(' - ')[0]
        # Handle || operators
        if ' || ' in cleaned:
            cleaned = cleaned.split(' || ')[0]
        return cleaned.strip()
        
    def check_package_compromise(self, package_name: str, version: str) -> Tuple[bool, str, List[str]]:
        """
        Check if a package version is compromised
        Returns: (is_compromised, severity, compromised_versions_list)
        """
        normalized_version = self.normalize_version(version)
        
        # Check exact compromised packages with versions
        if package_name in self.compromised_packages:
            pkg_data = self.compromised_packages[package_name]
            compromised_versions = pkg_data.get('compromised_versions', [])
            
            if normalized_version in compromised_versions:
                return True, 'CRITICAL', compromised_versions
            else:
                # Package is in our list but version is different - could be safe
                return False, 'INFO', compromised_versions
                
        # Check potentially compromised packages (no specific version)
        if package_name in self.potentially_compromised:
            return True, 'HIGH', []
            
        return False, '', []

    def process_package_file(self, file_path: str, repo_url: str = None, original_repo_path: str = None) -> Dict:
        """Process a single package file and create Phoenix asset with findings"""
        # Track this file as scanned
        self.scanned_files.append(file_path)
        
        # Extract repository URL if not provided
        if not repo_url:
            repo_url = self.get_repo_url_from_path(file_path)
            
        # Create Phoenix asset - use original repo path if available (for light scan mode)
        asset_file_path = original_repo_path if original_repo_path else file_path
        asset = self.create_phoenix_asset(asset_file_path, repo_url)
        
        print(f"📦 Processing: {file_path}")
        if repo_url:
            print(f"🔗 Repository: {repo_url}")
        
        # Scan the file for compromised packages
        if file_path.endswith('package.json'):
            findings = self.scan_package_json(file_path)
        elif file_path.endswith('package-lock.json') or file_path.endswith('yarn.lock'):
            findings = self.scan_lock_file(file_path)
        else:
            findings = []
            
        # Process findings and create Phoenix findings
        for finding in findings:
            package_name = finding.get('package', '')
            version = finding.get('version', '')
            dep_type = finding.get('type', 'dependencies')
            
            # Determine if this is a safe or compromised package
            is_compromised, severity, compromised_versions = self.check_package_compromise(package_name, version)
            is_safe = not is_compromised and package_name in self.compromised_packages
            
            if severity == 'INFO':
                is_safe = True
                
            # Create Phoenix finding - use asset file path for consistent location
            phoenix_finding = self.create_phoenix_finding(
                package_name, version, severity or 'INFO', 
                compromised_versions, is_safe, asset_file_path, repo_url, dep_type
            )
            
            asset['findings'].append(phoenix_finding)
            
            # Add to findings list for reporting (with repo and file info)
            if is_compromised or is_safe:
                # Create unique identifier to prevent duplicates
                finding_id = f"{package_name}@{version}:{asset_file_path}:{dep_type}"
                
                # Check if we already have this finding
                existing_finding = any(
                    f.get('details', {}).get('package') == package_name and
                    f.get('details', {}).get('version') == version and
                    f.get('file') == asset_file_path and
                    f.get('details', {}).get('dependency_type') == dep_type
                    for f in self.findings
                )
                
                if not existing_finding:
                    report_finding = {
                        'severity': severity or 'INFO',
                        'message': f"Safe version detected: {package_name}@{version}" if is_safe else f"Compromised package detected: {package_name}@{version}",
                        'file': asset_file_path,  # Use repository path for consistent reporting
                        'repo_url': repo_url,
                        'details': {
                            'package': package_name,
                            'version': version if not is_safe else None,
                            'safe_version': version if is_safe else None,
                            'dependency_type': dep_type,
                            'compromised_versions': compromised_versions
                        }
                    }
                    self.findings.append(report_finding)
                    
        # Create findings for ALL clean libraries if --import-all is enabled
        # This ensures every library gets a Phoenix finding, even if it's clean
        if self.import_all_libraries:
            for lib in self.clean_libraries:
                if lib.get('file') == file_path:  # Only process libraries from this specific file
                    phoenix_finding = self.create_phoenix_finding(
                        lib['name'], lib['clean_version'], 'CLEAN', 
                        [], False, asset_file_path, repo_url, lib['type']
                    )
                    asset['findings'].append(phoenix_finding)
                    
                    # Add clean library to findings list for reporting
                    report_finding = {
                        'severity': 'CLEAN',
                        'message': f"Library {lib['name']} version {lib['clean_version']} is not affected by Shai Halud",
                        'file': asset_file_path,  # Use repository path for consistent reporting
                        'repo_url': repo_url,
                        'details': {
                            'package': lib['name'],
                            'version': lib['clean_version'],
                            'dependency_type': lib['type'],
                            'compromised_versions': []
                        }
                    }
                    self.findings.append(report_finding)
            
        # Add installed software information
        # TODO - Review this. installedSoftware is for OS packages and apps
        #self._add_installed_software_to_asset(asset, file_path)
        
        return asset
        
    def _add_installed_software_to_asset(self, asset: Dict, file_path: str):
        """Add installed software information to asset based on package file"""
        try:
            if file_path.endswith('package.json'):
                with open(file_path, 'r', encoding='utf-8') as f:
                    package_data = json.load(f)
                    
                # Add dependencies as installed software
                for dep_type in ['dependencies', 'devDependencies', 'peerDependencies']:
                    if dep_type in package_data:
                        for package_name, version in package_data[dep_type].items():
                            clean_version = self.normalize_version(version)
                            if clean_version:
                                software = {
                                    "vendor": "npm",
                                    "name": package_name,
                                    "version": clean_version
                                }
                                asset['installedSoftware'].append(software)
                                
        except Exception as e:
            print(f"⚠️  Could not extract installed software from {file_path}: {str(e)}")

    def scan_package_json(self, file_path: str) -> List[Dict]:
        """Scan package.json for compromised packages"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                package_data = json.load(f)
                
            # Check direct dependencies
            for dep_type in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
                if dep_type in package_data:
                    for package_name, version in package_data[dep_type].items():
                        clean_version = self.normalize_version(version)
                        
                        # Track all scanned libraries
                        library_info = {
                            'name': package_name,
                            'version': version,
                            'clean_version': clean_version,
                            'type': dep_type,
                            'file': file_path,
                            'status': 'clean',  # Default to clean, will be updated if compromised
                            'repo_url': self.get_repo_url_from_path(file_path) if hasattr(self, 'get_repo_url_from_path') else 'unknown'
                        }
                        self.all_scanned_libraries.append(library_info)
                        
                        # Check if package is compromised
                        is_compromised, severity, compromised_versions = self.check_package_compromise(package_name, clean_version)
                        
                        if is_compromised or (package_name in self.compromised_packages):
                            # Update status to compromised
                            library_info['status'] = 'compromised'
                            library_info['severity'] = severity
                            library_info['compromised_versions'] = compromised_versions
                            self.compromised_libraries.append(library_info.copy())
                            
                            findings.append({
                                'package': package_name,
                                'version': version,
                                'type': dep_type,
                                'file': file_path,
                                'severity': severity,
                                'compromised_versions': compromised_versions
                            })
                        else:
                            # This is a clean library
                            self.clean_libraries.append(library_info.copy())
                            
                        # Log finding (for compromised packages only)
                        if is_compromised and severity == 'CRITICAL':
                            self.log_finding(
                                'CRITICAL',
                                f'Compromised package detected: {package_name}@{version}',
                                file_path,
                                {
                                    'package': package_name,
                                    'version': version,
                                    'dependency_type': dep_type,
                                    'compromised_versions': compromised_versions
                                }
                            )
                            self.dependency_stats['compromised_packages_found'] += 1
                        elif is_compromised and severity == 'INFO':
                            self.log_finding(
                                'INFO',
                                f'Safe version detected: {package_name}@{version} (compromised: {", ".join(compromised_versions)})',
                                file_path,
                                {
                                    'package': package_name,
                                    'safe_version': version,
                                    'compromised_versions': compromised_versions,
                                    'dependency_type': dep_type
                                }
                            )
                            self.dependency_stats['safe_packages_found'] += 1
                                
        except (json.JSONDecodeError, FileNotFoundError) as e:
            self.log_finding('ERROR', f'Failed to parse {file_path}: {str(e)}', file_path)
            
        return findings
        
    def scan_lock_file(self, file_path: str) -> List[Dict]:
        """Scan package-lock.json or yarn.lock for compromised packages"""
        findings = []
        
        try:
            if file_path.endswith('package-lock.json'):
                findings.extend(self._scan_package_lock(file_path))
            elif file_path.endswith('yarn.lock'):
                findings.extend(self._scan_yarn_lock(file_path))
                
        except Exception as e:
            self.log_finding('ERROR', f'Failed to scan lock file {file_path}: {str(e)}', file_path)
            
        return findings
        
    def _scan_package_lock(self, file_path: str) -> List[Dict]:
        """Scan package-lock.json specifically"""
        findings = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            lock_data = json.load(f)
            
        # Check packages in lockfile v2/v3 format
        if 'packages' in lock_data:
            for package_path, package_info in lock_data['packages'].items():
                if package_path.startswith('node_modules/'):
                    # Handle scoped packages correctly
                    path_parts = package_path.replace('node_modules/', '').split('/')
                    if path_parts[0].startswith('@'):
                        package_name = '/'.join(path_parts[:2])  # @scope/name
                    else:
                        package_name = path_parts[0]
                        
                    version = package_info.get('version', '')
                    
                    if version:
                        # Check if package is compromised
                        is_compromised, severity, compromised_versions = self.check_package_compromise(package_name, version)
                        
                        if is_compromised or (package_name in self.compromised_packages):
                            findings.append({
                                'package': package_name,
                                'version': version,
                                'file': file_path,
                                'path': package_path,
                                'severity': severity,
                                'compromised_versions': compromised_versions
                            })
                            
                            # Log finding
                            if severity == 'CRITICAL':
                                self.log_finding(
                                    'CRITICAL',
                                    f'Compromised package in lock file: {package_name}@{version}',
                                    file_path,
                                    {
                                        'package': package_name, 
                                        'version': version, 
                                        'path': package_path,
                                        'compromised_versions': compromised_versions
                                    }
                                )
                                self.dependency_stats['compromised_packages_found'] += 1
                            elif severity == 'INFO':
                                self.log_finding(
                                    'INFO',
                                    f'Safe version in lock file: {package_name}@{version} (compromised: {", ".join(compromised_versions)})',
                                    file_path,
                                    {
                                        'package': package_name,
                                        'safe_version': version,
                                        'compromised_versions': compromised_versions,
                                        'path': package_path
                                    }
                                )
                                self.dependency_stats['safe_packages_found'] += 1
                                
        return findings

    def _scan_yarn_lock(self, file_path: str) -> List[Dict]:
        """Scan yarn.lock file"""
        findings = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Parse yarn.lock format for our compromised packages
        all_packages = {**self.compromised_packages}
        for pkg_name in self.potentially_compromised:
            all_packages[pkg_name] = {"compromised_versions": [], "safe_version": "unknown"}
            
        for package_name, pkg_data in all_packages.items():
            compromised_versions = pkg_data.get('compromised_versions', [])
            
            # Look for package entries in yarn.lock
            escaped_name = re.escape(package_name)
            
            if compromised_versions:
                # Check for specific compromised versions
                for comp_version in compromised_versions:
                    pattern = rf'^{escaped_name}@.*?:\s*\n(?:\s+.*\n)*?\s+version\s+"?{re.escape(comp_version)}"?'
                    matches = re.findall(pattern, content, re.MULTILINE)
                    
                    if matches:
                        findings.append({
                            'package': package_name,
                            'version': comp_version,
                            'file': file_path,
                            'severity': 'CRITICAL',
                            'compromised_versions': compromised_versions
                        })
                        
                        self.log_finding(
                            'CRITICAL',
                            f'Compromised package in yarn.lock: {package_name}@{comp_version}',
                            file_path,
                            {'package': package_name, 'version': comp_version}
                        )
                        self.dependency_stats['compromised_packages_found'] += 1
                        
        return findings

    def parse_github_url(self, repo_url: str) -> Tuple[Optional[str], Optional[str]]:
        """Parse GitHub URL to extract owner and repository name"""
        try:
            # Handle various GitHub URL formats
            if repo_url.startswith('git@github.com:'):
                # SSH format: git@github.com:owner/repo.git
                path = repo_url.replace('git@github.com:', '').replace('.git', '')
            elif 'github.com' in repo_url:
                # HTTPS format: https://github.com/owner/repo
                parsed = urlparse(repo_url)
                path = parsed.path.strip('/')
            else:
                return None, None
                
            parts = path.split('/')
            if len(parts) >= 2:
                return parts[0], parts[1]
                
        except Exception as e:
            print(f"⚠️  Error parsing GitHub URL {repo_url}: {str(e)}")
            
        return None, None
        
    def get_github_api_headers(self, use_auth: bool = True) -> Dict[str, str]:
        """Get headers for GitHub API requests
        
        Args:
            use_auth: Whether to include authentication. Set to False for public repo fallback.
        """
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Shai-Halud-NPM-Security-Scanner/1.0'
        }
        
        if use_auth and self.github_token and self.github_token != 'your_github_token_here':
            headers['Authorization'] = f'token {self.github_token}'
            
        return headers
        
    def find_npm_files_in_repo(self, owner: str, repo: str) -> List[Dict]:
        """Find NPM package files in a GitHub repository using API"""
        npm_files = []
        
        try:
            # Try GitHub API search first
            npm_files = self._search_github_api(owner, repo)
            
            # If API search failed, try GitHub API fallback method for public repos
            if not npm_files:
                print(f"🔄 Trying GitHub API fallback method for public repository...")
                npm_files = self._fallback_github_search(owner, repo)
                
                # If GitHub API completely failed, try direct raw access
                if not npm_files:
                    print(f"🔄 GitHub API failed completely, trying direct raw access...")
                    # Track API failure
                    self.api_failed_repositories.append({
                        'owner': owner,
                        'repo': repo,
                        'url': f"https://github.com/{owner}/{repo}",
                        'reason': 'github_api_failed'
                    })
                    npm_files = self._direct_raw_github_access(owner, repo)
                    
                    # If direct access also failed, track complete failure
                    if not npm_files:
                        self.completely_failed_repositories.append({
                            'owner': owner,
                            'repo': repo,
                            'url': f"https://github.com/{owner}/{repo}",
                            'reason': 'all_methods_failed'
                        })
                    
        except Exception as e:
            print(f"❌ Error searching for NPM files in {owner}/{repo}: {str(e)}")
            self.completely_failed_repositories.append({
                'owner': owner,
                'repo': repo,
                'url': f"https://github.com/{owner}/{repo}",
                'reason': f'exception: {str(e)}'
            })
            
        return npm_files
        
    def _search_github_api(self, owner: str, repo: str) -> List[Dict]:
        """Search for NPM files using GitHub API with authentication fallback"""
        npm_files = []
        
        # Search for package.json files
        search_queries = [
            'filename:package.json',
            'filename:package-lock.json',
            'filename:yarn.lock'
        ]
        
        # Try with authentication first (if token is available and valid)
        use_auth = self.github_token and self.github_token != 'your_github_token_here'
        headers = self.get_github_api_headers(use_auth=use_auth)
        
        auth_failed = False
        
        for query in search_queries:
            url = f"https://api.github.com/search/code"
            params = {
                'q': f'{query} repo:{owner}/{repo}',
                'per_page': 100
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get('items', []):
                    npm_files.append({
                        'name': item['name'],
                        'path': item['path'],
                        'download_url': item.get('download_url'),
                        'url': item['url'],
                        'type': self._get_file_type(item['name'])
                    })
            elif response.status_code == 401 and use_auth:
                print(f"⚠️  GitHub API authentication failed, trying without authentication for public repository...")
                auth_failed = True
                break
            elif response.status_code == 403:
                if use_auth:
                    print(f"⚠️  GitHub API rate limit exceeded with authentication")
                else:
                    print(f"⚠️  GitHub API rate limit exceeded. Consider setting a valid GITHUB_TOKEN environment variable")
                break
            elif response.status_code == 422:
                print(f"⚠️  GitHub API search not available for this repository (private/empty)")
                break
            else:
                print(f"⚠️  GitHub API search failed: {response.status_code}")
                if use_auth and response.status_code == 401:
                    auth_failed = True
                break
        
        # If authentication failed, try again without authentication for public repositories
        if auth_failed and use_auth:
            print(f"🔄 Retrying without authentication for public repository access...")
            headers_no_auth = self.get_github_api_headers(use_auth=False)
            
            for query in search_queries:
                url = f"https://api.github.com/search/code"
                params = {
                    'q': f'{query} repo:{owner}/{repo}',
                    'per_page': 100
                }
                
                response = requests.get(url, headers=headers_no_auth, params=params, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    for item in data.get('items', []):
                        npm_files.append({
                            'name': item['name'],
                            'path': item['path'],
                            'download_url': item.get('download_url'),
                            'url': item['url'],
                            'type': self._get_file_type(item['name'])
                        })
                elif response.status_code == 403:
                    print(f"⚠️  GitHub API rate limit exceeded (unauthenticated)")
                    break
                elif response.status_code == 422:
                    print(f"⚠️  Repository not accessible or empty")
                    break
                else:
                    print(f"⚠️  GitHub API search failed without auth: {response.status_code}")
                    break
                
        return npm_files
        
    def _fallback_github_search(self, owner: str, repo: str) -> List[Dict]:
        """Fallback method: try to access common NPM file locations directly"""
        npm_files = []
        common_paths = [
            'package.json',
            'package-lock.json',
            'yarn.lock',
            'frontend/package.json',
            'backend/package.json',
            'client/package.json',
            'server/package.json',
            'app/package.json',
            'src/package.json'
        ]
        
        # Try without authentication first for public repositories
        use_auth = self.github_token and self.github_token != 'your_github_token_here'
        headers = self.get_github_api_headers(use_auth=False)  # Start without auth for public repos
        
        for path in common_paths:
            try:
                url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
                response = requests.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    npm_files.append({
                        'name': data['name'],
                        'path': data['path'],
                        'download_url': data.get('download_url'),
                        'url': data['url'],
                        'type': self._get_file_type(data['name'])
                    })
                    print(f"✅ Found {path}")
                    
            except Exception as e:
                continue  # Ignore errors for individual files
                
        return npm_files
        
    def _direct_raw_github_access(self, owner: str, repo: str) -> List[Dict]:
        """Direct fallback method: Access raw.githubusercontent.com for common NPM files"""
        npm_files = []
        common_files = [
            'package.json',
            'package-lock.json', 
            'yarn.lock'
        ]
        
        base_url = f"https://raw.githubusercontent.com/{owner}/{repo}/master"
        
        print(f"🔄 Fallback: Trying direct raw GitHub access for {owner}/{repo}")
        
        for filename in common_files:
            try:
                file_url = f"{base_url}/{filename}"
                response = requests.get(file_url, timeout=10)
                
                if response.status_code == 200:
                    # Verify it's actually JSON/text content (not HTML error page)
                    content = response.text.strip()
                    if content and (filename.endswith('.json') and content.startswith('{') or filename.endswith('.lock')):
                        npm_files.append({
                            'name': filename,
                            'path': filename,
                            'download_url': file_url,
                            'url': file_url,
                            'type': self._get_file_type(filename),
                            'content': content  # Store content directly for direct access
                        })
                        print(f"✅ Direct access found: {filename}")
                    
            except Exception as e:
                continue  # Ignore errors for individual files
                
        if npm_files:
            # Track successful fallback
            self.fallback_success_repositories.append({
                'owner': owner,
                'repo': repo,
                'url': f"https://github.com/{owner}/{repo}",
                'files_found': len(npm_files),
                'access_method': 'direct_raw_github'
            })
            print(f"✅ Fallback successful: Found {len(npm_files)} NPM file(s) via direct access")
        else:
            print(f"❌ Fallback failed: No NPM files accessible via direct access")
            
        return npm_files
        
    def _get_file_type(self, filename: str) -> str:
        """Determine file type based on filename"""
        if filename == 'package.json':
            return 'package'
        elif filename == 'package-lock.json':
            return 'lock'
        elif filename == 'yarn.lock':
            return 'yarn_lock'
        else:
            return 'unknown'
            
    def download_npm_file(self, file_info: Dict, repo_url: str, temp_dir: str) -> Optional[str]:
        """Download a single NPM file from GitHub"""
        
        # If we have direct content (from raw GitHub access), use it directly
        if 'content' in file_info:
            try:
                # Create file path
                file_path = os.path.join(temp_dir, file_info['path'])
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                
                # Write content to file
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(file_info['content'])
                    
                print(f"✅ Direct content saved: {file_info['path']}")
                return file_path
                
            except Exception as e:
                print(f"❌ Error saving direct content for {file_info['path']}: {str(e)}")
                return None
        
        # Original download logic for API-based files
        max_retries = 3
        timeout = 15  # Reduced timeout
        
        for attempt in range(max_retries):
            try:
                if file_info.get('download_url'):
                    # Use direct download URL if available
                    response = requests.get(file_info['download_url'], timeout=timeout)
                else:
                    # Use GitHub API to get file content
                    headers = self.get_github_api_headers()
                    response = requests.get(file_info['url'], headers=headers, timeout=timeout)
                
                if response.status_code == 200:
                    # Check if response is JSON (API response) or direct text
                    try:
                        content_data = response.json()
                        if content_data.get('encoding') == 'base64':
                            content = base64.b64decode(content_data['content']).decode('utf-8')
                        else:
                            content = content_data.get('content', '')
                    except:
                        # Direct text response
                        content = response.text
                        
                    # Validate content is not empty
                    if not content or content.strip() == '':
                        if attempt < max_retries - 1:
                            print(f"⚠️  Empty content on attempt {attempt + 1} for {file_info['path']}, retrying...")
                            continue
                        else:
                            print(f"❌ Empty content for {file_info['path']} after {max_retries} attempts")
                            return None
                        
                    # Create file path
                    file_path = os.path.join(temp_dir, file_info['path'])
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    
                    # Write content to file
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                        
                    return file_path
                else:
                    if attempt < max_retries - 1:
                        print(f"⚠️  Download attempt {attempt + 1} failed for {file_info['path']}: {response.status_code}, retrying...")
                        continue
                    else:
                        print(f"❌ Failed to download {file_info['path']}: {response.status_code}")
                        
            except requests.exceptions.Timeout:
                if attempt < max_retries - 1:
                    print(f"⚠️  Timeout on attempt {attempt + 1} for {file_info['path']}, retrying...")
                    continue
                else:
                    print(f"❌ Download timeout for {file_info['path']} after {max_retries} attempts")
                    
            except Exception as e:
                if attempt < max_retries - 1:
                    print(f"⚠️  Error on attempt {attempt + 1} for {file_info['path']}: {str(e)}, retrying...")
                    continue
                else:
                    print(f"❌ Error downloading {file_info['path']}: {str(e)}")
                    
        return None
        
    def light_scan_repository(self, repo_url: str) -> List[Dict]:
        """Perform light scan of repository (NPM files only)"""
        assets = []
        
        print(f"🔍 Light scanning repository: {repo_url}")
        
        # Parse GitHub URL
        owner, repo = self.parse_github_url(repo_url)
        if not owner or not repo:
            print(f"❌ Could not parse GitHub URL: {repo_url}")
            return assets
            
        # Find NPM files in repository
        npm_files = self.find_npm_files_in_repo(owner, repo)
        if not npm_files:
            print(f"📦 No NPM files found in {owner}/{repo}")
            return assets
            
        print(f"📁 Found {len(npm_files)} NPM file(s) in {owner}/{repo}")
        
        # Create directory for downloaded files
        if self.organize_folders:
            # Use organized folder structure
            repo_dir = os.path.join(self.github_pull_dir, repo)
            os.makedirs(repo_dir, exist_ok=True)
            temp_dir = repo_dir
            cleanup_temp = False  # Don't cleanup organized folders
        else:
            # Use temporary directory (original behavior)
            temp_dir = tempfile.mkdtemp(prefix=f"light_scan_{repo}_")
            cleanup_temp = True
        
        try:
            # Download and process each NPM file
            for file_info in npm_files:
                print(f"📥 Downloading {file_info['path']}")
                
                file_path = self.download_npm_file(file_info, repo_url, temp_dir)
                if file_path:
                    # Process the file - pass original repository path for Phoenix asset
                    original_repo_path = file_info['path']  # This is the path within the repository
                    asset = self.process_package_file(file_path, repo_url, original_repo_path)
                    if asset:
                        assets.append(asset)
                        
        finally:
            # Clean up temporary directory only if not using organized folders
            if cleanup_temp:
                try:
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    print(f"⚠️  Could not clean up temp directory {temp_dir}: {str(e)}")
            else:
                print(f"📁 Repository files saved to: {temp_dir}")
                
        return assets
        
    def process_folder_list(self, folder_list_file: str) -> List[Dict]:
        """Process multiple local folders from a list file"""
        assets = []
        
        if not os.path.exists(folder_list_file):
            print(f"❌ Folder list file not found: {folder_list_file}")
            return assets
            
        try:
            with open(folder_list_file, 'r') as f:
                folders = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
            print(f"📁 Processing {len(folders)} folders from {folder_list_file}")
            
            for folder_path in folders:
                print(f"\n🔄 Processing folder: {folder_path}")
                
                if not os.path.exists(folder_path):
                    print(f"⚠️  Folder not found: {folder_path}")
                    continue
                    
                if not os.path.isdir(folder_path):
                    print(f"⚠️  Path is not a directory: {folder_path}")
                    continue
                
                # Find package files in the folder
                package_files = []
                for pattern in ['package.json', 'package-lock.json']:
                    package_files.extend(Path(folder_path).rglob(pattern))
                    
                if not package_files:
                    print(f"📦 No NPM files found in {folder_path}")
                    continue
                    
                for package_file in package_files:
                    # Get repository URL for this local folder
                    repo_url = self.get_repo_url_from_path(str(package_file.parent))
                    asset = self.process_package_file(str(package_file), repo_url)
                    if asset:
                        assets.append(asset)
                        
        except Exception as e:
            print(f"❌ Error processing folder list: {str(e)}")
            
        return assets
        
    def process_multiple_folders(self, folder_paths: List[str]) -> List[Dict]:
        """Process multiple local folders specified directly"""
        assets = []
        
        print(f"📁 Processing {len(folder_paths)} folders")
        
        for folder_path in folder_paths:
            print(f"\n🔄 Processing folder: {folder_path}")
            
            if not os.path.exists(folder_path):
                print(f"⚠️  Folder not found: {folder_path}")
                continue
                
            if not os.path.isdir(folder_path):
                print(f"⚠️  Path is not a directory: {folder_path}")
                continue
            
            # Find package files in the folder
            package_files = []
            for pattern in ['package.json', 'package-lock.json']:
                package_files.extend(Path(folder_path).rglob(pattern))
                
            if not package_files:
                print(f"📦 No NPM files found in {folder_path}")
                continue
                
            for package_file in package_files:
                # Get repository URL for this local folder
                repo_url = self.get_repo_url_from_path(str(package_file.parent))
                asset = self.process_package_file(str(package_file), repo_url)
                if asset:
                    assets.append(asset)
                    
        return assets

    def process_repository_list(self, repo_list_file: str) -> List[Dict]:
        """Process multiple repositories from a list file"""
        assets = []
        
        if not os.path.exists(repo_list_file):
            print(f"❌ Repository list file not found: {repo_list_file}")
            return assets
            
        try:
            with open(repo_list_file, 'r') as f:
                repos = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
            print(f"📋 Processing {len(repos)} repositories from {repo_list_file}")
            
            for repo_url in repos:
                print(f"\n🔄 Processing repository: {repo_url}")
                
                if self.light_scan_mode:
                    # Light scan mode - download only NPM files
                    repo_assets = self.light_scan_repository(repo_url)
                    assets.extend(repo_assets)
                else:
                    # Full scan mode - clone or find the repository
                    repo_path = self._get_or_clone_repository(repo_url)
                    
                    if repo_path:
                        # Find package files in the repository
                        package_files = []
                        for pattern in ['package.json', 'package-lock.json']:
                            package_files.extend(Path(repo_path).rglob(pattern))
                            
                        for package_file in package_files:
                            asset = self.process_package_file(str(package_file), repo_url)
                            assets.append(asset)
                        
        except Exception as e:
            print(f"❌ Error processing repository list: {str(e)}")
            
        return assets
        
    def _get_or_clone_repository(self, repo_url: str) -> Optional[str]:
        """Get local path for repository, clone if necessary"""
        # Extract repository name from URL
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        
        # If organized folders is enabled, prioritize the organized location
        if self.organize_folders:
            organized_path = os.path.join(self.github_pull_dir, repo_name)
            if os.path.exists(organized_path) and os.path.isdir(organized_path):
                print(f"✅ Found repository in organized folder: {organized_path}")
                # Track found repository
                self.found_repositories.append({
                    'url': repo_url,
                    'name': repo_name,
                    'local_path': organized_path,
                    'source': 'organized_folder'
                })
                return organized_path
        
        # Check if repository exists locally in other locations
        # Include /tmp only if legacy tmp mode is enabled
        possible_paths = [
            f"./repos/{repo_name}",
            f"../{repo_name}",
            f"../../{repo_name}"
        ]
        
        # Add /tmp to search paths only if legacy mode is enabled
        if self.use_tmp:
            possible_paths.append(f"/tmp/{repo_name}")
        
        for path in possible_paths:
            if os.path.exists(path) and os.path.isdir(path):
                print(f"✅ Found local repository: {path}")
                # Track found repository
                self.found_repositories.append({
                    'url': repo_url,
                    'name': repo_name,
                    'local_path': path,
                    'source': 'existing_local'
                })
                return path
                
        # Determine clone path based on mode
        if self.use_tmp:
            # Legacy mode: use /tmp
            clone_path = f"/tmp/{repo_name}"
        else:
            # Default: use organized github-pull folder structure
            clone_path = os.path.join(self.github_pull_dir, repo_name)
            os.makedirs(os.path.dirname(clone_path), exist_ok=True)
            
        try:
            print(f"📥 Cloning repository to {clone_path}")
            result = subprocess.run(
                ['git', 'clone', repo_url, clone_path],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                print(f"✅ Successfully cloned repository")
                # Track cloned repository
                self.cloned_repositories.append({
                    'url': repo_url,
                    'name': repo_name,
                    'local_path': clone_path,
                    'source': 'organized_folder' if self.organize_folders else 'tmp_folder'
                })
                return clone_path
            else:
                print(f"❌ Failed to clone repository: {result.stderr}")
                
        except Exception as e:
            print(f"❌ Error cloning repository: {str(e)}")
            
        return None

    def generate_report(self, output_file: str = None) -> str:
        """Generate a comprehensive security report"""
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("ENHANCED NPM PACKAGE COMPROMISE DETECTION REPORT WITH PHOENIX INTEGRATION")
        report_lines.append("=" * 80)
        report_lines.append(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Enhanced scan statistics
        report_lines.append("")
        report_lines.append("SCAN STATISTICS:")
        report_lines.append("-" * 20)
        report_lines.append(f"Files scanned: {len(self.scanned_files)}")
        report_lines.append(f"Total packages scanned: {len(self.scanned_packages)}")
        report_lines.append(f"Clean packages found: {len(self.safe_packages)}")
        report_lines.append(f"Total findings: {len(self.findings)}")
        
        if self.light_scan_mode:
            report_lines.append(f"Scan mode: Light scan (NPM files only)")
        else:
            report_lines.append(f"Scan mode: Full repository scan")
            
        if self.organize_folders:
            report_lines.append(f"Repository storage: {self.github_pull_dir}")
            report_lines.append(f"Results directory: {self.result_dir}")
            
        if self.enable_phoenix_import:
            report_lines.append(f"Phoenix assets created: {len(self.phoenix_assets)}")
            
        # Fallback access statistics
        if self.light_scan_mode and (self.api_failed_repositories or self.fallback_success_repositories or self.completely_failed_repositories):
            report_lines.append("")
            report_lines.append("GITHUB ACCESS SUMMARY:")
            report_lines.append("-" * 22)
            if self.api_failed_repositories:
                report_lines.append(f"API failures: {len(self.api_failed_repositories)} repositories")
            if self.fallback_success_repositories:
                report_lines.append(f"Fallback successes: {len(self.fallback_success_repositories)} repositories")
            if self.completely_failed_repositories:
                report_lines.append(f"Complete failures: {len(self.completely_failed_repositories)} repositories")
            
        # Detailed scan information
        if self.scanned_files:
            report_lines.append("")
            report_lines.append("FILES SCANNED:")
            report_lines.append("-" * 20)
            for i, file_path in enumerate(self.scanned_files, 1):
                # Show relative path if possible
                display_path = file_path
                if os.path.isabs(file_path):
                    try:
                        display_path = os.path.relpath(file_path)
                    except:
                        display_path = file_path
                report_lines.append(f"{i:2d}. {display_path}")
                
        # Repository information - Enhanced with clone/found details
        report_lines.append("")
        report_lines.append("REPOSITORY PROCESSING DETAILS:")
        report_lines.append("-" * 30)
        
        # Show cloned repositories
        if self.cloned_repositories:
            report_lines.append("CLONED REPOSITORIES:")
            for i, repo in enumerate(self.cloned_repositories, 1):
                report_lines.append(f"{i:2d}. {repo['name']}")
                report_lines.append(f"    URL: {repo['url']}")
                report_lines.append(f"    Local path: {repo['local_path']}")
                report_lines.append(f"    Source: {repo['source']}")
                report_lines.append("")
        
        # Show found repositories
        if self.found_repositories:
            report_lines.append("FOUND EXISTING REPOSITORIES:")
            for i, repo in enumerate(self.found_repositories, 1):
                report_lines.append(f"{i:2d}. {repo['name']}")
                report_lines.append(f"    URL: {repo['url']}")
                report_lines.append(f"    Local path: {repo['local_path']}")
                report_lines.append(f"    Source: {repo['source']}")
                report_lines.append("")
        
        # Show repositories accessed via fallback
        if self.fallback_success_repositories:
            report_lines.append("REPOSITORIES ACCESSED VIA FALLBACK (Direct Raw GitHub):")
            for i, repo in enumerate(self.fallback_success_repositories, 1):
                report_lines.append(f"{i:2d}. {repo['repo']}")
                report_lines.append(f"    URL: {repo['url']}")
                report_lines.append(f"    Files found: {repo['files_found']}")
                report_lines.append(f"    Access method: {repo['access_method']}")
                report_lines.append(f"    Status: ✅ Fallback successful")
                report_lines.append("")
        
        # Show repositories where API failed
        if self.api_failed_repositories:
            report_lines.append("REPOSITORIES WITH API FAILURES:")
            for i, repo in enumerate(self.api_failed_repositories, 1):
                report_lines.append(f"{i:2d}. {repo['repo']}")
                report_lines.append(f"    URL: {repo['url']}")
                report_lines.append(f"    Reason: {repo['reason']}")
                # Check if fallback was successful
                fallback_success = any(fb['repo'] == repo['repo'] for fb in self.fallback_success_repositories)
                if fallback_success:
                    report_lines.append(f"    Status: ✅ Recovered via direct raw access")
                else:
                    report_lines.append(f"    Status: ❌ Failed both API and fallback")
                report_lines.append("")
        
        # Show completely failed repositories
        if self.completely_failed_repositories:
            report_lines.append("REPOSITORIES COMPLETELY INACCESSIBLE:")
            for i, repo in enumerate(self.completely_failed_repositories, 1):
                report_lines.append(f"{i:2d}. {repo['repo']}")
                report_lines.append(f"    URL: {repo['url']}")
                report_lines.append(f"    Reason: {repo['reason']}")
                report_lines.append(f"    Status: ❌ All access methods failed")
                report_lines.append("")
        
        # Library analysis summary
        if self.all_scanned_libraries:
            report_lines.append("")
            report_lines.append("LIBRARY ANALYSIS SUMMARY:")
            report_lines.append("-" * 25)
            report_lines.append(f"Total libraries scanned: {len(self.all_scanned_libraries)}")
            report_lines.append(f"Clean libraries: {len(self.clean_libraries)}")
            report_lines.append(f"Compromised libraries: {len(self.compromised_libraries)}")
            
            # Show clean libraries
            if self.clean_libraries:
                report_lines.append("")
                report_lines.append("CLEAN LIBRARIES FOUND:")
                report_lines.append("-" * 20)
                
                # Determine how many libraries to show
                libraries_to_show = self.clean_libraries if self.detail_log else self.clean_libraries[:20]
                
                for i, lib in enumerate(libraries_to_show, 1):
                    report_lines.append(f"{i:2d}. {lib['name']}@{lib['version']} ({lib['type']})")
                    
                    # Add repository and file information
                    file_path = lib.get('file', 'unknown')
                    
                    # Extract repository URL from findings or try to determine from file path
                    repo_url = None
                    for finding in self.findings:
                        if finding.get('file') == file_path:
                            repo_url = finding.get('repo_url')
                            break
                    
                    if not repo_url:
                        repo_url = self.get_repo_url_from_path(file_path)
                    
                    # Show file path (relative if possible)
                    display_path = file_path
                    if os.path.isabs(file_path):
                        try:
                            display_path = os.path.relpath(file_path)
                        except:
                            display_path = file_path
                    
                    report_lines.append(f"    📁 Build file: {display_path}")
                    if repo_url and repo_url != 'unknown':
                        report_lines.append(f"    🔗 Repository: {repo_url}")
                    report_lines.append(f"    📍 Local path: {file_path}")
                    report_lines.append("")
                    
                # Show truncation message only if not in detail log mode
                if not self.detail_log and len(self.clean_libraries) > 20:
                    report_lines.append(f"    ... and {len(self.clean_libraries) - 20} more clean libraries")
                    report_lines.append(f"    💡 Use --detail-log to see all {len(self.clean_libraries)} libraries")
                    report_lines.append("")
                    
            # Show compromised libraries
            if self.compromised_libraries:
                report_lines.append("")
                report_lines.append("COMPROMISED LIBRARIES FOUND:")
                report_lines.append("-" * 25)
                for i, lib in enumerate(self.compromised_libraries, 1):
                    report_lines.append(f"{i:2d}. {lib['name']}@{lib['version']} ({lib['type']}) - {lib.get('severity', 'UNKNOWN')}")
                    
                    # Add repository and file information
                    file_path = lib.get('file', 'unknown')
                    
                    # Extract repository URL from findings or try to determine from file path
                    repo_url = None
                    for finding in self.findings:
                        if finding.get('file') == file_path:
                            repo_url = finding.get('repo_url')
                            break
                    
                    if not repo_url:
                        repo_url = self.get_repo_url_from_path(file_path)
                    
                    # Show file path (relative if possible)
                    display_path = file_path
                    if os.path.isabs(file_path):
                        try:
                            display_path = os.path.relpath(file_path)
                        except:
                            display_path = file_path
                    
                    report_lines.append(f"    📁 Build file: {display_path}")
                    if repo_url and repo_url != 'unknown':
                        report_lines.append(f"    🔗 Repository: {repo_url}")
                    report_lines.append(f"    📍 Local path: {file_path}")
                    if 'compromised_versions' in lib:
                        report_lines.append(f"    ⚠️  Compromised versions: {', '.join(lib['compromised_versions'])}")
                    report_lines.append("")
            
        report_lines.append("")
        
        # Summary by severity
        severity_counts = {}
        for finding in self.findings:
            severity = finding['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
        report_lines.append("SEVERITY SUMMARY:")
        report_lines.append("-" * 20)
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'WARNING', 'ERROR', 'INFO', 'CLEAN']:
            if severity in severity_counts:
                report_lines.append(f"{severity}: {severity_counts[severity]}")
        report_lines.append("")
        
        # Detailed findings grouped by repository and build file
        if self.findings:
            report_lines.append("DETAILED FINDINGS:")
            report_lines.append("-" * 20)
            
            # Group findings by repository and file
            grouped_findings = {}
            for finding in self.findings:
                repo_url = finding.get('repo_url', 'unknown')
                file_path = finding.get('file', 'unknown')
                
                # Create full GitHub URLs for grouping
                if repo_url and repo_url != 'unknown' and 'github.com' in repo_url:
                    # Clean up repo URL and fix the repository name format
                    clean_repo_url = repo_url.replace('.git', '')
                    
                    # Fix the repository URL to match the actual GitHub structure
                    if 'Shai-Hulud-npm-tinycolour-compromise-verifier' in clean_repo_url:
                        clean_repo_url = clean_repo_url.replace('Shai-Hulud-npm-tinycolour-compromise-verifier', 'Shai-Hulud-Hulud-Shai-npm-tinycolour-compromise-verifier')
                    
                    # Extract relative path for file URL
                    if os.path.isabs(file_path):
                        # Try to extract relative path
                        path_parts = file_path.split(os.sep)
                        relative_path = os.path.basename(file_path)
                        
                        # Look for meaningful directory structure
                        for i, part in enumerate(path_parts):
                            if part.startswith('test') or 'package' in part.lower():
                                if i < len(path_parts):
                                    relative_path = '/'.join(path_parts[i:])
                                    break
                    else:
                        relative_path = file_path
                    
                    # Create directory and file URLs
                    if relative_path.endswith('.json'):
                        # For files, create directory URL and file URL
                        dir_path = '/'.join(relative_path.split('/')[:-1]) if '/' in relative_path else ''
                        repo_dir_url = f"{clean_repo_url}/tree/main/{dir_path}/" if dir_path else f"{clean_repo_url}/tree/main/"
                        file_url = f"{clean_repo_url}/tree/main/{relative_path}"
                    else:
                        # For directories
                        repo_dir_url = f"{clean_repo_url}/tree/main/{relative_path}/"
                        file_url = f"{clean_repo_url}/tree/main/{relative_path}/"
                    
                    # Group key
                    group_key = (repo_dir_url, file_url, relative_path)
                else:
                    # Fallback for non-GitHub URLs
                    group_key = (repo_url, file_path, file_path)
                
                if group_key not in grouped_findings:
                    grouped_findings[group_key] = []
                grouped_findings[group_key].append(finding)
            
            # Generate grouped report
            finding_counter = 1
            for (repo_dir_url, file_url, relative_path), group_findings in grouped_findings.items():
                # Repository header
                report_lines.append(f"Repository: {repo_dir_url}")
                report_lines.append(f"File: {file_url}")
                report_lines.append("")
                
                # Findings for this repo/file combination
                for finding in group_findings:
                    report_lines.append(f"{finding_counter}. [{finding['severity']}] {finding['message']}")
                    report_lines.append(f"   📁 Location: {relative_path}")
                    
                    if finding['details']:
                        for key, value in finding['details'].items():
                            if key == 'compromised_versions' and value:
                                report_lines.append(f"   ⚠️  Compromised versions: {', '.join(value)}")
                            elif key in ['package', 'version', 'safe_version'] and value:
                                report_lines.append(f"   {key}: {value}")
                            elif key == 'dependency_type':
                                report_lines.append(f"   📦 Type: {value}")
                    
                    report_lines.append("")
                    finding_counter += 1
                
                report_lines.append("-" * 40)
                report_lines.append("")
        else:
            report_lines.append("✅ No compromised packages detected!")
            report_lines.append("")
            
        # Scan mode information
        if self.light_scan_mode:
            report_lines.append("SCAN MODE:")
            report_lines.append("-" * 15)
            report_lines.append("Light scan mode: NPM files only (via GitHub API)")
            report_lines.append("")
            
        # Phoenix integration status
        if self.enable_phoenix_import:
            report_lines.append("PHOENIX SECURITY INTEGRATION:")
            report_lines.append("-" * 30)
            report_lines.append(f"Assets created: {len(self.phoenix_assets)}")
            total_findings = sum(len(asset['findings']) for asset in self.phoenix_assets)
            report_lines.append(f"Findings created: {total_findings}")
            report_lines.append(f"Import status: {'Enabled' if self.enable_phoenix_import else 'Disabled'}")
            report_lines.append("")
            
        report_content = '\n'.join(report_lines)
        
        if output_file:
            # If using organized folders, save to result directory
            if self.organize_folders and not os.path.isabs(output_file):
                output_file = os.path.join(self.result_dir, output_file)
                
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
            print(f"📄 Report saved to: {output_file}")
            
        return report_content


def main():
    parser = argparse.ArgumentParser(description='Enhanced NPM Package Compromise Detection Tool with Phoenix API Integration')
    
    # Input options
    parser.add_argument('target', nargs='?', default='.', 
                       help='Directory to scan, single file, or repository list file')
    parser.add_argument('--repo-list', action='store_true',
                       help='Treat target as a file containing list of repository URLs')
    parser.add_argument('--repo-url', type=str,
                       help='Specify repository URL for the target (overrides auto-detection)')
    
    # Local folder processing options (NEW)
    parser.add_argument('--folder-list', action='store_true',
                       help='Treat target as a file containing list of local folder paths')
    parser.add_argument('--folders', nargs='+', type=str,
                       help='Specify multiple local folders to scan directly')
    parser.add_argument('--use-embedded-credentials', action='store_true',
                       help='Use embedded Phoenix credentials from the script (for local laptop use)')
    
    # Configuration options
    parser.add_argument('--config', '-c', default='compromised_packages_2025.json',
                       help='Configuration file with compromised package data')
    parser.add_argument('--phoenix-config', default='.config',
                       help='Phoenix API configuration file')
    parser.add_argument('--create-config', action='store_true',
                       help='Create a template Phoenix API configuration file and exit')
    
    # Output options
    parser.add_argument('--output', '-o', help='Output report file')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Only show critical and high severity findings')
    
    # Phoenix integration options
    parser.add_argument('--enable-phoenix', action='store_true',
                       help='Enable Phoenix Security API integration')
    parser.add_argument('--phoenix-only', action='store_true',
                       help='Only import to Phoenix, skip local report')
    
    # Analysis options
    parser.add_argument('--full-tree', action='store_true',
                       help='Enable full dependency tree analysis (slower but comprehensive)')
    parser.add_argument('--light-scan', action='store_true',
                       help='Light scan mode: download only NPM files from repositories (faster, GitHub only)')
    parser.add_argument('--organize-folders', action='store_true',
                       help='Organize GitHub pulls in github-pull/YYYYMMDD and results in result/YYYYMMDD')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug mode: save Phoenix API payloads and responses to debug files')
    parser.add_argument('--delete-local-files', action='store_true',
                       help='Delete cloned repositories after scanning (cleanup mode)')
    parser.add_argument('--detail-log', action='store_true',
                       help='Show all libraries in the report without truncation (detailed logging)')
    parser.add_argument('--use-tmp', action='store_true',
                       help='Use /tmp for repository cloning (legacy mode, not recommended)')
    
    # Import all libraries option
    parser.add_argument('--import-all', action='store_true',
                       help='Import all libraries to Phoenix including clean ones (creates CVSS 1.0 findings for clean libraries)')
    
    # Additional tag options
    parser.add_argument('--tag_vuln', type=str,
                       help='Additional tags for vulnerability findings (comma-separated)')
    parser.add_argument('--tag_asset', type=str,
                       help='Additional tags for asset findings (comma-separated)')
    
    args = parser.parse_args()
    
    print("🔍 Enhanced NPM Package Compromise Detector with Phoenix Integration")
    print("=" * 70)
    
    # Create configuration template if requested
    if args.create_config:
        detector = EnhancedNPMCompromiseDetectorPhoenix()
        detector.create_config_template()
        return 0
    
    # Initialize detector
    detector = EnhancedNPMCompromiseDetectorPhoenix(
        config_file=args.config,
        phoenix_config_file=args.phoenix_config
    )
    
    # Enable options
    if args.full_tree:
        detector.enable_full_tree_analysis(True)
        print("🌳 Full dependency tree analysis enabled")
        
    if args.enable_phoenix or args.phoenix_only:
        detector.enable_phoenix_integration(True)
        print("🔗 Phoenix Security API integration enabled")
        
    if args.light_scan:
        detector.enable_light_scan(True)
        print("🪶 Light scan mode enabled (NPM files only)")
        if not os.getenv('GITHUB_TOKEN'):
            print("💡 Tip: Set GITHUB_TOKEN environment variable for higher GitHub API rate limits")
            
    if args.use_embedded_credentials:
        detector.use_embedded_credentials = True
        print("🔐 Embedded credentials mode enabled")
        
    if args.organize_folders:
        detector.enable_folder_organization(True)
        
    if args.debug:
        detector.enable_debug_mode(True)
        
    if args.delete_local_files:
        detector.enable_delete_local_files(True)
        
    if args.detail_log:
        detector.enable_detail_log(True)
        
    if args.use_tmp:
        detector.enable_tmp_mode(True)
    else:
        # Default behavior: use organized folders for better organization
        detector.enable_folder_organization(True)
        
    if args.import_all:
        detector.enable_import_all(True)
        
    # Handle additional tags
    vuln_tags = []
    asset_tags = []
    
    if args.tag_vuln:
        vuln_tags = [tag.strip() for tag in args.tag_vuln.split(',') if tag.strip()]
        
    if args.tag_asset:
        asset_tags = [tag.strip() for tag in args.tag_asset.split(',') if tag.strip()]
        
    if vuln_tags or asset_tags:
        detector.set_additional_tags(vuln_tags, asset_tags)
    
    print(f"📁 Target: {os.path.abspath(args.target)}")
    print()
    
    # Process based on input type
    if args.folders:
        # Multiple folders specified directly
        assets = detector.process_multiple_folders(args.folders)
        detector.phoenix_assets = assets
    elif args.folder_list:
        # Local folder list mode
        assets = detector.process_folder_list(args.target)
        detector.phoenix_assets = assets
    elif args.repo_list:
        # Process repository list
        assets = detector.process_repository_list(args.target)
        detector.phoenix_assets = assets
    else:
        # Process single file or directory
        if os.path.isfile(args.target):
            # Single file
            asset = detector.process_package_file(args.target, args.repo_url)
            detector.phoenix_assets = [asset]
        else:
            # Directory - find all package files
            directory_path = Path(args.target)
            package_files = []
            
            # Find package.json and lock files
            for pattern in ['package.json', 'package-lock.json', 'yarn.lock']:
                package_files.extend(directory_path.rglob(pattern))
            
            for package_file in package_files:
                asset = detector.process_package_file(str(package_file), args.repo_url)
                detector.phoenix_assets.append(asset)
    
    # Import to Phoenix if enabled
    if detector.enable_phoenix_import:
        success = detector.import_to_phoenix()
        if not success:
            print("⚠️  Phoenix import failed, but continuing with local report")
    
    # Generate report unless phoenix-only mode
    if not args.phoenix_only:
        report = detector.generate_report(args.output)
        
        if not args.quiet:
            print(report)
        else:
            # Show only critical and high findings
            critical_findings = [f for f in detector.findings if f['severity'] == 'CRITICAL']
            high_findings = [f for f in detector.findings if f['severity'] == 'HIGH']
            
            if critical_findings:
                print("🚨 CRITICAL FINDINGS DETECTED!")
                for finding in critical_findings:
                    print(f"  - {finding['message']}")
                    if finding['file']:
                        print(f"    File: {finding['file']}")
            
            if high_findings:
                print("⚠️  HIGH PRIORITY FINDINGS DETECTED!")
                for finding in high_findings:
                    print(f"  - {finding['message']}")
                    if finding['file']:
                        print(f"    File: {finding['file']}")
                        
            if not critical_findings and not high_findings:
                print("✅ No critical or high priority findings detected")
    
    # Cleanup cloned repositories if requested
    detector.cleanup_cloned_repositories()
    
    # Exit with error code if critical or high findings
    critical_count = len([f for f in detector.findings if f['severity'] in ['CRITICAL', 'HIGH']])
    return 1 if critical_count > 0 else 0


if __name__ == '__main__':
    sys.exit(main())
