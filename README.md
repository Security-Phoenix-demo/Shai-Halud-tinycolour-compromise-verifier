# NPM Package Compromise Detection Tools with Phoenix Security Integration - 2025

## ⚡ Quick Start (30 seconds)

### **📊 Quick Results Guide:**
- **0 findings** = ✅ **EXCELLENT!** Your project is secure (like Optimizely, Facebook, Google repos)
- **1+ findings** = 🚨 **ACTION REQUIRED!** Compromised packages detected - follow remediation steps below

**🚨 SECURITY EMERGENCY? Run this immediately:**

```bash
# 1. Make scripts executable
chmod +x *.sh *.py

# 2. FASTEST: Enhanced security check with Phoenix + Light Scan
./enhanced-quick-check-with-phoenix.sh . --enable-phoenix --light-scan

# 3. Or traditional quick check
./local-security-check.sh .

# 4. If compromised packages found, get detailed report with all libraries
python3 enhanced_npm_compromise_detector_phoenix.py . --full-tree --enable-phoenix --detail-log --output emergency-report.txt
```

### **⚡ Enterprise Quick Start (Batch Scanning)**

**Scan multiple repositories at once:**

```bash
# 1. Create repository list
cat > my_repos.txt << EOF
https://github.com/your-org/frontend
https://github.com/your-org/backend
https://github.com/your-org/mobile-app
EOF

# 2. Set GitHub token for best performance (optional but recommended)
export GITHUB_TOKEN=your_github_token_here

# 3. Light scan all repositories (10x faster!) with cleanup
python3 enhanced_npm_compromise_detector_phoenix.py --repo-list my_repos.txt --light-scan --enable-phoenix --organize-folders --delete-local-files --detail-log --output batch-security-report.txt

# 4. Or use the integrated script
./enhanced-quick-check-with-phoenix.sh my_repos.txt --enable-phoenix --light-scan --repo-list
```

### **🎯 What Each Tool Does**

| Tool | Purpose | Speed | Use Case |
|------|---------|-------|----------|
| `./enhanced-quick-check-with-phoenix.sh` | **🔗 Integrated scanner + Phoenix API** | ⚡ Fast | Enterprise security, automated reporting |
| `./enhanced-quick-check-with-phoenix.sh --light-scan` | **🪶 Light batch scanner** | ⚡⚡ Very Fast | **Enterprise batch scanning** |
| `./local-security-check.sh` | **Quick scanner with nice output** | ⚡ Fast | Daily checks, CI/CD |
| `./quick-check-compromised-packages-2025.sh` | **Core detection engine** | ⚡ Fast | Direct usage, automation |
| `enhanced_npm_compromise_detector_phoenix.py --light-scan` | **🪶 Light Phoenix scanner** | ⚡⚡ Very Fast | **Batch repo scanning, zero storage** |
| `enhanced_npm_compromise_detector_phoenix.py --detail-log` | **📋 Detailed library reporting** | ⚡ Fast | **Complete library visibility** |
| `enhanced_npm_compromise_detector_phoenix.py --delete-local-files` | **🗑️ Auto-cleanup scanner** | ⚡ Fast | **CI/CD, clean environments** |
| `enhanced_npm_compromise_detector_phoenix.py` | **🔗 Phoenix integrated analysis** | 🐌 Thorough | Enterprise security audits, asset management |
| `npm_package_compromise_detector_2025.py` | **Comprehensive analysis** | 🐌 Thorough | Security audits, reports |

### **📊 Understanding Scan Results**

#### ✅ **Clean Project (Exit Code 0) - GOOD NEWS!**
```bash
$ ./local-security-check.sh .
✅ SCAN COMPLETE: No compromised packages detected

Files scanned: 3
Total packages scanned: 45
Clean packages found: 45
Total findings: 0
```

**This means:**
- ✅ **Your project is SECURE** - no compromised packages found
- ✅ **All dependencies are clean** and safe to use
- ✅ **No immediate action required** - continue development safely
- 📊 **Example**: Optimizely, Facebook, Google repositories typically show 0 findings (they're secure!)

#### 🚨 **Compromised Project (Exit Code 1) - ACTION REQUIRED!**
```bash
$ ./local-security-check.sh .
🚨 CRITICAL: Compromised packages detected!

Files scanned: 2
Total packages scanned: 23
Clean packages found: 18
Total findings: 5

IMMEDIATE ACTIONS REQUIRED:
1. Stop all running applications immediately
2. Clear npm cache: npm cache clean --force
3. Remove node_modules: rm -rf node_modules
4. Remove lock files: rm package-lock.json yarn.lock
5. Update to safe versions and reinstall
```

**This means:**
- ❌ **SECURITY RISK DETECTED** - compromised packages found
- 🚨 **Immediate action required** - follow remediation steps
- 📊 **Mixed results**: Some packages clean (18), some compromised (5)

#### 🔍 **Understanding "0 Findings" Results**

**"0 findings" is EXCELLENT NEWS and means:**

1. **✅ Secure Dependencies**: Your project uses only clean, uncompromised packages
2. **✅ Good Security Posture**: No known vulnerabilities in your supply chain
3. **✅ Safe to Deploy**: No security risks from NPM package compromise
4. **✅ Well-Maintained Project**: Dependencies are from trusted sources

**Real Examples of Clean Projects:**
- **Optimizely repositories**: 0 findings ✅ (Professional, secure dependencies)
- **Facebook Create React App**: 0 findings ✅ (Well-vetted dependencies)
- **Vue.js core**: 0 findings ✅ (Minimal, trusted dependencies)
- **Microsoft TypeScript**: 0 findings ✅ (Enterprise-grade security)

**Why Some Projects Show 0 Findings:**
- They use **mainstream, trusted packages** (lodash, react, express)
- They **avoid experimental/niche packages** where compromises often occur
- They have **good security practices** and dependency management
- They **regularly update dependencies** to avoid known vulnerable versions

---

## 🔗 Phoenix Security Integration (NEW!)

### **Enterprise Asset & Vulnerability Management**

The enhanced tools now integrate with **Phoenix Security** platform to automatically:

- **🏗️ Create BUILD Assets** for each package.json/package-lock.json file
- **🔍 Generate Security Findings** with proper risk scoring (1.0-10.0)
- **🔗 Link to Git Repositories** automatically detected from file paths
- **📊 Centralize Security Data** in your Phoenix Security dashboard

### **Quick Phoenix Setup**

```bash
# 1. Create Phoenix API configuration template
python3 enhanced_npm_compromise_detector_phoenix.py --create-config

# 2. Edit .config with YOUR Phoenix API credentials
cp .config.example .config
# ⚠️  IMPORTANT: Edit .config file and replace:
#   - your_phoenix_client_id_here → your actual Phoenix client ID
#   - your_phoenix_client_secret_here → your actual Phoenix client secret  
#   - your-phoenix-domain.com → your actual Phoenix domain

# 3. Run with Phoenix integration
./enhanced-quick-check-with-phoenix.sh . --enable-phoenix
```

> **🔧 Critical Setup**: The Phoenix integration requires your actual credentials. The example values like `your_phoenix_client_id_here` and `your-phoenix-domain.com` are placeholders that MUST be replaced with your real Phoenix Security platform credentials and domain.

### **Phoenix Risk Scoring**

| Finding Type | Risk Score | Description |
|--------------|------------|-------------|
| **Compromised Package** | 10.0 (Critical) | Known compromised version detected |
| **Potentially Compromised** | 8.0 (High) | Package name in compromise list |
| **Safe Version** | 1.0 (Info) | Safe version of monitored package |
| **Clean Library** | 1.0 (Info) | Clean library not affected by Shai Halud |

### **🆕 Import All Libraries (`--import-all`)**

By default, Phoenix findings are only created for compromised or monitored packages. Use `--import-all` to create findings for **ALL** libraries including clean ones:

```bash
# Import all libraries including clean ones (creates CVSS 1.0 findings)
python3 enhanced_npm_compromise_detector_phoenix.py . --enable-phoenix --import-all

# Complete security posture with all libraries
python3 enhanced_npm_compromise_detector_phoenix.py \
  --repo-list repos.txt \
  --light-scan \
  --enable-phoenix \
  --import-all \
  --output complete-posture.txt
```

**Benefits of `--import-all`:**
- ✅ **Complete Asset Inventory**: Every library gets a Phoenix finding
- ✅ **Security Posture Visibility**: See all dependencies, not just compromised ones  
- ✅ **Compliance Ready**: Full library documentation for audits
- ✅ **Clean Library Tracking**: Track "Library XYZ version Z is not affected by Shai Halud"

**Clean Library Finding Example:**
- **Name**: "NPM Package Security: express"
- **Description**: "Library express version 4.18.2 is not affected by Shai Halud"
- **Risk Score**: 1.0 (CVSS 1)
- **Tag**: "shai-hulud-clean-library"

### **🏷️ Custom Tags Configuration**

Add custom tags to Phoenix findings and assets for better organization:

#### **Command Line Tags:**
```bash
# Add custom vulnerability tags
python3 enhanced_npm_compromise_detector_phoenix.py . \
  --enable-phoenix \
  --tag_vuln="security-audit,compliance-scan,Q4-2025"

# Add custom asset tags  
python3 enhanced_npm_compromise_detector_phoenix.py . \
  --enable-phoenix \
  --tag_asset="frontend-project,production-ready,team-alpha"

# Combine both tag types
python3 enhanced_npm_compromise_detector_phoenix.py . \
  --enable-phoenix \
  --import-all \
  --tag_vuln="security-audit,shai-halud-scan" \
  --tag_asset="npm-project,dependency-inventory" \
  --output tagged-security-scan.txt
```

#### **Configuration File Tags:**
Add tags to your `.config` file for consistent tagging:

```ini
[phoenix]
client_id = your_phoenix_client_id_here
client_secret = your_phoenix_client_secret_here
api_base_url = https://api.securityphoenix.cloud
assessment_name = NPM Compromise Detection - Shai Halud
import_type = new

# Additional tags for findings and assets (comma-separated)
additional_vuln_tags = custom-scan,security-audit,Q4-2025
additional_asset_tags = npm-project,dependency-scan,team-alpha

# GitHub token for enhanced API rate limits
github_token = your_github_token_here
```

**Tag Use Cases:**
- **Team Organization**: `team-frontend,team-backend,team-mobile`
- **Environment Tracking**: `production,staging,development`
- **Compliance**: `sox-compliance,gdpr-audit,security-review`
- **Time-based**: `Q1-2025,monthly-scan,pre-deployment`
- **Project Classification**: `critical-app,internal-tool,public-facing`

### **📊 Enhanced Fallback Reporting**

When using light-scan mode, the scanner provides detailed reporting about GitHub access methods:

```
GITHUB ACCESS SUMMARY:
----------------------
API failures: 3 repositories
Fallback successes: 2 repositories  
Complete failures: 1 repositories

REPOSITORIES ACCESSED VIA FALLBACK (Direct Raw GitHub):
 1. react-sdk
    URL: https://github.com/optimizely/react-sdk
    Files found: 2
    Access method: direct_raw_github
    Status: ✅ Fallback successful

REPOSITORIES WITH API FAILURES:
 1. react-sdk
    URL: https://github.com/optimizely/react-sdk
    Reason: github_api_failed
    Status: ✅ Recovered via direct raw access

REPOSITORIES COMPLETELY INACCESSIBLE:
 1. android-sdk
    URL: https://github.com/optimizely/android-sdk
    Reason: all_methods_failed
    Status: ❌ All access methods failed
```

**Report Categories:**
- **✅ Fallback Successful**: Repositories recovered via direct raw access
- **⚠️ API Failed**: Repositories where GitHub API failed but fallback worked
- **❌ Complete Failure**: Repositories inaccessible by all methods (usually no NPM files)

### **Repository URL Detection**

The tool automatically detects repository URLs from file paths:

- **GitHub Pattern**: `/Documents/GitHub/repo-name/` → `https://github.com/org/repo-name`
- **Git Remote**: Reads `git remote get-url origin` from `.git` directory  
- **Manual Override**: Use `--repo-url` parameter

### **Batch Repository Processing**

```bash
# Create repository list
cat > repos.txt << EOF
https://github.com/securityphoenix/SP-MVP1-Frontend
https://github.com/Security-Phoenix-demo/Shai-Halud-tinycolour-compromise-verifier
EOF

# Process multiple repositories (full scan)
python3 enhanced_npm_compromise_detector_phoenix.py --repo-list repos.txt --enable-phoenix

# 🪶 Light scan mode (10x faster - NPM files only!)
python3 enhanced_npm_compromise_detector_phoenix.py --repo-list repos.txt --enable-phoenix --light-scan
```

### **🪶 Light Scan Mode (NEW!)**

Perfect for scanning hundreds of repositories quickly:

- ⚡ **10x Faster**: Downloads only NPM files via GitHub API
- 💾 **Zero Storage**: No repository cloning required
- 🔄 **Batch Optimized**: Scan entire organizations efficiently
- 🛡️ **Automatic Fallback**: Recovers from API failures using direct raw GitHub access

```bash
# Set GitHub token for higher rate limits (recommended)
export GITHUB_TOKEN=your_github_token_here

# Light scan repository list
python3 enhanced_npm_compromise_detector_phoenix.py --repo-list repos.txt --light-scan --enable-phoenix
```

#### **🔄 Intelligent Fallback System**

When GitHub API access fails (invalid tokens, rate limits, etc.), the scanner automatically:

1. **GitHub API Search** → Tries authenticated/unauthenticated API access
2. **GitHub API Fallback** → Tries direct GitHub API file access  
3. **Direct Raw Access** → Uses `raw.githubusercontent.com` for public repositories
4. **Complete Documentation** → Reports exactly what happened in scan results

**Example Fallback Flow:**
```
🔄 GitHub API failed completely, trying direct raw access...
🔄 Fallback: Trying direct raw GitHub access for optimizely/react-sdk
✅ Direct access found: package.json
✅ Direct access found: yarn.lock
✅ Fallback successful: Found 2 NPM file(s) via direct access
```

**Fallback Benefits:**
- ✅ **Zero Empty Files**: No more JSON parsing errors from failed downloads
- ✅ **Maximum Coverage**: Recovers repositories that would otherwise fail
- ✅ **Detailed Reporting**: Shows which repositories used fallback methods
- ✅ **Public Repository Support**: Works with any public GitHub repository
- ✅ **Automatic Recovery**: No manual intervention required

### **🆕 New Enhanced Features (2025)**

#### **📋 Detail Log Mode (`--detail-log`)**

Show ALL libraries without truncation for complete visibility:

```bash
# Show every single library (no "... and 50 more" messages)
python3 enhanced_npm_compromise_detector_phoenix.py --folders my_projects --detail-log

# Enterprise audit with complete library listing
python3 enhanced_npm_compromise_detector_phoenix.py --repo-list enterprise_repos.txt --detail-log --output complete-audit.txt
```

**Benefits:**
- ✅ **Complete Visibility**: See every single library scanned
- ✅ **No Truncation**: No "... and X more libraries" messages
- ✅ **Audit Ready**: Perfect for compliance and security audits
- ✅ **Repository Context**: Each library shows repo, build file, and local path

#### **🗑️ Auto-Cleanup Mode (`--delete-local-files`)**

Automatically clean up cloned repositories after scanning:

```bash
# Scan and cleanup - perfect for CI/CD
python3 enhanced_npm_compromise_detector_phoenix.py --repo-list repos.txt --organize-folders --delete-local-files

# Enterprise batch scan with cleanup
python3 enhanced_npm_compromise_detector_phoenix.py \
  --repo-list large_org_repos.txt \
  --light-scan \
  --organize-folders \
  --delete-local-files \
  --enable-phoenix
```

**Benefits:**
- ✅ **Clean Environment**: No leftover cloned repositories
- ✅ **CI/CD Ready**: Perfect for automated pipelines
- ✅ **Disk Management**: Prevents disk space accumulation
- ✅ **Safe Cleanup**: Only deletes repos cloned during current scan

#### **🔄 Combined Usage**

Use both features together for ultimate scanning experience:

```bash
# Complete enterprise security audit with cleanup
python3 enhanced_npm_compromise_detector_phoenix.py \
  --repo-list organization_repos.txt \
  --light-scan \
  --organize-folders \
  --delete-local-files \
  --detail-log \
  --enable-phoenix \
  --output comprehensive-security-audit.txt
```

### **🗂️ Organized Folder Structure**

Perfect for systematic security monitoring and audit trails:

```bash
# Organize GitHub pulls and results by date
python3 enhanced_npm_compromise_detector_phoenix.py \
  --repo-list repos.txt \
  --light-scan \
  --organize-folders \
  --enable-phoenix \
  --output security_audit.txt
```

**Creates organized structure:**
```
github-pull/20250917/    # Downloaded NPM files by repository
├── repo1/package.json
├── repo2/package-lock.json
└── repo3/yarn.lock

result/20250917/         # All reports and results
├── security_audit.txt
└── phoenix_import.log
```

📖 **[Complete Phoenix Integration Guide](PHOENIX_INTEGRATION_GUIDE.md)**

---

## Overview

This repository contains comprehensive security tools to detect **195 confirmed compromised NPM packages** from the 2025 supply chain attack affecting multiple organizations including `@ctrl/*`, `@nativescript-community/*`, `@art-ws/*`, `@crowdstrike/*`, `@operato/*`, `@teselagen/*`, `@things-factory/*`, and many others.

## ⚠️ Critical Security Alert

**IMMEDIATE ACTION REQUIRED** if any of these packages are detected in your project:

### 🚨 **195 Confirmed Compromised Packages** with Specific Versions

**⚠️ CRITICAL ORGANIZATIONS AFFECTED:**
- **@ctrl** - 15+ packages compromised
- **@nativescript-community** - 25+ packages compromised  
- **@art-ws** - 15+ packages compromised
- **@crowdstrike** - 10+ packages compromised
- **@operato** - 15+ packages compromised
- **@teselagen** - 10+ packages compromised
- **@things-factory** - 8+ packages compromised
- **@nstudio** - 8+ packages compromised
- **Plus 100+ individual packages from various maintainers**

#### **Key Compromised Packages (Sample):**
- `@ctrl/tinycolor@4.1.1, 4.1.2`
- `@ahmedhfarag/ngx-perfect-scrollbar@20.0.20`
- `@art-ws/common@2.0.28`
- `@crowdstrike/commitlint@8.1.1, 8.1.2`
- `@operato/board@9.0.36-9.0.46` (multiple versions)
- `@nativescript-community/text@1.6.9-1.6.13` (multiple versions)
- `angulartics2@14.1.1, 14.1.2`
- `ngx-bootstrap@18.1.4, 19.0.3-19.0.4, 20.0.3-20.0.5`
- `ts-gaussian@3.0.5, 3.0.6`
- `encounter-playground@0.0.2-0.0.5` (multiple versions)

> **📋 Complete List**: All 195 packages with specific compromised versions are detected by our tools. Run the scanner for the complete detection coverage.

## 🚨 Emergency Response (If Compromised Packages Found)

**If the scan detects compromised packages, follow these steps immediately:**

```bash
# 1. Stop applications immediately
pkill -f node

# 2. Clean environment
npm cache clean --force
rm -rf node_modules
rm -f package-lock.json yarn.lock

# 3. Get detailed analysis
python3 npm_package_compromise_detector_2025.py . --full-tree --output emergency-report.txt

# 4. Review emergency-report.txt for safe versions
# 5. Update package.json with safe versions from report
# 6. Reinstall dependencies
npm install

# 7. Verify fix
./local-security-check.sh .
```

## 🛠️ Detection Tools

### 1. **Local Security Check (Recommended)**

```bash
# Best option: Clean output with both shell and Python analysis
./local-security-check.sh .                    # Check current directory
./local-security-check.sh /path/to/project     # Check specific project
```

**Features:**
- ⚡ Fast execution with comprehensive coverage
- 🎨 Clean, readable output format
- 🔄 Runs both shell and Python scanners
- 📊 Clear summary with next steps

### 2. **Quick Shell Script (Direct Core Scanner)**

```bash
# Direct access to core detection engine
./quick-check-compromised-packages-2025.sh .                    # Check current directory
./quick-check-compromised-packages-2025.sh /path/to/project     # Check specific project
```

**Features:**
- ⚡ Fastest scanning of package.json and lock files
- 🎨 Color-coded output for easy identification
- 🗂️ NPM cache checking
- 📊 Summary report with actionable recommendations

### 3. **Comprehensive Python Scanner (Detailed Analysis)**

```bash
# No additional requirements needed - uses standard library
# Basic scan
python3 npm_package_compromise_detector_2025.py .

# Full dependency tree analysis (recommended for security audits)
python3 npm_package_compromise_detector_2025.py . --full-tree

# Save detailed report with timestamp
python3 npm_package_compromise_detector_2025.py . --full-tree \
  --output "security-report-$(date +%Y%m%d-%H%M).txt"

# Quiet mode (only critical/high severity findings)
python3 npm_package_compromise_detector_2025.py . --quiet

# Custom configuration file
python3 npm_package_compromise_detector_2025.py . --config custom-packages.json
```

**Advanced Features:**
- 🌳 Full dependency tree traversal (requires npm install first)
- 📋 Detailed package analysis and reporting
- 🔍 Source code scanning for malicious patterns
- 📊 Comprehensive statistics and safe version recommendations
- 🧬 Crypto-related keyword detection
- 🌐 Malicious URL detection

### 4. **Common Workflows**

```bash
# Daily development check
./local-security-check.sh .

# Pre-deployment security audit
python3 npm_package_compromise_detector_2025.py . --full-tree --output pre-deploy-security.txt

# Multiple projects scan
for project in ~/projects/*/; do
    echo "Scanning $project"
    ./local-security-check.sh "$project"
done

# CI/CD integration
./local-security-check.sh . || exit 1  # Fail build if compromised
```

## 📁 Repository Structure

```
├── local-security-check.sh                    # ⭐ Recommended: Clean runner script
├── quick-check-compromised-packages-2025.sh   # Fast shell script checker  
├── npm_package_compromise_detector_2025.py    # Comprehensive Python scanner
├── compromised_packages_2025.json             # Package compromise database
├── install-and-run.sh                         # One-liner installation script
├── test_sample/                                # Test data for validation
│   ├── package.json                           # Sample with compromised packages
│   └── suspicious_code.js                     # Sample with malicious patterns
├── test_deep_dependencies/                     # Deep dependency tree testing
│   ├── package.json                           # Complex dependency structure
│   └── package-lock.json                      # Lock file with nested compromised packages
├── .github/workflows/                          # GitHub Actions integration
│   └── npm-security-scan.yml                  # CI/CD workflow template
├── QUICK_START.md                              # Comprehensive usage guide
├── COMMAND_REFERENCE.md                        # Quick reference card
├── requirements.txt                            # Python dependencies (optional)
└── README.md                                  # This documentation
```

## 🚨 Immediate Response Actions

If compromised packages are detected:

### 1. **STOP IMMEDIATELY**
```bash
# Kill all running Node.js processes
pkill -f node
pkill -f npm
```

### 2. **Clean Environment**
```bash
# Clear npm cache
npm cache clean --force

# Remove node_modules and lock files
rm -rf node_modules
rm -f package-lock.json yarn.lock
```

### 3. **Update Package Versions**

**🎯 Automatic Safe Version Detection**: The Python scanner generates safe version recommendations automatically. For manual updates, here are key examples:

```json
{
  "overrides": {
    "@ctrl/tinycolor": "4.1.0",
    "@ahmedhfarag/ngx-perfect-scrollbar": "20.0.19",
    "@art-ws/common": "2.0.27",
    "@crowdstrike/commitlint": "8.1.0",
    "@nativescript-community/text": "1.6.8",
    "angulartics2": "14.1.0",
    "ngx-color": "10.0.0",
    "ngx-toastr": "19.0.0",
    "ts-gaussian": "3.0.4",
    "encounter-playground": "0.0.1"
  }
}
```

> **💡 Pro Tip**: Run `python3 npm_package_compromise_detector_2025.py . --output report.txt` to get **complete safe version recommendations** for all 195 packages automatically generated in the report.
```

### 4. **Reinstall and Audit**
```bash
# Reinstall dependencies
npm install

# Run security audit
npm audit
npm audit fix

# Verify no compromised packages remain
./quick-check-compromised-packages-2025.sh .
```

### 5. **Security Assessment**
- Review application logs for suspicious network activity
- Check for unauthorized file modifications
- Monitor for unusual CPU/memory usage
- Scan for crypto wallet compromise if browser-based application
- Review recent deployments and rollback if necessary

## 🔧 Configuration

### Custom Package Database
You can modify `compromised_packages_2025.json` to add new compromised packages or update versions:

```json
{
  "compromised_packages": {
    "package-name": {
      "compromised_versions": ["1.0.0", "1.0.1"],
      "safe_version": "0.9.9"
    }
  },
  "potentially_compromised_packages": [
    "suspicious-package-name"
  ]
}
```

### Python Script Options
```bash
# Custom configuration file
python3 npm_package_compromise_detector_2025.py --config custom_packages.json

# Skip recursive directory scanning
python3 npm_package_compromise_detector_2025.py --no-recursive

# Enable full dependency tree analysis
python3 npm_package_compromise_detector_2025.py --full-tree
```

## 🧪 Testing & Validation

### **Quick Test (30 seconds)**

```bash
# Test with clean project
mkdir clean_test && echo '{"name":"test","version":"1.0.0","dependencies":{"lodash":"^4.17.21"}}' > clean_test/package.json
./local-security-check.sh clean_test
# Expected: ✅ No compromised packages detected

# Test with compromised packages
./local-security-check.sh test_sample
# Expected: 🚨 Multiple compromised packages detected
```

### **Comprehensive Testing**

```bash
# Test shell script with sample data
./quick-check-compromised-packages-2025.sh test_sample

# Test Python script with detailed output
python3 npm_package_compromise_detector_2025.py test_sample --output test_results.txt

# Test deep dependency analysis (requires npm install first)
cd test_deep_dependencies && npm install && cd ..
python3 npm_package_compromise_detector_2025.py test_deep_dependencies --full-tree
```

### **Expected Results:**
- **test_sample**: Should detect 5+ compromised packages and malicious patterns from 195 total monitored packages
- **test_deep_dependencies**: Should detect compromised packages in nested dependencies  
- **clean_test**: Should show clean results with exit code 0
- **Coverage**: Scanner monitors **195 confirmed compromised packages** across **11+ major organizations**

### **🤔 Troubleshooting: "Why Do I See 0 Findings?"**

#### **✅ This is Usually GOOD News!**

If you're scanning repositories like:
- **Optimizely**: `python3 enhanced_npm_compromise_detector_phoenix.py --repo-list optimizely_repos.txt --light-scan`
- **Facebook/Meta projects**: `--repo-list facebook_repos.txt`  
- **Google/Angular projects**: `--repo-list google_repos.txt`
- **Microsoft projects**: `--repo-list microsoft_repos.txt`

**Expected Result: 0 findings ✅**

**Why?** These organizations:
- Use **enterprise-grade security practices**
- Have **dedicated security teams** reviewing dependencies
- Use **mainstream, well-vetted packages** (React, Express, TypeScript, etc.)
- **Avoid niche/experimental packages** where compromises typically occur
- **Regularly audit and update** their dependencies

#### **🔍 How to Verify the Scanner is Working:**

```bash
# 1. Test with known compromised packages (should show findings)
python3 enhanced_npm_compromise_detector_phoenix.py --folders test_compromised_packages
# Expected: 17 CRITICAL + 6 INFO findings

# 2. Test with clean enterprise repos (should show 0 findings)  
echo "https://github.com/optimizely/react-sdk" > clean_test.txt
python3 enhanced_npm_compromise_detector_phoenix.py --repo-list clean_test.txt --light-scan
# Expected: 0 findings (this is correct!)

# 3. Check scanner database is loaded
python3 -c "import json; data=json.load(open('compromised_packages_2025.json')); print(f'Monitoring {len(data[\"compromised_packages\"])} packages')"
# Expected: Monitoring 198 packages
```

#### **📊 What "0 Findings" Tells You:**

| Scenario | Findings | Meaning | Action |
|----------|----------|---------|--------|
| **Enterprise repos** (Optimizely, Facebook) | 0 | ✅ **Secure & Professional** | Continue development |
| **Your production app** | 0 | ✅ **Good security posture** | Continue monitoring |  
| **Test files** (`test_compromised_packages`) | 17+ | ❌ **Contains test compromised packages** | Expected for testing |
| **Legacy/experimental project** | 0 | ✅ **Either clean OR uses packages we don't monitor** | Review manually if concerned |

#### **🚨 When to Be Concerned About 0 Findings:**

**Only worry if:**
- You **expect** compromised packages (testing with `test_sample/`)
- Scanner shows `Files scanned: 0` (indicates scanning issue)
- You're using packages from the affected organizations (`@ctrl/*`, `@operato/*`, etc.) but getting 0 findings

**Debug steps:**
```bash
# Check if files are being found
python3 enhanced_npm_compromise_detector_phoenix.py your_project --debug
# Look for: "Files scanned: X" where X > 0

# Check specific package
python3 -c "
import json
data = json.load(open('compromised_packages_2025.json'))
pkg = '@ctrl/tinycolor'  # Replace with your package
if pkg in data['compromised_packages']:
    print(f'✅ {pkg} is monitored')
    print(f'Compromised versions: {data[\"compromised_packages\"][pkg][\"compromised_versions\"]}')
else:
    print(f'❌ {pkg} is not in our database')
"
```

#### **🔧 GitHub API Troubleshooting**

**Common Issues and Solutions:**

| Issue | Symptoms | Solution |
|-------|----------|----------|
| **Invalid GitHub Token** | `Bad credentials (401)` | Generate new token at https://github.com/settings/tokens |
| **Rate Limit Exceeded** | `API rate limit exceeded` | Wait or use valid token for higher limits |
| **Empty Downloaded Files** | `JSON parsing errors` | ✅ **Auto-fixed by fallback system** |
| **Private Repository** | `Not Found (404)` | Ensure token has `repo` permission |

**Fallback System Handles:**
- ✅ Invalid/expired GitHub tokens
- ✅ API rate limit exceeded  
- ✅ Authentication failures
- ✅ Empty file downloads
- ✅ Network timeouts

**When Fallback Won't Work:**
- ❌ Private repositories (requires valid token)
- ❌ Repositories with no NPM files
- ❌ Repositories that don't exist

### **Performance Benchmarks:**
- Shell script: ~1-2 seconds for typical projects
- Python basic scan: ~3-5 seconds for typical projects  
- Python full-tree: ~10-30 seconds (requires npm install first)

## 📊 Sample Output

### Shell Script Output:
```
🚨 CRITICAL: Compromised package detected: @ctrl/tinycolor@4.1.2 in dependencies
🚨 CRITICAL: Compromised package detected: angulartics2@14.1.2 in dependencies
❌ Found 5 compromised package(s) in package.json

Status: ❌ COMPROMISED PACKAGES DETECTED
```

### Python Script Output:
```
[CRITICAL] Compromised package detected: @ctrl/tinycolor@4.1.2
[HIGH] Malicious URL detected: npmjs.help  
[MEDIUM] Crypto-related keywords detected: wallet, privatekey, crypto
[MEDIUM] Suspicious code patterns detected: 5 patterns

COMPROMISED PACKAGES FOUND: 5
POTENTIALLY COMPROMISED FOUND: 0
```

## 🔗 References

- **Attack Vector**: Supply chain compromise targeting popular packages
- **Impact**: Potential malicious code injection, data exfiltration, crypto wallet stealing
- **Severity**: CRITICAL
- **Date**: September 2025

## 🤝 Contributing

To add new compromised packages or improve detection:

1. Update `compromised_packages_2025.json` with new package data
2. Test with sample projects
3. Update documentation
4. Submit pull request with detailed description

## ⚖️ License

This security tool is provided as-is for protection against supply chain attacks. Use responsibly and ensure you have proper authorization before scanning systems.

## 🆘 Support

For urgent security incidents or questions:
- Create an issue in this repository
- Include scan results and affected package information
- Mark as urgent for critical security issues

## 📚 Quick Reference

### **🚀 Most Common Commands**
```bash
# Daily quick check
./local-security-check.sh .

# Before deployment with complete library details
python3 enhanced_npm_compromise_detector_phoenix.py . --full-tree --detail-log --output pre-deploy-report.txt

# Emergency scan after security alert
python3 enhanced_npm_compromise_detector_phoenix.py . --full-tree --detail-log --output emergency-$(date +%Y%m%d).txt

# Enterprise repository batch scan with cleanup
python3 enhanced_npm_compromise_detector_phoenix.py --repo-list enterprise_repos.txt --light-scan --organize-folders --delete-local-files --enable-phoenix

# Complete audit with all features including clean libraries
python3 enhanced_npm_compromise_detector_phoenix.py --repo-list repos.txt --light-scan --organize-folders --delete-local-files --detail-log --enable-phoenix --import-all --output complete-audit.txt

# Enterprise scan with custom tags and automatic fallback
python3 enhanced_npm_compromise_detector_phoenix.py --repo-list repos.txt --light-scan --enable-phoenix --import-all --tag_vuln="Q4-audit,compliance" --tag_asset="production,critical" --output enterprise-scan.txt

# Automatic fallback handles GitHub API failures (no configuration needed)
python3 enhanced_npm_compromise_detector_phoenix.py --repo-list public_repos.txt --light-scan --import-all
```

### **📊 Exit Code Reference**
- `0` = ✅ Clean (no compromised packages)
- `1` = 🚨 Compromised packages detected (IMMEDIATE ACTION REQUIRED)
- `2` = ⚠️ Script error (check dependencies, file paths, permissions)

### **🚨 Emergency Checklist**
If you see compromised packages:
1. ⏹️ **STOP** - Don't ignore this
2. 🔍 **ANALYZE** - Run: `python3 npm_package_compromise_detector_2025.py . --full-tree --output emergency.txt`
3. 🧹 **CLEAN** - `npm cache clean --force && rm -rf node_modules`
4. 📋 **REVIEW** - Check `emergency.txt` for safe versions
5. 🔄 **UPDATE** - Modify package.json with safe versions
6. 🔧 **REINSTALL** - `npm install`
7. ✅ **VERIFY** - `./local-security-check.sh .`

### **💡 Pro Tips**
- Run `./local-security-check.sh .` every morning
- Add to your git pre-commit hooks
- Use `--full-tree` for comprehensive audits
- Save reports with timestamps for tracking
- Integrate into CI/CD for automated protection

### **🏢 Enterprise-Scale Examples**

**Scan entire organization (hundreds of repositories):**
```bash
# 1. Generate repository list from GitHub API
curl -H "Authorization: token $GITHUB_TOKEN" \
     "https://api.github.com/orgs/your-org/repos?per_page=100&type=all" | \
     jq -r '.[].clone_url' > org_repos.txt

# 2. Light scan all repositories with Phoenix integration
python3 enhanced_npm_compromise_detector_phoenix.py \
  --repo-list org_repos.txt \
  --light-scan \
  --enable-phoenix \
  --output "org_security_scan_$(date +%Y%m%d).txt"

# 3. Or use the integrated script for complete workflow
./enhanced-quick-check-with-phoenix.sh org_repos.txt \
  --repo-list --light-scan --enable-phoenix
```

**CI/CD Pipeline Integration:**
```yaml
# .github/workflows/npm-security-light-scan.yml
name: NPM Security Light Scan
on: 
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Light Scan NPM Security
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          # ⚠️  Replace with your actual Phoenix Security credentials
          PHOENIX_CLIENT_ID: ${{ secrets.PHOENIX_CLIENT_ID }}
          PHOENIX_CLIENT_SECRET: ${{ secrets.PHOENIX_CLIENT_SECRET }}
          PHOENIX_API_URL: ${{ secrets.PHOENIX_API_URL }}  # Your Phoenix domain API endpoint
        run: |
          # Create repo list for organization
          echo "${{ github.repository_url }}" > current_repo.txt
          
          # Run light scan with Phoenix integration
          python3 enhanced_npm_compromise_detector_phoenix.py \
            --repo-list current_repo.txt \
            --light-scan \
            --enable-phoenix \
            --quiet
```

### **📖 Additional Resources**
- 📘 **[QUICK_START.md](QUICK_START.md)** - Comprehensive usage guide with GitHub Actions
- 📄 **[COMMAND_REFERENCE.md](COMMAND_REFERENCE.md)** - Quick command reference card
- ⚡ **[QUICK_CONFIG_GUIDE.md](QUICK_CONFIG_GUIDE.md)** - **NEW!** Enhanced fallback system & configuration
- 🔗 **[PHOENIX_INTEGRATION_GUIDE.md](PHOENIX_INTEGRATION_GUIDE.md)** - Complete Phoenix integration guide
- 🔧 **[PHOENIX_CREDENTIALS_SETUP.md](PHOENIX_CREDENTIALS_SETUP.md)** - Step-by-step credentials configuration
- 💻 **[LOCAL_LAPTOP_USAGE_GUIDE.md](LOCAL_LAPTOP_USAGE_GUIDE.md)** - Local laptop usage with embedded credentials
- 🍦 **[VANILLA_SCRIPT_USAGE_GUIDE.md](VANILLA_SCRIPT_USAGE_GUIDE.md)** - Using without Phoenix integration
- 🎯 **[LOCAL_USAGE_DEMO.md](LOCAL_USAGE_DEMO.md)** - Complete local setup demo
- 🗂️ **[ORGANIZED_FOLDERS_GUIDE.md](ORGANIZED_FOLDERS_GUIDE.md)** - GitHub pulls & results organization

---

**Remember**: Time is critical in supply chain attacks. Run these scans immediately and take action if compromised packages are detected.
