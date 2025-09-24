# Quick Configuration Guide - Enhanced Fallback System

## 🚀 Quick Start (2 Minutes)

### **Option 1: No Configuration Required (Recommended for Public Repos)**
```bash
# Works immediately with public repositories using automatic fallback
python3 enhanced_npm_compromise_detector_phoenix.py \
  --repo-list repos.txt \
  --light-scan \
  --import-all \
  --tag_vuln="security-audit,Q4-2025" \
  --tag_asset="production"
```

### **Option 2: With GitHub Token (Higher Rate Limits)**
```bash
# Generate token: https://github.com/settings/tokens
export GITHUB_TOKEN=your_github_token_here

python3 enhanced_npm_compromise_detector_phoenix.py \
  --repo-list repos.txt \
  --light-scan \
  --import-all
```

### **Option 3: Full Phoenix Integration**
```bash
# 1. Create config template
python3 enhanced_npm_compromise_detector_phoenix.py --create-config

# 2. Edit .config with your Phoenix credentials
# 3. Run with Phoenix integration
python3 enhanced_npm_compromise_detector_phoenix.py \
  --repo-list repos.txt \
  --light-scan \
  --enable-phoenix \
  --import-all
```

---

## 🔄 Enhanced Fallback System

### **How It Works**

The scanner uses a **3-tier fallback system** that automatically handles GitHub API failures:

```
1. GitHub API Search (with/without auth)
   ↓ (if fails)
2. GitHub API Fallback (direct file access)
   ↓ (if fails)  
3. Direct Raw Access (raw.githubusercontent.com)
   ↓ (if fails)
4. Mark as completely failed
```

### **What You'll See**

#### **✅ Successful Fallback:**
```
🔄 GitHub API failed completely, trying direct raw access...
🔄 Fallback: Trying direct raw GitHub access for optimizely/react-sdk
✅ Direct access found: package.json
✅ Direct access found: yarn.lock
✅ Fallback successful: Found 2 NPM file(s) via direct access
```

#### **📊 Enhanced Reporting:**
```
GITHUB ACCESS SUMMARY:
----------------------
API failures: 3 repositories
Fallback successes: 2 repositories
Complete failures: 1 repositories

REPOSITORIES ACCESSED VIA FALLBACK (Direct Raw GitHub):
 1. react-sdk
    Status: ✅ Fallback successful
    Files found: 2
    Access method: direct_raw_github
```

---

## 🛠️ Configuration Options

### **GitHub Token Setup**

#### **Environment Variable (Recommended):**
```bash
export GITHUB_TOKEN=ghp_your_token_here
```

#### **Config File:**
```ini
[phoenix]
github_token = ghp_your_token_here
```

**Token Requirements:**
- **Public repos**: `public_repo` permission
- **Private repos**: `repo` permission
- **Generate at**: https://github.com/settings/tokens

### **Custom Tags Configuration**

#### **Command Line:**
```bash
--tag_vuln="security-audit,compliance,Q4-2025"
--tag_asset="production,critical,frontend"
```

#### **Config File:**
```ini
[phoenix]
additional_vuln_tags = security-audit,compliance,Q4-2025
additional_asset_tags = production,critical,frontend
```

### **Phoenix Integration:**
```ini
[phoenix]
client_id = your_phoenix_client_id
client_secret = your_phoenix_client_secret
api_base_url = https://api.securityphoenix.cloud
assessment_name = NPM Security Scan
```

---

## 🚨 Troubleshooting

### **Common Issues (Auto-Resolved by Fallback)**

| Issue | Old Behavior | New Behavior |
|-------|-------------|-------------|
| **Invalid GitHub Token** | ❌ Empty files, JSON errors | ✅ Auto-fallback to direct access |
| **Rate Limit Exceeded** | ❌ Failed downloads | ✅ Switches to raw.githubusercontent.com |
| **Authentication Failed** | ❌ Empty package.json files | ✅ Bypasses API, direct download |

### **When Fallback Won't Help**

- **❌ Private repositories** - Requires valid token
- **❌ Non-existent repositories** - Nothing to fallback to
- **❌ Repositories with no NPM files** - Android/iOS projects, etc.

### **Debug Commands**

```bash
# Check what's happening
python3 enhanced_npm_compromise_detector_phoenix.py \
  --repo-list repos.txt \
  --light-scan \
  --debug

# Test single repository
echo "https://github.com/optimizely/react-sdk" > test_repo.txt
python3 enhanced_npm_compromise_detector_phoenix.py \
  --repo-list test_repo.txt \
  --light-scan
```

---

## 📋 Command Reference

### **Basic Commands**

```bash
# Local directory scan with all libraries
python3 enhanced_npm_compromise_detector_phoenix.py . --import-all

# Repository list with custom tags
python3 enhanced_npm_compromise_detector_phoenix.py \
  --repo-list repos.txt \
  --light-scan \
  --import-all \
  --tag_vuln="audit-2025" \
  --tag_asset="production"

# Full Phoenix integration
python3 enhanced_npm_compromise_detector_phoenix.py \
  --repo-list repos.txt \
  --light-scan \
  --enable-phoenix \
  --import-all \
  --organize-folders \
  --output security-report.txt
```

### **Enterprise Batch Scanning**

```bash
# Generate repository list from GitHub API
curl -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/orgs/your-org/repos?per_page=100" | \
  jq -r '.[].clone_url' > org_repos.txt

# Scan all repositories with cleanup
python3 enhanced_npm_compromise_detector_phoenix.py \
  --repo-list org_repos.txt \
  --light-scan \
  --enable-phoenix \
  --import-all \
  --organize-folders \
  --delete-local-files \
  --tag_vuln="org-audit,$(date +%Y-%m)" \
  --tag_asset="enterprise,npm-security"
```

---

## 🎯 Best Practices

### **For Public Repository Scanning:**
- ✅ No GitHub token required (fallback handles everything)
- ✅ Use `--light-scan` for speed
- ✅ Add `--import-all` for complete library visibility
- ✅ Use custom tags for organization

### **For Private Repository Scanning:**
- ✅ Valid GitHub token required
- ✅ Use `repo` permission for private repos
- ✅ Fallback still helps with rate limits

### **For Enterprise/CI-CD:**
- ✅ Use `--organize-folders` for audit trails
- ✅ Use `--delete-local-files` for cleanup
- ✅ Use `--output` with timestamps
- ✅ Set custom tags for tracking

### **Performance Optimization:**
- ✅ Light scan mode: 10x faster than full cloning
- ✅ Fallback system: No failed repositories
- ✅ Parallel processing: Handles hundreds of repos
- ✅ Smart caching: Reuses downloaded files

---

## ✅ Success Indicators

**Look for these in your scan results:**

```
✅ Fallback successful: Found 2 NPM file(s) via direct access
✅ Direct content saved: package.json
✅ Import all libraries enabled: Clean libraries will get CVSS 1.0 findings
✅ Added vulnerability tags: security-audit, Q4-2025
✅ Added asset tags: production, critical

SEVERITY SUMMARY:
CLEAN: 86    ← All clean libraries tracked
INFO: 12     ← Safe versions of monitored packages  
CRITICAL: 2  ← Compromised packages found
```

**Repository Access Success:**
```
REPOSITORIES ACCESSED VIA FALLBACK (Direct Raw GitHub):
 ✅ 2 repositories successfully recovered
 ✅ 4 NPM files downloaded with valid content
 ✅ Zero empty files or JSON parsing errors
```

The enhanced fallback system ensures **maximum repository coverage** with **zero manual intervention** required!
