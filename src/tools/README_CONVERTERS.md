# Worksheet Conversion Utilities

This folder contains two utilities for converting student worksheets from
Markdown to Microsoft Word (DOCX) format:

## 📄 Available Converters

### 1. Local Converter (`worksheet_converter.py`)

- **✅ Offline**: Works without internet connection
- **✅ Free**: No API costs or limits
- **✅ Private**: No data sent to external services
- **✅ Fast**: Immediate conversion
- **❌ Basic Quality**: Limited formatting capabilities

### 2. CloudConvert Converter (`cloudconvert_converter.py`)

- **✅ High Quality**: Professional-grade conversions
- **✅ Better Formatting**: Superior table, code block, and layout handling
- **✅ Reliable**: Industry-standard conversion service
- **❌ Internet Required**: Needs active internet connection
- **❌ API Key Required**: Requires CloudConvert account and API key
- **❌ Usage Limits**: Has conversion limits based on plan

---

## � Dependencies

### Required for All Features

```bash
# Install all dependencies from requirements.txt
pip install -r requirements.txt
```

### Specific Package Versions (Tested & Verified)

```bash
# Local converter dependencies
python-docx>=1.2.0     # Microsoft Word document creation (✅ Installed)
markdown>=3.4.0        # Markdown parsing (✅ Installed)

# CloudConvert dependencies
cloudconvert>=2.1.0    # CloudConvert API client (✅ Tested)
requests>=2.31.0       # HTTP requests (✅ Installed)
```

### Automatic Installation in Codespaces

- All dependencies are automatically installed via `requirements.txt`
- CloudConvert API key is pre-configured via Codespaces secrets
- Git LFS is automatically configured in devcontainer
- No manual setup required for new Codespace instances

---

## �🚀 Quick Start

### Local Converter (Recommended for Development)

```bash
# Install dependencies (now included in requirements.txt)
pip install python-docx>=1.2.0 markdown>=3.4.0

# Convert all worksheets (✅ Tested - 5 worksheets found)
python src/tools/worksheet_converter.py --all

# Convert single worksheet
python src/tools/worksheet_converter.py --file sast-student-worksheet.md
```

### CloudConvert Converter (Recommended for Production)

```bash
# Install dependencies (already included in requirements.txt)
pip install cloudconvert>=2.1.0 requests

# Set up API key (already configured in this Codespace)
export CLOUDCONVERT_API_KEY="your_api_key_here"

# Check account info (✅ Working)
python src/tools/cloudconvert_converter.py --account-info

# Convert all worksheets (✅ Tested with 5 worksheets)
python src/tools/cloudconvert_converter.py --all

# Convert single worksheet
python src/tools/cloudconvert_converter.py --file sast-student-worksheet.md
```

---

## 🔑 CloudConvert Setup

1. **Create Account**: Sign up at
   [https://cloudconvert.com/](https://cloudconvert.com/)
2. **Get API Key**:
   - Go to
     [Dashboard → API Keys](https://cloudconvert.com/dashboard/api/v2/keys)
   - Create a new API key
   - Copy the key (JWT token starting with "eyJ")
3. **Set Environment Variable**:

   ```bash
   # Linux/Mac/Codespaces
   export CLOUDCONVERT_API_KEY="your_api_key_here"

   # Windows
   set CLOUDCONVERT_API_KEY=your_api_key_here
   ```

4. **For GitHub Codespaces**:
   - Go to your repository settings:
     `https://github.com/{username}/{repo}/settings/secrets/codespaces`
   - Add secret: `CLOUDCONVERT_API_KEY=your_api_key_here`
   - The API key will be automatically available in new Codespace instances

### ✅ Verified API Key Status

- **Format**: JWT token (starts with "eyJ")
- **Length**: ~1000+ characters
- **Status**: ✅ Working and tested with all worksheets
- **Ready**: All 5 student worksheets successfully converted

---

## 📊 Comparison

| Feature                 | Local Converter  | CloudConvert                    |
| ----------------------- | ---------------- | ------------------------------- |
| **Setup Complexity**    | Easy             | Medium (✅ Configured)           |
| **Internet Required**   | No               | Yes                             |
| **Cost**                | Free             | Free tier + paid                |
| **Conversion Quality**  | Good             | Excellent (✅ Tested)            |
| **Table Formatting**    | Basic            | Professional                    |
| **Code Block Handling** | Basic            | Advanced                        |
| **Processing Speed**    | Fast             | Medium (2s delay between files) |
| **Privacy**             | Fully local      | Data sent to service            |
| **Reliability**         | High             | High (✅ 5/5 successful)         |
| **File Size Limits**    | Memory dependent | Enterprise grade                |
| **Git LFS Integration** | Manual           | ✅ Automatic                     |

---

## 💡 Usage Recommendations

### **For Instructors/Classroom Use:**

- **Use Local Converter** for quick conversions and development
- **Use CloudConvert** when distributing worksheets to students or parents

### **For Educational Institutions:**

- **Use Local Converter** for internal development and testing
- **Use CloudConvert** for final worksheet production and official distribution

### **For Individual Teachers:**

- Start with **Local Converter** to learn the system
- Upgrade to **CloudConvert** when you need professional-quality documents

---

## 🛠️ Command Examples

### Local Converter Examples

```bash
# List available worksheets
python src/tools/worksheet_converter.py --list

# Convert all with verbose output
python src/tools/worksheet_converter.py --all --verbose

# Convert to custom directory
python src/tools/worksheet_converter.py --all --output-dir ./final_worksheets

# Convert specific file
python src/tools/worksheet_converter.py --file network-student-worksheet.md
```

### CloudConvert Examples

```bash
# Check account info and credits
python src/tools/cloudconvert_converter.py --account-info

# List available worksheets
python src/tools/cloudconvert_converter.py --list

# Convert all with verbose logging
python src/tools/cloudconvert_converter.py --all --verbose

# Convert to custom directory
python src/tools/cloudconvert_converter.py --all --output-dir ./professional_docs

# Convert specific file
python src/tools/cloudconvert_converter.py --file sast-student-worksheet.md
```

---

## 🔄 Workflow Recommendations

### Development Workflow

1. **Develop** worksheets in Markdown
2. **Test** with local converter for quick feedback
3. **Finalize** content and formatting
4. **Produce** final versions with CloudConvert

### Classroom Distribution

1. **Create** high-quality versions with CloudConvert
2. **Distribute** DOCX files to students
3. **Update** worksheets as needed and reconvert

---

## ✅ Current Status (Updated September 16, 2025)

### **CloudConvert Integration Status:**

- ✅ **API Key**: Configured and working in Codespaces
- ✅ **All Dependencies**: Installed and verified (cloudconvert 2.1.0)
- ✅ **Batch Conversion**: Successfully converted all 5 worksheets
- ✅ **Git LFS Integration**: All DOCX files automatically tracked
- ✅ **Quality**: Professional-grade output verified

### **Generated Files (CloudConvert):**

1. ✅ `dast-student-worksheet.docx` (15.8 KB)
2. ✅ `network-student-worksheet.docx` (17.5 KB)
3. ✅ `penetration-testing-student-worksheet.docx` (18.5 KB)
4. ✅ `sandbox-student-worksheet.docx` (17.3 KB)
5. ✅ `sast-student-worksheet.docx` (15.6 KB)

### **Repository Integration:**

- ✅ All DOCX files tracked by Git LFS
- ✅ Devcontainer configured for automatic setup
- ✅ Requirements.txt updated with correct versions
- ✅ Documentation updated with tested procedures

---

## ⚠️ Important Notes

- **Overwrite Behavior**: Both converters will overwrite existing DOCX files
- **File Names**: DOCX files will have the same name as MD files (with .docx
  extension)
- **Error Handling**: Both converters include comprehensive error handling and
  status reporting
- **Large Files**: CloudConvert handles large files better than local conversion
- **Batch Processing**: Both support converting all worksheets at once

---

## 🆘 Troubleshooting

### Local Converter Issues

```bash
# Check dependencies
pip list | grep -E "(python-docx|markdown)"

# Reinstall if needed
pip install --upgrade python-docx markdown
```

### CloudConvert Issues

```bash
# Verify API key is set
echo "API Key present: ${CLOUDCONVERT_API_KEY:+YES}"

# Check API key format (should start with "eyJ")
echo "API Key format: ${CLOUDCONVERT_API_KEY:0:3}..."

# Verify CloudConvert package version
pip show cloudconvert

# Test API connection
python src/tools/cloudconvert_converter.py --account-info

# Test with single file first
python src/tools/cloudconvert_converter.py --file sast-student-worksheet.md --verbose
```

### Dependency Verification

```bash
# Check all required packages
pip list | grep -E "(python-docx|markdown|cloudconvert|requests)"

# Reinstall specific packages if needed
pip install --upgrade python-docx markdown cloudconvert requests

# Verify Git LFS is working
git lfs track
git lfs ls-files
```

### Common Problems

- **Permission Errors**: Ensure write permissions in output directory
- **Network Issues**: Check internet connection for CloudConvert
- **API Limits**: Monitor CloudConvert usage and upgrade plan if needed
- **File Not Found**: Verify worksheet files exist in `docs/student-worksheets/`

---

**🎓 Both utilities are designed to help educators create professional,
distributable worksheets for cybersecurity education!**
