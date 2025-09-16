# Worksheet Conversion Utilities

This folder contains two utilities for converting student worksheets from Markdown to Microsoft Word (DOCX) format:

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

## 🚀 Quick Start

### Local Converter (Recommended for Development)
```bash
# Install dependencies
pip install python-docx markdown

# Convert all worksheets
python src/worksheet_converter.py --all

# Convert single worksheet
python src/worksheet_converter.py --file sast-student-worksheet.md
```

### CloudConvert Converter (Recommended for Production)
```bash
# Install dependencies
pip install cloudconvert requests

# Set up API key
export CLOUDCONVERT_API_KEY="your_api_key_here"

# Check account info
python src/cloudconvert_converter.py --account-info

# Convert all worksheets
python src/cloudconvert_converter.py --all

# Convert single worksheet
python src/cloudconvert_converter.py --file sast-student-worksheet.md
```

---

## 🔑 CloudConvert Setup

1. **Create Account**: Sign up at [https://cloudconvert.com/](https://cloudconvert.com/)
2. **Get API Key**: 
   - Go to [Dashboard → API Keys](https://cloudconvert.com/dashboard/api/v2/keys)
   - Create a new API key
   - Copy the key
3. **Set Environment Variable**:
   ```bash
   # Linux/Mac
   export CLOUDCONVERT_API_KEY="your_api_key_here"
   
   # Windows
   set CLOUDCONVERT_API_KEY=your_api_key_here
   ```

---

## 📊 Comparison

| Feature | Local Converter | CloudConvert |
|---------|----------------|--------------|
| **Setup Complexity** | Easy | Medium |
| **Internet Required** | No | Yes |
| **Cost** | Free | Free tier + paid |
| **Conversion Quality** | Good | Excellent |
| **Table Formatting** | Basic | Professional |
| **Code Block Handling** | Basic | Advanced |
| **Processing Speed** | Fast | Medium (upload time) |
| **Privacy** | Fully local | Data sent to service |
| **Reliability** | High | High (service dependent) |

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
python src/worksheet_converter.py --list

# Convert all with verbose output
python src/worksheet_converter.py --all --verbose

# Convert to custom directory
python src/worksheet_converter.py --all --output-dir ./final_worksheets

# Convert specific file
python src/worksheet_converter.py --file network-student-worksheet.md
```

### CloudConvert Examples
```bash
# Check account info and credits
python src/cloudconvert_converter.py --account-info

# List available worksheets
python src/cloudconvert_converter.py --list

# Convert all with verbose logging
python src/cloudconvert_converter.py --all --verbose

# Convert to custom directory
python src/cloudconvert_converter.py --all --output-dir ./professional_docs

# Convert specific file
python src/cloudconvert_converter.py --file sast-student-worksheet.md
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

## ⚠️ Important Notes

- **Overwrite Behavior**: Both converters will overwrite existing DOCX files
- **File Names**: DOCX files will have the same name as MD files (with .docx extension)
- **Error Handling**: Both converters include comprehensive error handling and status reporting
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
# Verify API key
python src/cloudconvert_converter.py --account-info

# Check credits
echo $CLOUDCONVERT_API_KEY

# Test with single file first
python src/cloudconvert_converter.py --file sast-student-worksheet.md --verbose
```

### Common Problems
- **Permission Errors**: Ensure write permissions in output directory
- **Network Issues**: Check internet connection for CloudConvert
- **API Limits**: Monitor CloudConvert usage and upgrade plan if needed
- **File Not Found**: Verify worksheet files exist in `docs/student-worksheets/`

---

**🎓 Both utilities are designed to help educators create professional, distributable worksheets for cybersecurity education!**