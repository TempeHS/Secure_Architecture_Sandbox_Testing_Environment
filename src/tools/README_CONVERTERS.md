# Document Conversion Utilities

## Available Converters

### 1. Markdown to DOCX (`worksheet_converter.py`)
- **Purpose**: Convert markdown to Word documents
- **Features**: Offline, free, basic formatting
- **Best for**: Quick conversions, development

### 2. CloudConvert DOCX (`cloudconvert_converter.py`)
- **Purpose**: High-quality markdown to Word conversion
- **Features**: Professional formatting, requires API key
- **Best for**: Final document distribution

### 3. Markdown to PDF (`md_to_pdf_converter.py`)
- **Purpose**: Convert markdown to PDF with GitHub styling
- **Features**: Two page break modes, A4 optimised, images supported
- **Best for**: Print-ready documents

## Installation

Each converter requires specific dependencies to be installed before use.

### DOCX Converter Dependencies
```bash
pip install python-docx markdown
```

### CloudConvert Dependencies
```bash
pip install cloudconvert requests
```

### PDF Converter Dependencies
```bash
# System dependencies (Ubuntu/Debian)
sudo apt-get install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0

# Python packages
pip install weasyprint markdown pygments
```

## Usage

### DOCX Converter
```bash
# Install dependencies first
pip install python-docx markdown

# Convert all worksheets
python src/tools/worksheet_converter.py --all

# Convert single file
python src/tools/worksheet_converter.py --file filename.md
```

### CloudConvert (requires API key)
```bash
# Install dependencies first
pip install cloudconvert requests

# Set API key
export CLOUDCONVERT_API_KEY="your_api_key_here"

# Convert all worksheets
python src/tools/cloudconvert_converter.py --all

# Convert single file
python src/tools/cloudconvert_converter.py --file filename.md
```

### PDF Converter
```bash
# Install system dependencies first (Ubuntu/Debian)
sudo apt-get install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0

# Install Python dependencies
pip install weasyprint markdown pygments

# Convert all files
python src/tools/md_to_pdf_converter.py --all

# Convert single file
python src/tools/md_to_pdf_converter.py --file filename.md

# Choose page break mode
python src/tools/md_to_pdf_converter.py --file filename.md --page-break-mode sections
python src/tools/md_to_pdf_converter.py --file filename.md --page-break-mode continuous
```

## PDF Page Break Modes
- **sections**: New page for each `##` heading (structured documents)
- **continuous**: No section breaks (compact printing)

## CloudConvert Setup
1. Sign up at [cloudconvert.com](https://cloudconvert.com/)
2. Get API key from dashboard
3. Set environment variable: `export CLOUDCONVERT_API_KEY="your_key"`
