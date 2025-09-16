#!/usr/bin/env python3
"""
CloudConvert Worksheet Converter - Markdown to DOCX via CloudConvert API

This script uses the CloudConvert API to convert student worksheets from Markdown 
to high-quality DOCX format. CloudConvert typically produces better formatting 
results than local conversion libraries.

Requirements:
- CloudConvert API key (set as environment variable CLOUDCONVERT_API_KEY)
- Internet connection
- cloudconvert Python package

Setup:
1. Sign up at https://cloudconvert.com/
2. Get your API key from the dashboard
3. Set environment variable: export CLOUDCONVERT_API_KEY="your_api_key"
4. Install dependencies: pip install cloudconvert

Usage:
    python src/cloudconvert_converter.py [options]

Examples:
    # Convert single file
    python src/cloudconvert_converter.py --file sast-student-worksheet.md
    
    # Convert all worksheets
    python src/cloudconvert_converter.py --all
    
    # Convert with custom output directory
    python src/cloudconvert_converter.py --all --output-dir ./converted_docs
"""

import os
import sys
import time
import argparse
from pathlib import Path
from typing import List, Optional, Dict, Any

try:
    import requests
    import cloudconvert
    from cloudconvert import Job, Task
except ImportError as e:
    print(f"❌ Missing required dependencies: {e}")
    print("📦 Install with: pip install cloudconvert requests")
    sys.exit(1)


class CloudConvertWorksheetConverter:
    """Converts Markdown worksheets to DOCX using CloudConvert API."""

    def __init__(self, api_key: Optional[str] = None, verbose: bool = False):
        """Initialize the CloudConvert converter."""
        self.api_key = api_key or os.getenv('CLOUDCONVERT_API_KEY')
        self.verbose = verbose
        self.worksheets_dir = Path("docs/student-worksheets")
        self.converted_count = 0

        if not self.api_key:
            print("❌ CloudConvert API key not found!")
            print("🔑 Set your API key as environment variable:")
            print("   export CLOUDCONVERT_API_KEY='your_api_key_here'")
            print(
                "📘 Get your API key from: https://cloudconvert.com/dashboard/api/v2/keys")
            sys.exit(1)

        # Initialize CloudConvert client
        try:
            cloudconvert.configure(api_key=self.api_key)
            self.log("CloudConvert client initialized successfully")
        except Exception as e:
            print(f"❌ Failed to initialize CloudConvert client: {e}")
            sys.exit(1)

    def log(self, message: str) -> None:
        """Print verbose log messages."""
        if self.verbose:
            print(f"🔧 {message}")

    def validate_api_key(self) -> bool:
        """Validate the CloudConvert API key."""
        try:
            # Test API key by creating a simple job
            Job.list()
            self.log("API key validated successfully")
            return True
        except Exception as e:
            print(f"❌ Invalid API key or API error: {e}")
            return False

    def convert_markdown_to_docx(self, input_file: Path, output_file: Path) -> bool:
        """
        Convert a single Markdown file to DOCX using CloudConvert.

        Args:
            input_file: Path to the input Markdown file
            output_file: Path where the output DOCX file should be saved

        Returns:
            bool: True if conversion successful, False otherwise
        """
        self.log(
            f"Starting conversion: {input_file.name} → {output_file.name}")

        try:
            # Create a job
            job = Job.create({
                'tasks': {
                    'upload-my-file': {
                        'operation': 'import/upload'
                    },
                    'convert-my-file': {
                        'operation': 'convert',
                        'input': 'upload-my-file',
                        'input_format': 'md',
                        'output_format': 'docx',
                        'options': {
                            'page_range': '1-',
                            'optimize_print': False,
                            'embed_images': True,
                        }
                    },
                    'export-my-file': {
                        'operation': 'export/url',
                        'input': 'convert-my-file'
                    }
                }
            })

            job_id = job['id']
            self.log(f"Created job: {job_id}")

            # Get upload task
            upload_task = None
            for task in job['tasks']:
                if task['name'] == 'upload-my-file':
                    upload_task = task
                    break

            if not upload_task:
                print(f"❌ Upload task not found in job {job_id}")
                return False

            upload_task_id = upload_task['id']
            self.log(f"Upload task ID: {upload_task_id}")

            # Upload the file
            self.log(f"Uploading file: {input_file}")
            upload_task = Task.upload(
                upload_task_id,
                file=open(input_file, 'rb')
            )
            self.log("File uploaded successfully")

            # Wait for job completion
            self.log("Waiting for conversion to complete...")
            job = Job.wait(job_id)

            if job['status'] == 'finished':
                self.log("Conversion completed successfully")

                # Find the export task
                export_task = None
                for task in job['tasks']:
                    if (task['name'] == 'export-my-file' and
                            task['status'] == 'finished'):
                        export_task = task
                        break

                if not export_task:
                    print(f"❌ Export task not found or not finished")
                    return False

                # Get download URL
                file_data = export_task['result']['files'][0]
                download_url = file_data['url']
                filename = file_data['filename']

                self.log(f"Download URL obtained: {filename}")

                # Download the converted file
                self.log(f"Downloading converted file to: {output_file}")
                response = requests.get(download_url)
                response.raise_for_status()

                # Ensure output directory exists
                output_file.parent.mkdir(parents=True, exist_ok=True)

                # Save the file
                with open(output_file, 'wb') as f:
                    f.write(response.content)

                self.log(f"File saved successfully: {output_file}")
                return True

            else:
                print(f"❌ Job failed with status: {job['status']}")
                if 'message' in job:
                    print(f"Error message: {job['message']}")
                return False

        except Exception as e:
            print(f"❌ Error during conversion: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return False

    def convert_worksheet(self, markdown_file: Path, output_dir: Path) -> Optional[Path]:
        """Convert a single worksheet from Markdown to DOCX."""
        self.log(f"Converting {markdown_file.name}")

        if not markdown_file.exists():
            print(f"❌ File not found: {markdown_file}")
            return None

        # Determine output file path
        output_file = output_dir / f"{markdown_file.stem}.docx"

        # Perform conversion
        if self.convert_markdown_to_docx(markdown_file, output_file):
            self.converted_count += 1
            print(f"✅ Converted: {markdown_file.name} → {output_file.name}")
            return output_file
        else:
            print(f"❌ Failed to convert: {markdown_file.name}")
            return None

    def convert_all_worksheets(self, output_dir: Path = None) -> List[Path]:
        """Convert all student worksheets to DOCX format."""
        if output_dir is None:
            output_dir = self.worksheets_dir

        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)

        # Find all worksheet files
        worksheet_files = list(self.worksheets_dir.glob("*.md"))

        if not worksheet_files:
            print(f"❌ No worksheet files found in {self.worksheets_dir}")
            return []

        print(f"📄 Found {len(worksheet_files)} worksheet files")

        # Validate API key before starting batch conversion
        if not self.validate_api_key():
            return []

        converted_files = []
        for i, worksheet_file in enumerate(worksheet_files, 1):
            print(
                f"\n🔄 Converting {i}/{len(worksheet_files)}: {worksheet_file.name}")
            output_file = self.convert_worksheet(worksheet_file, output_dir)
            if output_file:
                converted_files.append(output_file)

            # Add small delay between conversions to be respectful to the API
            if i < len(worksheet_files):
                self.log("Waiting 2 seconds before next conversion...")
                time.sleep(2)

        return converted_files

    def convert_single_worksheet(self, filename: str, output_dir: Path = None) -> Optional[Path]:
        """Convert a single worksheet by filename."""
        if output_dir is None:
            output_dir = self.worksheets_dir

        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)

        worksheet_file = self.worksheets_dir / filename

        if not worksheet_file.exists():
            print(f"❌ Worksheet file not found: {worksheet_file}")
            return None

        # Validate API key
        if not self.validate_api_key():
            return None

        return self.convert_worksheet(worksheet_file, output_dir)

    def get_account_info(self) -> Dict[str, Any]:
        """Get CloudConvert account information."""
        try:
            jobs = Job.list()
            return {
                'status': 'API key is valid',
                'jobs_count': len(jobs.get('data', [])),
                'api_working': True
            }
        except Exception as e:
            return {'error': str(e)}


def main():
    """Main function for command-line usage."""
    parser = argparse.ArgumentParser(
        description="Convert student worksheets from Markdown to DOCX using CloudConvert API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --all                              # Convert all worksheets
  %(prog)s --file sast-student-worksheet.md  # Convert specific worksheet
  %(prog)s --all --output-dir ./converted     # Convert to custom directory
  %(prog)s --account-info                     # Show CloudConvert account info

Setup:
  1. Get API key from: https://cloudconvert.com/dashboard/api/v2/keys
  2. Set environment variable: export CLOUDCONVERT_API_KEY="your_api_key"
  3. Install dependencies: pip install cloudconvert requests
        """
    )

    parser.add_argument(
        '--all',
        action='store_true',
        help='Convert all student worksheets'
    )

    parser.add_argument(
        '--file',
        type=str,
        help='Convert specific worksheet file (e.g., sast-student-worksheet.md)'
    )

    parser.add_argument(
        '--output-dir',
        type=str,
        help='Output directory for DOCX files (default: same as source)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )

    parser.add_argument(
        '--list',
        action='store_true',
        help='List available worksheet files'
    )

    parser.add_argument(
        '--account-info',
        action='store_true',
        help='Show CloudConvert account information'
    )

    parser.add_argument(
        '--api-key',
        type=str,
        help='CloudConvert API key (overrides environment variable)'
    )

    args = parser.parse_args()

    # Change to project root directory
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    os.chdir(project_root)

    # Initialize converter
    converter = CloudConvertWorksheetConverter(
        api_key=args.api_key,
        verbose=args.verbose
    )

    # Show account info
    if args.account_info:
        print("🔑 CloudConvert Account Information")
        print("=" * 40)
        account_info = converter.get_account_info()
        if 'error' in account_info:
            print(f"❌ Error: {account_info['error']}")
        else:
            print(f"📧 Email: {account_info['email']}")
            print(f"💳 Credits: {account_info['credits']}")
            print(f"📋 Plan: {account_info['plan']}")
        return

    # List worksheets
    if args.list:
        worksheet_files = list(converter.worksheets_dir.glob("*.md"))
        print(f"📄 Available worksheets in {converter.worksheets_dir}:")
        for i, file in enumerate(worksheet_files, 1):
            print(f"  {i}. {file.name}")
        return

    # Determine output directory
    output_dir = Path(
        args.output_dir) if args.output_dir else converter.worksheets_dir

    print("☁️  CloudConvert Worksheet Converter")
    print("=" * 50)

    # Convert worksheets
    if args.all:
        print("🔄 Converting all student worksheets via CloudConvert...")
        converted_files = converter.convert_all_worksheets(output_dir)

        print("\n" + "=" * 50)
        print(
            f"✅ Conversion complete! {converter.converted_count} files converted.")
        print(f"📁 Output directory: {output_dir.absolute()}")

        if converted_files:
            print("\n📄 Converted files:")
            for file in converted_files:
                print(f"  • {file.name}")

    elif args.file:
        print(f"🔄 Converting {args.file} via CloudConvert...")
        output_file = converter.convert_single_worksheet(args.file, output_dir)

        if output_file:
            print(f"✅ Conversion complete!")
            print(f"📄 Output file: {output_file}")
        else:
            print("❌ Conversion failed!")
            sys.exit(1)

    else:
        print("❌ Please specify --all, --file, --list, or --account-info option")
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
