#!/usr/bin/env python3
"""
Report Generator CLI Tool

Command-line interface for generating PDF reports from JSON security analysis files.
"""

from reporter.report_generator import PdfReportGenerator
import argparse
import sys
import os
import json
from pathlib import Path

# Add the src directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Generate PDF reports from security analysis JSON files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s sast_report.json
  %(prog)s dast_report.json --type dast
  %(prog)s network_report.json --output network_analysis.pdf
  %(prog)s --convert-all reports/
        """
    )

    # Input arguments
    parser.add_argument(
        'input',
        nargs='?',
        help='Path to JSON report file or directory (use --convert-all for directory)'
    )

    # Type specification
    parser.add_argument(
        '--type',
        choices=['sast', 'dast', 'network', 'sandbox'],
        help='Analyser type (auto-detected if not specified)'
    )

    # Output options
    parser.add_argument(
        '--output',
        help='Output PDF filename (auto-generated if not specified)'
    )

    parser.add_argument(
        '--reports-dir',
        default='reports',
        help='Reports directory (default: reports)'
    )

    # Conversion options
    parser.add_argument(
        '--convert-all',
        action='store_true',
        help='Convert all JSON files in the specified directory'
    )

    args = parser.parse_args()

    # Check required arguments
    if not args.input and not args.convert_all:
        print("❌ Input file or --convert-all required")
        return 1

    if args.convert_all and not args.input:
        print("❌ Directory path required when using --convert-all")
        return 1

    # Initialize generator
    try:
        generator = PdfReportGenerator(args.reports_dir)
    except Exception as e:
        print(f"❌ Error initializing PDF generator: {e}", file=sys.stderr)
        return 1

    # Main processing logic
    try:
        if args.convert_all:
            return convert_all_files(generator, args)
        else:
            return convert_single_file(generator, args)

    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        return 1


def convert_all_files(generator, args):
    """Convert all JSON files in a directory."""
    input_path = Path(args.input)

    if not input_path.exists():
        print(f"❌ Directory does not exist: {input_path}")
        return 1

    json_files = list(input_path.glob('*.json'))

    if not json_files:
        print(f"❌ No JSON files found in: {input_path}")
        return 1

    print(f"📄 Found {len(json_files)} JSON files to convert")

    success_count = 0
    error_count = 0

    for json_file in json_files:
        try:
            output_path = generator.convert_json_to_pdf(
                str(json_file), args.type)
            print(f"✅ Converted: {json_file.name} → {Path(output_path).name}")
            success_count += 1
        except Exception as e:
            print(f"❌ Error converting {json_file.name}: {e}", file=sys.stderr)
            error_count += 1

    print("\n📊 Conversion Summary:")
    print(f"   📁 Source directory: {input_path}")
    print(f"   📁 Output directory: {Path(args.reports_dir).absolute()}")
    print(f"   ✅ Successfully converted: {success_count}")
    if error_count > 0:
        print(f"   ❌ Errors: {error_count}")

    return 0 if error_count == 0 else 1


def convert_single_file(generator, args):
    """Convert a single JSON file to PDF."""
    input_path = Path(args.input)

    if not input_path.exists():
        print(f"❌ File does not exist: {input_path}")
        return 1

    if not str(input_path).lower().endswith('.json'):
        print(f"❌ Input file must be a JSON file: {input_path}")
        return 1

    try:
        if args.output:
            # Custom output filename specified - need to load JSON first
            with open(input_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            output_path = generator.generate_report(
                data, args.type or 'general', args.output)
        else:
            # Auto-generate output filename
            output_path = generator.convert_json_to_pdf(
                str(input_path), args.type)

        print(f"✅ PDF report generated: {output_path}")
        return 0

    except Exception as e:
        print(f"❌ Error generating report: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    exit(main())
