#!/usr/bin/env python3
"""
Report Generator CLI Tool

Command-line interface for generating markdown reports from JSON security analysis files.
"""

from reporter.report_generator import MarkdownReportGenerator
import argparse
import sys
import os
from pathlib import Path

# Add the src directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Generate markdown reports from security analysis JSON files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s sast_report.json
  %(prog)s dast_report.json --type dast
  %(prog)s network_report.json --output network_analysis.md
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
        help='Analyzer type (auto-detected if not specified)'
    )

    # Output options
    parser.add_argument(
        '--output',
        help='Output markdown filename (auto-generated if not specified)'
    )

    parser.add_argument(
        '--reports-dir',
        default='reports',
        help='Reports directory (default: reports)'
    )

    # Batch processing
    parser.add_argument(
        '--convert-all',
        action='store_true',
        help='Convert all JSON files in the specified directory'
    )

    # Display options
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress output messages'
    )

    parser.add_argument(
        '--list-files',
        action='store_true',
        help='List all JSON files in the reports directory'
    )

    args = parser.parse_args()

    # Initialize the report generator
    try:
        generator = MarkdownReportGenerator(args.reports_dir)
    except Exception as e:
        print(f"❌ Error initializing report generator: {e}", file=sys.stderr)
        return 1

    # Handle list-files option
    if args.list_files:
        reports_path = Path(args.reports_dir)
        if not reports_path.exists():
            print(f"Reports directory '{args.reports_dir}' does not exist")
            return 1

        json_files = list(reports_path.glob('*.json'))
        if not json_files:
            print(f"No JSON files found in '{args.reports_dir}'")
            return 0

        print(f"JSON files in '{args.reports_dir}':")
        for file in sorted(json_files):
            print(f"  - {file.name}")
        return 0

    # Validate input argument
    if not args.input:
        if args.convert_all:
            print("Error: --convert-all requires an input directory")
        else:
            print("Error: input file or directory is required")
        parser.print_help()
        return 1

    input_path = Path(args.input)

    # Handle convert-all option
    if args.convert_all:
        if not input_path.is_dir():
            print(f"❌ Error: '{args.input}' is not a directory")
            return 1

        json_files = list(input_path.glob('*.json'))
        if not json_files:
            print(f"No JSON files found in '{args.input}'")
            return 0

        if not args.quiet:
            print(f"Converting {len(json_files)} JSON files...")

        success_count = 0
        for json_file in json_files:
            try:
                output_path = generator.convert_json_to_markdown(
                    str(json_file), args.type)
                if not args.quiet:
                    print(f"✅ Generated: {output_path}")
                success_count += 1
            except Exception as e:
                print(
                    f"❌ Error converting {json_file.name}: {e}", file=sys.stderr)

        if not args.quiet:
            print(f"\n📊 Conversion Summary:")
            print(f"  Processed: {len(json_files)} files")
            print(f"  Successful: {success_count} files")
            print(f"  Failed: {len(json_files) - success_count} files")

        return 0 if success_count > 0 else 1

    # Handle single file conversion
    if not input_path.exists():
        print(f"❌ Error: File '{args.input}' does not exist")
        return 1

    if not input_path.is_file():
        print(f"❌ Error: '{args.input}' is not a file")
        return 1

    if not str(input_path).lower().endswith('.json'):
        print(f"❌ Error: '{args.input}' is not a JSON file")
        return 1

    try:
        if args.output:
            # Use custom output filename
            output_path = generator.generate_markdown_report(
                json_data=_load_json_file(input_path),
                analyzer_type=args.type or _detect_analyzer_type(input_path),
                output_file=args.output
            )
        else:
            # Auto-generate output filename
            output_path = generator.convert_json_to_markdown(
                str(input_path), args.type)

        if not args.quiet:
            print(f"✅ Markdown report generated: {output_path}")

    except Exception as e:
        print(f"❌ Error generating report: {e}", file=sys.stderr)
        return 1

    return 0


def _load_json_file(file_path: Path) -> dict:
    """Load and parse a JSON file."""
    import json
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def _detect_analyzer_type(file_path: Path) -> str:
    """Detect analyzer type from filename or content."""
    filename = file_path.name.lower()
    if 'sast' in filename:
        return 'sast'
    elif 'dast' in filename:
        return 'dast'
    elif 'network' in filename:
        return 'network'
    elif 'sandbox' in filename:
        return 'sandbox'
    else:
        # Try to detect from content
        try:
            data = _load_json_file(file_path)
            if 'target_path' in data and 'tools_used' in data:
                return 'sast'
            elif 'target_url' in data and 'scan_duration' in data:
                return 'dast'
            elif 'active_connections' in data or 'total_connections' in data:
                return 'network'
            else:
                return 'unknown'
        except Exception:
            return 'unknown'


if __name__ == "__main__":
    exit(main())
