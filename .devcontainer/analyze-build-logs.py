#!/usr/bin/env python3
"""
Build Process Log Analyzer
Analyzes build logs to identify failures, performance issues, and trends.
"""

import os
import re
import sys
import json
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, Counter


class BuildLogAnalyzer:
    def __init__(self, log_dir="/tmp/sandbox-build-logs"):
        self.log_dir = Path(log_dir)
        self.main_log = self.log_dir / "build-process.log"
        self.error_log = self.log_dir / "build-errors.log"
        self.performance_log = self.log_dir / "build-performance.log"

        # Patterns for parsing log entries
        self.log_pattern = re.compile(
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) '
            r'\[([A-Z]+)\] \[([A-Z_]+)\] \[PID:([^\]]+)\] (.+)'
        )

        self.performance_pattern = re.compile(
            r'Process \'([^\']+)\' took ([0-9.]+)s \[Status: ([A-Z_]+)\]'
        )

        self.docker_pattern = re.compile(
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) '
            r'\[DOCKER-([A-Z]+)\] \[([A-Z_]+)\] (.+)'
        )

        self.install_pattern = re.compile(
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) '
            r'\[INSTALL-([A-Z]+)\] (.+)'
        )

    def parse_log_entry(self, line):
        """Parse a single log line into components."""
        # Try main log pattern first
        match = self.log_pattern.match(line.strip())
        if match:
            timestamp, level, component, pid, message = match.groups()
            return {
                'timestamp': datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f'),
                'level': level,
                'component': component,
                'pid': pid,
                'message': message,
                'source': 'main'
            }

        # Try Docker build pattern
        match = self.docker_pattern.match(line.strip())
        if match:
            timestamp, level, stage, message = match.groups()
            return {
                'timestamp': datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f'),
                'level': level,
                'component': f'DOCKER-{stage}',
                'pid': 'docker',
                'message': message,
                'source': 'docker'
            }

        # Try install tools pattern
        match = self.install_pattern.match(line.strip())
        if match:
            timestamp, level, message = match.groups()
            return {
                'timestamp': datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f'),
                'level': level,
                'component': 'INSTALL',
                'pid': 'installer',
                'message': message,
                'source': 'installer'
            }

        return None

    def load_logs(self):
        """Load and parse all log files."""
        logs = []

        # Load main log
        if self.main_log.exists():
            with open(self.main_log, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    if line.startswith('#') or not line.strip():
                        continue
                    entry = self.parse_log_entry(line)
                    if entry:
                        entry['line_number'] = line_num
                        entry['file'] = 'main'
                        logs.append(entry)

        # Load Docker build logs from /tmp if they exist
        docker_log = Path('/tmp/docker-build.log')
        if docker_log.exists():
            with open(docker_log, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    entry = self.parse_log_entry(line)
                    if entry:
                        entry['line_number'] = line_num
                        entry['file'] = 'docker'
                        logs.append(entry)

        # Load tool installation logs
        install_log = Path('/tmp/tool-install.log')
        if install_log.exists():
            with open(install_log, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    entry = self.parse_log_entry(line)
                    if entry:
                        entry['line_number'] = line_num
                        entry['file'] = 'install'
                        logs.append(entry)

        # Sort by timestamp
        logs.sort(key=lambda x: x['timestamp'])
        return logs

    def analyze_errors(self, logs):
        """Analyze error patterns and trends."""
        errors = [log for log in logs if log['level'] in ['ERROR', 'FATAL']]
        warnings = [log for log in logs if log['level'] == 'WARN']

        error_by_component = Counter(log['component'] for log in errors)
        warning_by_component = Counter(log['component'] for log in warnings)

        # Common error patterns
        error_patterns = defaultdict(list)
        for error in errors:
            message = error['message'].lower()
            if 'timeout' in message:
                error_patterns['Network Timeouts'].append(error)
            elif 'permission' in message:
                error_patterns['Permission Issues'].append(error)
            elif 'not found' in message or 'command not found' in message:
                error_patterns['Missing Dependencies'].append(error)
            elif 'docker' in message:
                error_patterns['Docker Issues'].append(error)
            elif 'pip' in message or 'python' in message:
                error_patterns['Python Package Issues'].append(error)
            else:
                error_patterns['Other Errors'].append(error)

        return {
            'total_errors': len(errors),
            'total_warnings': len(warnings),
            'errors_by_component': dict(error_by_component),
            'warnings_by_component': dict(warning_by_component),
            'error_patterns': {k: len(v) for k, v in error_patterns.items()},
            'error_details': dict(error_patterns)
        }

    def analyze_performance(self, logs):
        """Analyze build performance and timing."""
        start_events = [log for log in logs if log['level'] == 'START']
        end_events = [log for log in logs if log['level'] == 'END']

        # Match start and end events by PID
        processes = {}
        for start in start_events:
            processes[start['pid']] = {
                'component': start['component'],
                'start_time': start['timestamp'],
                'start_message': start['message']
            }

        completed_processes = []
        for end in end_events:
            if end['pid'] in processes:
                proc = processes[end['pid']]
                duration = (end['timestamp'] -
                            proc['start_time']).total_seconds()

                # Extract status from end message
                status = 'UNKNOWN'
                if 'SUCCESS' in end['message']:
                    status = 'SUCCESS'
                elif 'FAILED' in end['message']:
                    status = 'FAILED'
                elif 'PARTIAL' in end['message']:
                    status = 'PARTIAL_SUCCESS'

                completed_processes.append({
                    'component': proc['component'],
                    'process': proc['start_message'],
                    'duration': duration,
                    'status': status,
                    'start_time': proc['start_time'],
                    'end_time': end['timestamp']
                })

        # Performance statistics
        durations_by_component = defaultdict(list)
        for proc in completed_processes:
            durations_by_component[proc['component']].append(proc['duration'])

        performance_stats = {}
        for component, durations in durations_by_component.items():
            performance_stats[component] = {
                'count': len(durations),
                'total_time': sum(durations),
                'avg_time': sum(durations) / len(durations),
                'min_time': min(durations),
                'max_time': max(durations)
            }

        return {
            'completed_processes': completed_processes,
            'performance_by_component': performance_stats,
            'total_build_time': sum(proc['duration'] for proc in completed_processes),
            'slowest_processes': sorted(completed_processes, key=lambda x: x['duration'], reverse=True)[:10]
        }

    def analyze_trends(self, logs):
        """Analyze trends over time."""
        if not logs:
            return {}

        start_time = logs[0]['timestamp']
        end_time = logs[-1]['timestamp']
        total_duration = (end_time - start_time).total_seconds()

        # Events by minute
        events_by_minute = defaultdict(lambda: defaultdict(int))
        for log in logs:
            minute = log['timestamp'].replace(second=0, microsecond=0)
            events_by_minute[minute][log['level']] += 1

        # Component activity timeline
        component_timeline = defaultdict(list)
        for log in logs:
            component_timeline[log['component']].append({
                'timestamp': log['timestamp'],
                'level': log['level'],
                'message': log['message']
            })

        return {
            'build_start': start_time,
            'build_end': end_time,
            'total_duration': total_duration,
            'events_by_minute': dict(events_by_minute),
            'component_timeline': dict(component_timeline),
            'total_events': len(logs)
        }

    def generate_report(self, output_format='text'):
        """Generate comprehensive analysis report."""
        print("🔍 Loading and parsing build logs...")
        logs = self.load_logs()

        if not logs:
            print("❌ No logs found to analyze!")
            return

        print(f"📊 Analyzing {len(logs)} log entries...")

        # Perform analyses
        error_analysis = self.analyze_errors(logs)
        performance_analysis = self.analyze_performance(logs)
        trend_analysis = self.analyze_trends(logs)

        if output_format == 'json':
            return self._generate_json_report(error_analysis, performance_analysis, trend_analysis, logs)
        else:
            return self._generate_text_report(error_analysis, performance_analysis, trend_analysis, logs)

    def _generate_text_report(self, error_analysis, performance_analysis, trend_analysis, logs):
        """Generate human-readable text report."""
        report = []
        report.append("="*80)
        report.append("🔍 BUILD PROCESS LOG ANALYSIS REPORT")
        report.append("="*80)
        report.append(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Log Directory: {self.log_dir}")
        report.append("")

        # Summary
        report.append("📋 SUMMARY")
        report.append("-" * 40)
        report.append(f"Total Log Entries: {len(logs)}")
        report.append(
            f"Build Duration: {trend_analysis.get('total_duration', 0):.2f} seconds")
        report.append(
            f"Build Start: {trend_analysis.get('build_start', 'Unknown')}")
        report.append(
            f"Build End: {trend_analysis.get('build_end', 'Unknown')}")
        report.append("")

        # Error Analysis
        report.append("🚨 ERROR ANALYSIS")
        report.append("-" * 40)
        report.append(f"Total Errors: {error_analysis['total_errors']}")
        report.append(f"Total Warnings: {error_analysis['total_warnings']}")
        report.append("")

        if error_analysis['errors_by_component']:
            report.append("Errors by Component:")
            for component, count in sorted(error_analysis['errors_by_component'].items(), key=lambda x: x[1], reverse=True):
                report.append(f"  • {component}: {count} errors")
            report.append("")

        if error_analysis['error_patterns']:
            report.append("Error Patterns:")
            for pattern, count in sorted(error_analysis['error_patterns'].items(), key=lambda x: x[1], reverse=True):
                report.append(f"  • {pattern}: {count} occurrences")
            report.append("")

        # Performance Analysis
        report.append("⚡ PERFORMANCE ANALYSIS")
        report.append("-" * 40)
        total_processes = len(performance_analysis['completed_processes'])
        successful_processes = sum(
            1 for p in performance_analysis['completed_processes'] if p['status'] == 'SUCCESS')
        failed_processes = sum(
            1 for p in performance_analysis['completed_processes'] if p['status'] == 'FAILED')

        report.append(f"Completed Processes: {total_processes}")
        report.append(f"Successful: {successful_processes}")
        report.append(f"Failed: {failed_processes}")
        report.append(
            f"Success Rate: {(successful_processes/total_processes*100) if total_processes > 0 else 0:.1f}%")
        report.append(
            f"Total Build Time: {performance_analysis['total_build_time']:.2f} seconds")
        report.append("")

        if performance_analysis['performance_by_component']:
            report.append("Performance by Component:")
            for component, stats in sorted(performance_analysis['performance_by_component'].items(), key=lambda x: x[1]['total_time'], reverse=True):
                report.append(f"  • {component}:")
                report.append(f"    - Total Time: {stats['total_time']:.2f}s")
                report.append(f"    - Average Time: {stats['avg_time']:.2f}s")
                report.append(f"    - Process Count: {stats['count']}")
            report.append("")

        if performance_analysis['slowest_processes']:
            report.append("Slowest Processes:")
            for i, proc in enumerate(performance_analysis['slowest_processes'][:5], 1):
                report.append(
                    f"  {i}. {proc['component']} - {proc['process']}: {proc['duration']:.2f}s ({proc['status']})")
            report.append("")

        # Recent Errors (if any)
        recent_errors = [log for log in logs if log['level']
                         in ['ERROR', 'FATAL']][-10:]
        if recent_errors:
            report.append("🔥 RECENT ERRORS")
            report.append("-" * 40)
            for error in recent_errors:
                report.append(
                    f"[{error['timestamp']}] {error['component']}: {error['message']}")
            report.append("")

        # Recommendations
        report.append("💡 RECOMMENDATIONS")
        report.append("-" * 40)

        if error_analysis['total_errors'] == 0:
            report.append("✅ No errors detected - build process is healthy!")
        else:
            if 'Network Timeouts' in error_analysis['error_patterns']:
                report.append(
                    "• Consider increasing timeout values for network operations")
            if 'Permission Issues' in error_analysis['error_patterns']:
                report.append("• Review file permissions and user privileges")
            if 'Docker Issues' in error_analysis['error_patterns']:
                report.append("• Check Docker daemon status and permissions")
            if 'Python Package Issues' in error_analysis['error_patterns']:
                report.append(
                    "• Review Python package dependencies and installation order")

        if performance_analysis['total_build_time'] > 300:  # 5 minutes
            report.append(
                "• Build time is high - consider optimizing slow components")

        report.append("")
        report.append("="*80)

        return "\n".join(report)

    def _generate_json_report(self, error_analysis, performance_analysis, trend_analysis, logs):
        """Generate machine-readable JSON report."""
        return json.dumps({
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'log_directory': str(self.log_dir),
                'total_entries': len(logs)
            },
            'summary': {
                'build_duration': trend_analysis.get('total_duration', 0),
                'build_start': trend_analysis.get('build_start', '').isoformat() if trend_analysis.get('build_start') else None,
                'build_end': trend_analysis.get('build_end', '').isoformat() if trend_analysis.get('build_end') else None,
                'total_processes': len(performance_analysis['completed_processes']),
                'success_rate': len([p for p in performance_analysis['completed_processes'] if p['status'] == 'SUCCESS']) / len(performance_analysis['completed_processes']) if performance_analysis['completed_processes'] else 0
            },
            'errors': error_analysis,
            'performance': {k: v for k, v in performance_analysis.items() if k != 'completed_processes'},
            'trends': trend_analysis,
            'recent_errors': [
                {
                    'timestamp': log['timestamp'].isoformat(),
                    'component': log['component'],
                    'message': log['message']
                }
                for log in logs if log['level'] in ['ERROR', 'FATAL']
            ][-10:]
        }, indent=2, default=str)


def main():
    parser = argparse.ArgumentParser(description='Analyze build process logs')
    parser.add_argument('--log-dir', default='/tmp/sandbox-build-logs',
                        help='Directory containing log files')
    parser.add_argument('--format', choices=['text', 'json'], default='text',
                        help='Output format')
    parser.add_argument('--output', help='Output file (default: stdout)')

    args = parser.parse_args()

    analyzer = BuildLogAnalyzer(args.log_dir)
    report = analyzer.generate_report(args.format)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report written to {args.output}")
    else:
        print(report)


if __name__ == '__main__':
    main()
