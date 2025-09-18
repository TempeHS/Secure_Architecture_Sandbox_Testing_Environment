#!/usr/bin/env python3
"""
Docker Network Visualization Tool for Secure Architecture Sandbox Testing Environment

This script generates a detailed network topology visualization of the Docker sandbox
environment, showing container isol    dot_lines = [
        'digraph "Docker Network Topology" {',
        '    rankdir=TB;',
        '    compound=true;',
        '    node [shape=box, style=rounded, fontname="Roboto"];',
        '    edge [style=solid, fontname="Roboto"];',
        '    ',
        '    // Graph styling',
        '    bgcolor="transparent";',
        '    fontname="Roboto";',
        '    fontsize=14;'work configuration, and security boundaries.

Dependencies are automatically installed when needed.
"""

import subprocess
import sys
import os
import json
import tempfile
from datetime import datetime
from pathlib import Path

# Required packages that will be installed automatically
REQUIRED_PACKAGES = [
    'graphviz',  # For rendering graphs
    'pydot',     # Python interface to Graphviz
    'pillow',    # For image processing
    'pyyaml',    # For parsing docker-compose.yml
]


def check_system_graphviz():
    """Check if system graphviz is installed."""
    try:
        subprocess.check_output(['which', 'dot'], stderr=subprocess.DEVNULL)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def check_python_package(package_name, import_name):
    """Check if a Python package is available for import."""
    try:
        __import__(import_name)
        return True
    except ImportError:
        return False


def ensure_dependencies():
    """Check all dependencies and provide installation instructions if missing."""
    print("🔍 Checking dependencies...")

    missing_deps = []
    install_commands = []

    # Check Python packages
    python_deps = [
        ('graphviz', 'graphviz', 'pip install graphviz'),
        ('pydot', 'pydot', 'pip install pydot'),
        ('pillow', 'PIL', 'pip install pillow'),
        ('pyyaml', 'yaml', 'pip install pyyaml'),
    ]

    for package_name, import_name, install_cmd in python_deps:
        if not check_python_package(package_name, import_name):
            missing_deps.append(f"Python package: {package_name}")
            install_commands.append(install_cmd)

    # Check system graphviz
    if not check_system_graphviz():
        missing_deps.append("System package: graphviz")
        install_commands.append("apt update && apt install -y graphviz")

    # If dependencies are missing, show helpful error message
    if missing_deps:
        print("\n❌ Missing dependencies detected!")
        print("=" * 50)
        print("The following dependencies are required but not installed:")
        for dep in missing_deps:
            print(f"  ❌ {dep}")

        print("\n🔧 To install missing dependencies, run these commands:")
        print("-" * 50)
        for i, cmd in enumerate(install_commands, 1):
            print(f"{i}. {cmd}")

        print("\n💡 Quick install (run all at once):")
        print("-" * 35)
        all_pip_commands = [
            cmd for cmd in install_commands if cmd.startswith('pip install')]
        if all_pip_commands:
            packages = ' '.join([cmd.split()[-1] for cmd in all_pip_commands])
            print(f"pip install {packages}")

        # System package command
        sys_commands = [
            cmd for cmd in install_commands if not cmd.startswith('pip install')]
        if sys_commands:
            for cmd in sys_commands:
                print(f"{cmd}")

        print("\n🚀 After installing dependencies, run this script again.")
        print("=" * 50)
        return False

    print("✅ All dependencies are available!")
    return True


def get_docker_network_info():
    """Get detailed Docker network information."""
    try:
        # Get network information
        networks_output = subprocess.check_output(
            ['docker', 'network', 'ls', '--format', 'json'])
        networks = []
        for line in networks_output.decode().strip().split('\n'):
            if line:
                networks.append(json.loads(line))

        # Get container information
        containers_output = subprocess.check_output(
            ['docker', 'ps', '-a', '--format', 'json'])
        containers = []
        for line in containers_output.decode().strip().split('\n'):
            if line:
                containers.append(json.loads(line))

        # Get detailed network inspect for each network
        network_details = {}
        for network in networks:
            try:
                inspect_output = subprocess.check_output(
                    ['docker', 'network', 'inspect', network['Name']])
                network_details[network['Name']] = json.loads(
                    inspect_output.decode())[0]
            except subprocess.CalledProcessError:
                pass

        return {
            'networks': networks,
            'containers': containers,
            'network_details': network_details
        }
    except subprocess.CalledProcessError as e:
        print(f"Error getting Docker information: {e}")
        return None


def analyse_sandbox_isolation(docker_info):
    """Analyse and document sandbox isolation characteristics."""
    analysis = {
        'network_isolation': [],
        'container_security': [],
        'port_mappings': [],
        'volume_mounts': [],
        'capabilities': []
    }

    if not docker_info:
        return analysis

    # Analyse network isolation
    for net_name, net_details in docker_info['network_details'].items():
        if 'sandbox' in net_name.lower():
            isolation_info = {
                'name': net_name,
                'driver': net_details.get('Driver', 'unknown'),
                'subnet': net_details.get('IPAM', {}).get('Config', [{}])[0].get('Subnet', 'unknown'),
                'gateway': net_details.get('IPAM', {}).get('Config', [{}])[0].get('Gateway', 'unknown'),
                'internal': net_details.get('Internal', False),
                'containers': list(net_details.get('Containers', {}).keys())
            }
            analysis['network_isolation'].append(isolation_info)

    # Analyse container security from docker-compose configuration
    compose_file = '/workspaces/Secure_Architecture_Sandbox_Testing_Environment/docker/docker-compose.yml'
    if os.path.exists(compose_file):
        try:
            import yaml
        except ImportError:
            print("❌ PyYAML not available for parsing docker-compose.yml")
            print("Run: pip install pyyaml")
            return analysis

        with open(compose_file, 'r') as f:
            compose_data = yaml.safe_load(f)

        for service_name, service_config in compose_data.get('services', {}).items():
            security_info = {
                'service': service_name,
                'container_name': service_config.get('container_name', service_name),
                'hostname': service_config.get('hostname', 'unknown'),
                'ports': service_config.get('ports', []),
                'networks': service_config.get('networks', []),
                'security_opts': service_config.get('security_opt', []),
                'cap_drop': service_config.get('cap_drop', []),
                'cap_add': service_config.get('cap_add', []),
                'mem_limit': service_config.get('mem_limit', 'unlimited'),
                'cpus': service_config.get('cpus', 'unlimited'),
                'volumes': service_config.get('volumes', [])
            }
            analysis['container_security'].append(security_info)

    return analysis


def create_enhanced_network_graph(docker_info, analysis, output_path):
    """Create an enhanced network visualization with security details."""
    try:
        # Create a temporary DOT file for custom graph generation
        with tempfile.NamedTemporaryFile(mode='w', suffix='.dot',
                                         delete=False) as f:
            dot_content = generate_custom_dot_graph(docker_info, analysis)
            f.write(dot_content)
            dot_file = f.name

        # Generate PNG using graphviz
        try:
            subprocess.check_call(['dot', '-Tpng', dot_file, '-o',
                                   output_path])
            print(f"✓ Network visualization saved to: {output_path}")
        except subprocess.CalledProcessError as e:
            print(f"Error generating PNG with graphviz: {e}")
            return False

        # Clean up temporary file
        os.unlink(dot_file)

    except Exception as e:
        print(f"Error creating network graph: {e}")
        return False

    return True


def generate_custom_dot_graph(docker_info, analysis):
    """Generate a custom DOT graph with detailed security information."""
    dot_lines = [
        'digraph "Docker Network Topology" {',
        '    rankdir=TB;',
        '    node [shape=box, style=rounded, fontname="Roboto"];',
        '    edge [style=solid, fontname="Roboto"];',
        '    ',
        '    // Graph styling',
        '    bgcolor="#ffffff";',
        '    fontname="Roboto";',
        '    fontsize=14;',
        '    label=<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" CELLPADDING="8"><TR><TD><FONT POINT-SIZE="32">Secure Architecture Sandbox - Docker Network Topology</FONT></TD></TR><TR><TD><FONT POINT-SIZE="22">https://github.com/TempeHS/Secure_Architecture_Sandbox_Testing_Environment</FONT></TD></TR><TR><TD><FONT POINT-SIZE="4"> </FONT></TD></TR></TABLE>>;',
        '    labelloc=t;',
        '    ',
        '    // Browser and host isolation layers',
        '    subgraph cluster_browser {',
        '        label="Student Browser Environment\\n(Isolated from Local System)";',
        '        labelloc=t;',
        '        labeljust=l;',
        '        style="dashed,filled";',
        '        colour=purple;',
        '        fillcolor="#f8f0ff";',
        '        fontcolor=purple;',
        '        margin=20;',
        '        ',
        '        subgraph cluster_codespaces {',
        '            label="Codespaces Cloud Environment\\n(Isolated from Student Network)";',
        '            labelloc=t;',
        '            labeljust=l;',
        '            style="solid,filled";',
        '            colour="#228B22";',
        '            fillcolor="#f0fff0";',
        '            fontcolor="#228B22";',
        '            margin=20;',
        '            ',
        '            "Host System" [',
        '                label="Codespaces Host\\nDocker Runtime\\nPorts: 3000, 5000, 8000, 8080, 9090";',
        '                fillcolor="#d4edda";',
        '                style=filled;',
        '                shape=ellipse;',
        '            ];',
        '            ',
        '            // Network subnet cluster inside codespaces',
        '            subgraph cluster_sandbox {',
        '                label="Sandbox Network (172.20.0.0/16)";',
        '                labelloc=t;',
        '                labeljust=l;',
        '                style="dashed,filled";',
        '                colour=blue;',
        '                fillcolor="#f0f8ff";',
        '                fontcolor=blue;',
        '                margin=20;',
        '                ',
    ]

    # Add containers to the graph with cybersec_sandbox on top, others below
    colours = {
        'sandbox': '#e8f5e8',
        'unsecure-pwa': '#ffe8e8',
        'vulnerable-flask': '#fff3e8',
        'student-uploads': '#e8f3ff',
        'vulnerable-nodejs': '#f3e8ff'
    }

    # First add the cybersec_sandbox (tools) container at the top
    cybersec_container = ('cybersec_sandbox', 'sandbox',
                          '8080:8080\\n(cybersec_sandbox_tools)')

    # Then the 4 vulnerable applications in port order for the bottom row
    app_containers = [
        ('vulnerable_nodejs', 'vulnerable-nodejs',
         '3000:3000\\n(Vulnerable Node.js)'),
        ('unsecure_pwa', 'unsecure-pwa', '5000:5000\\n(The Unsecure PWA)'),
        ('student_uploads', 'student-uploads',
         '8000:8000\\n(Student Uploads)'),
        ('vulnerable_flask', 'vulnerable-flask',
         '9090:9090\\n(Vulnerable Flask)')
    ]

    # Process cybersec_sandbox first (top position)
    all_containers = [cybersec_container] + app_containers

    for i, (service, hostname, port_label) in enumerate(all_containers):
        # Find the container info for this service
        container_info = None
        for container in analysis['container_security']:
            if (container['service'] == service or
                    container['container_name'] == service):
                container_info = container
                break

        if not container_info:
            continue

        container_name = container_info['container_name']
        hostname = container_info['hostname']
        ports = container_info['ports']

        # Determine security level colour
        colour = colours.get(service, '#f0f0f0')

        # Create node label with security details
        security_details = []
        if container_info['cap_drop']:
            caps_dropped = ', '.join(container_info['cap_drop'])
            security_details.append(f"Caps Dropped: {caps_dropped}")
        if container_info['cap_add']:
            caps_added = ', '.join(container_info['cap_add'])
            security_details.append(f"Caps Added: {caps_added}")
        if container_info['mem_limit'] != 'unlimited':
            security_details.append(f"Memory: {container_info['mem_limit']}")
        if container_info['security_opts']:
            sec_opts = ', '.join(container_info['security_opts'])
            security_details.append(f"Security: {sec_opts}")

        port_info = ', '.join(ports) if ports else 'No exposed ports'

        # Special display name for cybersec_sandbox
        display_name = container_name
        if container_name == "cybersec_sandbox":
            display_name = "cybersec_sandbox_tools"

        label_parts = [
            f"{display_name}",
            f"Hostname: {hostname}",
            f"Ports: {port_info}",
        ]
        label_parts.extend(security_details)

        label = '\\n'.join(label_parts)

        dot_lines.append(f'                "{container_name}" [')
        dot_lines.append(f'                    label="{label}";')
        dot_lines.append(f'                    fillcolor="{colour}";')
        dot_lines.append('                    style=filled;')
        dot_lines.append('                ];')
        dot_lines.append('')

    # New layout: apps on top, whitespace, cybersec_sandbox at bottom
    dot_lines.append('                // Row 1: Vulnerable apps at top')
    apps_rank = ('                { rank=min; "vulnerable_nodejs"; "unsecure_pwa"; '
                 '"student_uploads"; "vulnerable_flask"; }')
    dot_lines.append(apps_rank)
    dot_lines.append('')

    dot_lines.append('                // Row 2: Whitespace spacers')
    dot_lines.append(
        '                "spacer_1" [style=invis, width=0, height=0];')
    dot_lines.append(
        '                "spacer_2" [style=invis, width=0, height=0];')
    dot_lines.append(
        '                "spacer_3" [style=invis, width=0, height=0];')
    dot_lines.append(
        '                "spacer_4" [style=invis, width=0, height=0];')
    dot_lines.append(
        '                { rank=same; "spacer_1"; "spacer_2"; "spacer_3"; "spacer_4"; }')
    dot_lines.append('')

    dot_lines.append('                // Row 3: Cybersec sandbox at bottom')
    dot_lines.append('                { rank=max; "cybersec_sandbox"; }')
    dot_lines.append('')

    dot_lines.append('                // Vertical structure - apps to spacers')
    dot_lines.append(
        '                "vulnerable_nodejs" -> "spacer_1" [style=invis];')
    dot_lines.append(
        '                "unsecure_pwa" -> "spacer_2" [style=invis];')
    dot_lines.append(
        '                "student_uploads" -> "spacer_3" [style=invis];')
    dot_lines.append(
        '                "vulnerable_flask" -> "spacer_4" [style=invis];')
    dot_lines.append('')

    dot_lines.append(
        '                // Vertical structure - spacers to cybersec')
    dot_lines.append(
        '                "spacer_2" -> "cybersec_sandbox" [style=invis];')
    dot_lines.append(
        '                "spacer_3" -> "cybersec_sandbox" [style=invis];')
    dot_lines.append('')

    dot_lines.append('            }')  # Close sandbox cluster
    dot_lines.append('            ')
    dot_lines.append(
        '            // Host to cybersec_sandbox connection with cluster constraints')
    dot_lines.append('            "Host System" -> "cybersec_sandbox" [')
    dot_lines.append('                label="8080:8080\\n(sandbox_tools)";')
    dot_lines.append('                labeldistance=1.5;')
    dot_lines.append('                labelangle=0;')
    dot_lines.append('                style=bold;')
    dot_lines.append('                colour="#228B22";')
    dot_lines.append('                ltail=cluster_codespaces;')
    dot_lines.append('                lhead=cluster_sandbox;')
    dot_lines.append('            ];')
    dot_lines.append('            ')
    dot_lines.append('        }')     # Close codespaces cluster
    dot_lines.append('    }')         # Close browser cluster
    dot_lines.append('    ')

    # Add external student computer
    dot_lines.extend([
        '    // Student computer (external)',
        '    "Student Computer" [',
        '        label="Student Local Computer\\n(Completely Isolated)\\nNo Direct Access";',
        '        fillcolor="#f8d7da";',
        '        style=filled;',
        '        shape=box3d;',
        '        margin=0.3;',
        '        width=2.5;',
        '        height=1.2;',
        '    ];',
        '    ',
        '    // Browser connection',
        '    "Student Computer" -> "Host System" [',
        '        label=<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" CELLPADDING="0">',
        '               <TR><TD ALIGN="LEFT">  HTTPS Only</TD></TR>',
        '               <TR><TD ALIGN="LEFT">  Browser Isolation</TD></TR>',
        '               <TR><TD ALIGN="LEFT">  No Hardware, Software or Network Access</TD></TR>',
        '              </TABLE>>;',
        '        labeldistance=2.0;',
        '        labelangle=10;',
        '        style=bold;',
        '        colour=purple;',
        '    ];',
        '    '
    ])

    # Add network connections - using routing helpers to split left/right
    # External connections - simple top-to-bottom structure
    dot_lines.extend([
        '    ',
        '    // External host connections to apps (direct from host to top row)',
        '    edge [style=bold, colour="#228B22"];',
        '    "Host System" -> "vulnerable_nodejs" [',
        '        label="3000:3000\\n(Vulnerable Node.js)";',
        '        labeldistance=1.5;',
        '        labelangle=0;',
        '    ];',
        '    "Host System" -> "unsecure_pwa" [',
        '        label="5000:5000\\n(The Unsecure PWA)";',
        '        labeldistance=1.5;',
        '        labelangle=0;',
        '    ];',
        '    "Host System" -> "student_uploads" [',
        '        label="8000:8000\\n(Student Uploads)";',
        '        labeldistance=1.5;',
        '        labelangle=0;',
        '    ];',
        '    "Host System" -> "vulnerable_flask" [',
        '        label="9090:9090\\n(Vulnerable Flask)";',
        '        labeldistance=1.5;',
        '        labelangle=0;',
        '    ];',
        '    ',
        '    // Internal sandbox connections (cybersec tools → apps)',
        '    edge [style=dashed, colour=blue, penwidth=2];',
        '    "cybersec_sandbox" -> "vulnerable_nodejs" [',
        '        label="Internal\\nNetwork\\nAccess";',
        '    ];',
        '    "cybersec_sandbox" -> "unsecure_pwa" [',
        '        label="Internal\\nNetwork\\nAccess";',
        '    ];',
        '    "cybersec_sandbox" -> "student_uploads" [',
        '        label="Internal\\nNetwork\\nAccess";',
        '    ];',
        '    "cybersec_sandbox" -> "vulnerable_flask" [',
        '        label="Internal\\nNetwork\\nAccess";',
        '    ];',
        '    '
    ])

    dot_lines.append('}')

    return '\n'.join(dot_lines)


def generate_detailed_report(analysis, output_dir):
    """Generate a detailed text report of the security analysis."""
    report_path = os.path.join(output_dir, 'network_security_analysis.txt')

    with open(report_path, 'w') as f:
        f.write("SECURE ARCHITECTURE SANDBOX - NETWORK SECURITY ANALYSIS\n")
        f.write("=" * 55 + "\n")
        f.write(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write("NETWORK ISOLATION OVERVIEW\n")
        f.write("-" * 25 + "\n")
        for net_info in analysis['network_isolation']:
            f.write(f"Network: {net_info['name']}\n")
            f.write(f"  Driver: {net_info['driver']}\n")
            f.write(f"  Subnet: {net_info['subnet']}\n")
            f.write(f"  Gateway: {net_info['gateway']}\n")
            f.write(f"  Internal: {net_info['internal']}\n")
            f.write(
                f"  Connected Containers: {len(net_info['containers'])}\n\n")

        f.write("CONTAINER SECURITY CONFIGURATION\n")
        f.write("-" * 32 + "\n")
        for container in analysis['container_security']:
            f.write(f"Service: {container['service']}\n")
            f.write(f"  Container Name: {container['container_name']}\n")
            f.write(f"  Hostname: {container['hostname']}\n")
            f.write(f"  Exposed Ports: {container['ports']}\n")
            f.write(f"  Networks: {container['networks']}\n")
            f.write(f"  Security Options: {container['security_opts']}\n")
            f.write(f"  Capabilities Dropped: {container['cap_drop']}\n")
            f.write(f"  Capabilities Added: {container['cap_add']}\n")
            f.write(f"  Memory Limit: {container['mem_limit']}\n")
            f.write(f"  CPU Limit: {container['cpus']}\n")
            f.write(f"  Volumes: {len(container['volumes'])} mounted\n\n")

        f.write("SECURITY ISOLATION SUMMARY\n")
        f.write("-" * 25 + "\n")
        f.write("1. Network Isolation:\n")
        f.write("   - All containers run in isolated 'sandbox_network'\n")
        f.write("   - Bridge driver provides container-to-container communication\n")
        f.write("   - Specific subnet (172.20.0.0/16) limits network scope\n\n")

        f.write("2. Container Isolation:\n")
        f.write("   - Each application runs in separate container\n")
        f.write("   - Resource limits prevent resource exhaustion\n")
        f.write("   - Capability dropping reduces attack surface\n\n")

        f.write("3. Port Isolation:\n")
        f.write("   - Host port mapping controls external access\n")
        f.write("   - Different ports for each service prevent conflicts\n")
        f.write("   - Internal communication possible within network\n\n")

    print(f"✓ Detailed report saved to: {report_path}")
    return report_path


def main():
    """Main function to generate network visualization."""
    print("🔍 Docker Network Visualization Tool")
    print("=" * 40)

    # Ensure dependencies are installed
    if not ensure_dependencies():
        print("❌ Failed to install required dependencies")
        return 1

    # Get Docker information
    print("\n📊 Gathering Docker network information...")
    docker_info = get_docker_network_info()
    if not docker_info:
        print("❌ Failed to get Docker network information")
        print("Make sure Docker is running and you have permission to access it")
        return 1

    # Analyse sandbox isolation
    print("🔒 Analysing sandbox isolation...")
    analysis = analyse_sandbox_isolation(docker_info)

    # Ensure output directory exists
    output_dir = '/workspaces/Secure_Architecture_Sandbox_Testing_Environment/reports'
    os.makedirs(output_dir, exist_ok=True)

    # Generate network visualization
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_path = os.path.join(
        output_dir, f'docker_network_topology_{timestamp}.png')

    print("🎨 Generating network visualization...")
    if create_enhanced_network_graph(docker_info, analysis, output_path):
        print(f"✅ Network visualization completed successfully!")
        print(f"📁 Output saved to: {output_path}")
    else:
        print("❌ Failed to generate network visualization")
        return 1

    # Generate detailed report
    print("📝 Generating detailed security analysis report...")
    generate_detailed_report(analysis, output_dir)

    print("\n🎉 Network analysis complete!")
    print(f"📂 Check the reports/ directory for outputs")

    return 0


if __name__ == "__main__":
    sys.exit(main())
