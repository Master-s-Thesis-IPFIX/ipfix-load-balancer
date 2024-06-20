import argparse

from FixDemux import FixDemux
from helper import Config
from information_elements import export_ie, import_ie

parser = argparse.ArgumentParser(description="Parse command line arguments for the application")

# Add arguments with flags
parser.add_argument('--malfix_instances', type=int, help='Number of instances', default=1)
parser.add_argument('--malfix_hostname', type=str, help='The hostname as a string', default="127.0.0.1")
parser.add_argument('--malfix_base_port', type=int, help='The base port for MalFix', default="19000")
parser.add_argument('--malfix_protocol', type=str, help='The protocol to use', default="tcp")
parser.add_argument('--listen_host', type=str, help='The host to listen on', default="0.0.0.0")
parser.add_argument('--listen_port', type=int, help='The port to listen on', default="1337")
parser.add_argument('--listen_protocol', type=str, help='The protocol to listen on', default="tcp")
parser.add_argument('--benchmark', action='store_true', help='Flag to enable benchmarking')

# Parse the arguments
args = parser.parse_args()

# Create the config dictionary
config: Config = {
    'malfix_instances': args.malfix_instances,
    'malfix_host': args.malfix_hostname,
    'malfix_base_port': args.malfix_base_port,
    'malfix_protocol': args.malfix_protocol,
    'listen_host': args.listen_host,
    'listen_port': args.listen_port,
    'listen_protocol': args.listen_protocol,
    'benchmark': args.benchmark
}

# Print the configuration
print("Configuration:")
print(f"  MalFix Instances: {config['malfix_instances']}")
print(f"  MalFix Hostname: {config['malfix_host']}")
print(
    f"  MalFix Port(s): {config['malfix_base_port']} ... {config['malfix_base_port'] + config['malfix_instances'] - 1}")
print(f"  MalFix Protocol: {config['malfix_protocol']}")
print(f"  Benchmarking: {config['benchmark']}")
print(f"Listening on {config['listen_host']}:{config['listen_port']}/{config['listen_protocol']} for IPFIX!") if not \
    config['benchmark'] else print("Benchmarking!")

# Initialize FixDemux with the appropriate arguments
demux = FixDemux(import_ie, export_ie, config)
demux.setup()
demux.run_benchmark() if config['benchmark'] else demux.run()
