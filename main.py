import argparse
import time
from ctypes import c_bool
from multiprocessing import Value, Process

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
parser.add_argument('--max_flows', type=int, help='Max flow to send', default=10000000)
parser.add_argument('--malicious_percentage', type=int, help='Percentage of malicious flows, only %10=0', default=50)
parser.add_argument('--malicious_types', type=lambda s: s.split(','), help='Comma-separated list of malicious flow '
                                                                           'types which should be used',
                    default=["dns", "ip"])
parser.add_argument('--minimal_log', action='store_true', help='Log minimal info (for multiple benchmarking)')
parser.add_argument('--flows_per_second', type=int, help='Flows per second, default max', default=0)

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
    'benchmark': args.benchmark,
    'max_flows': args.max_flows,
    'malicious_percentage': args.malicious_percentage,
    'malicious_types': args.malicious_types,
    'minimal_log': args.minimal_log,
    'flows_per_second': args.flows_per_second
}

# Print the configuration
if not config['minimal_log']:
    print("Configuration:")
    print(f"  MalFix Instances: {config['malfix_instances']}")
    print(f"  MalFix Hostname: {config['malfix_host']}")
    print(
        f"  MalFix Port(s): {config['malfix_base_port']} ... {config['malfix_base_port'] + config['malfix_instances'] - 1}")
    print(f"  MalFix Protocol: {config['malfix_protocol']}")
    print(f"  Benchmarking: {config['benchmark']}")
    print(f"Listening on {config['listen_host']}:{config['listen_port']}/{config['listen_protocol']} for IPFIX!") if not \
        config['benchmark'] else print("Benchmarking!")
    print(
        f"  Bench params: Flows: {config['max_flows']}, "
        f"malicious percentage: {config['malicious_percentage']}, "
        f"types: {config['malicious_types']}, "
        f"f/s: {config['flows_per_second'] if config['flows_per_second'] > 0 else 'max'}")

# Initialize FixDemux with the appropriate arguments
demux = FixDemux(import_ie, export_ie, config)
demux.setup()


# Function to run the benchmark repeatedly
def run_benchmark_repeatedly(flows_per_second, stop_event):
    interval = 1.0 / flows_per_second
    next_run = time.perf_counter()

    while not stop_event.value:
        demux.run_benchmark()
        next_run += interval
        sleep_time = next_run - time.perf_counter()
        if sleep_time > 0:
            time.sleep(sleep_time)
        else:
            next_run = time.perf_counter()  # Reset next_run if we're behind schedule


# Run the appropriate method based on the configuration
if config['benchmark'] and config['flows_per_second'] > 0:
    stop_event = Value(c_bool, False)
    process = Process(target=run_benchmark_repeatedly, args=(config['flows_per_second'], stop_event))
    process.start()
    try:
        while True:
            time.sleep(1)  # Keep the main thread alive
    except KeyboardInterrupt:
        stop_event.value = True
        process.join()
        print("Benchmarking stopped.")
else:
    demux.run_benchmark() if config['benchmark'] else demux.run()
