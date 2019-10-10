#!/bin/python3
# parse-nmap.py
import re
import sys
import argparse
import os.path as osp


def terminate(*args, exit_code=1, **kwargs):
    print()
    print(*args, **kwargs)
    sys.exit(exit_code)


def printnow(*args, end='', flush=True, **kwargs):
    print(*args, end=end, flush=flush, **kwargs)


def make_argparser():
    parser = argparse.ArgumentParser(
        description="Split nmap output into individual files for each host"
    )
    parser.add_argument(
        "input_file",
        help="name of .nmap file to parse"
    )
    parser.add_argument(
        "-o", "--output-path",
        help="path of directory for output, default is '.'"
    )
    parser.add_argument(
        "-p", "--ports-open",
        help="only output hosts with open ports",
        action="store_true"
    )
    parser.add_argument(
        "-e", "--extension",
        help="extension of output files, default is .txt",
        action="store"
    )
    return parser


def get_hosts(input_path):
    with open(input_path) as input_file:
        try:
            lines = input_file.readlines()
        except Exception as ex:
            terminate("Could not open", input_path, "for input:\n\t", ex)

    # Remove comment lines, "# Nmap x.xx scan initiated ..." etc.
    data = ''.join([line for line in lines if not line.startswith("#")])

    # Split up by host, remove blank chunks
    matcher = re.compile(r"(Nmap scan report for (?:\d{1,3}[.]?){4})")
    chunks = [chunk for chunk in matcher.split(data) if chunk]

    # Combine host header with host body
    hosts = [chunks[i] + chunks[i+1] for i in range(0, len(chunks), 2)]
    return hosts


def filter_hosts(hosts):
    # If -p or --ports-open specified, skip hosts with no open ports
    matcher = re.compile(r"All \d+ scanned ports on (\d{1,3}[.]?){4} are closed")
    hosts = [host for host in hosts if not matcher.search(host)]
    return hosts


def save_host(host, ip, filepath):
    # Save nmap for one host to a file
    print("Saving results for", ip, "to", filepath)
    try:
        with open(filepath, "w") as file:
            file.write(host)
            file.write("\n")
    except Exception as ex:
        terminate("Error when saving host", ip, "to file", filepath, "\n\t", ex)


def main():
    # Set up the command-line options 
    parser = make_argparser()
    args = parser.parse_args()

    output_path = args.output_path if args.output_path else "."
    extension = args.extension if args.extension else ".txt"

    # Break nmap file into chunks representing individual hosts
    hosts = get_hosts(args.input_file)
    total_hosts = len(hosts)

    # If -p or --ports-open specified, skip hosts with no open ports
    if args.ports_open:
        hosts = filter_hosts(hosts)

    # Save hosts to individual files
    matcher = re.compile(r"Nmap scan report for ((\d{1,3}[.]?){4})")
    for host in hosts:
        ip = matcher.search(host).group(1)
        filepath = osp.join(output_path, ip) + extension
        save_host(host, ip, filepath)
    print('\n', len(hosts), " hosts written out of ", total_hosts, sep='')
    print("OK. Bye.")


if __name__ == "__main__":
    main()
