from flask import Flask, request, jsonify
import argparse
import sys

sys.path.append('ai')
from ai import runNsfwClassifier, printClassifierResults

sys.path.append('antivirus')
from antivirus import runAntivirus, printAvResults

sys.path.append('util')
from util import suppressStdout

sys.path.append('server')
from server import app

# The version of this app
app_version = "1.2 (10.07.2024)"

if __name__ == '__main__':
    
    # Parse CLI args
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--server", type=int, help="Start the server on the given port.")
    parser.add_argument("-tn", "--test-nsfw", type=str, help="Test a WARC file for NSFW content. The WARC can be compressed or uncompressed.")
    parser.add_argument("-ta", "--test-av", type=str, help="Test a WARC file for viruses. The WARC can be compressed or uncompressed.")
    parser.add_argument("-v", "--version", action='version', version=f"Version: {app_version}")

    args = parser.parse_args()
    results = {}
    
    if args.server:
        server_port = args.server
        print(f"Starting the server on port {server_port}")
        app.run(debug=True, port=server_port)
    elif args.test_nsfw:
        test_file = args.test_nsfw
        print(f"Starting NSFW test on file: {test_file}")
        with suppressStdout():
            results = runNsfwClassifier(test_file)
        printClassifierResults(results)
    elif args.test_av:
        test_file = args.test_av
        print(f"Starting antivirus test on file: {test_file}")
        with suppressStdout():
            results = runAntivirus(test_file)
        printAvResults(results)
    else:
        parser.print_help()
        exit()
