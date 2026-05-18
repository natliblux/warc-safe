from flask import Flask, request, jsonify
import argparse
import sys
import logging
import werkzeug

sys.path.append('ai')
from ai import runNsfwClassifier, printClassifierResults

sys.path.append('antivirus')
from antivirus import runAntivirus, printAvResults

sys.path.append('util')
from util import suppressStdout

sys.path.append('server')
from server import app

# The version of this app
app_version = "1.3 (18.05.2026)"

if __name__ == '__main__':
    
    # Parse CLI args
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--server", type=int, help="Start the server on the given port.")
    parser.add_argument("-tn", "--test-nsfw", type=str, help="Test a WARC file for NSFW content. The WARC can be compressed or uncompressed.")
    parser.add_argument("-ta", "--test-av", type=str, help="Test a WARC file for viruses. The WARC can be compressed or uncompressed.")
    parser.add_argument("-o", "--offset", type=int, help="The offest of the record in the WARC file that should be tested.")
    parser.add_argument("-v", "--version", action='version', version=f"Version: {app_version}")

    # Set up some logging
    logging.getLogger('werkzeug').setLevel(logging.ERROR)

    args = parser.parse_args()
    results = {}
    
    if args.server:
        server_port = args.server
        print(f"Starting the server on port {server_port}")
        app.run(debug=False, port=server_port, threaded=True)
    elif args.test_nsfw:
        if args.offset is not None:
            print(f"Starting NSFW test on file: {args.test_nsfw} at offset {args.offset}")
            with suppressStdout():
                results = runNsfwClassifier(args.test_nsfw, args.offset)
        else:
            print(f"Starting NSFW test on file: {args.test_nsfw}")
            with suppressStdout():
                results = runNsfwClassifier(args.test_nsfw)
        printClassifierResults(results)
    elif args.test_av:
        if args.offset is not None:
            print(f"Starting antivirus test on file: {args.test_av} at offset {args.offset}")
            with suppressStdout():
                results = runAntivirus(args.test_av, args.offset)
        else:
            print(f"Starting antivirus test on file: {args.test_av}")
            with suppressStdout():
                results = runAntivirus(args.test_av)
        printAvResults(results)
    else:
        parser.print_help()
        exit()
