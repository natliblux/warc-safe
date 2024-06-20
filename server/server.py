from flask import Flask, request, jsonify

import sys
import traceback

sys.path.append('ai')
from ai import runNsfwClassifier

sys.path.append('antivirus')
from antivirus import runAntivirus

sys.path.append('util')
from util import runEverything, suppressStdout


app = Flask(__name__)

#
# Test a WARC for NSFW content. Parameter:
#
#   - file_path: The absolute path to the WARC you want to analyze. 
#                It can be compressed or uncompressed.
#
@app.route('/test_nsfw', methods=['POST'])
def test_nsfw():
    try:
        data = request.json
        if 'file_path' in data:
            # Prepare the params
            file_path = data['file_path']
            results = {}
            
            # Now we run the workflow
            with suppressStdout():
                results = runNsfwClassifier(file_path)
            
            # Return the JSON results
            return jsonify({'results': results})
        else:
            return jsonify({'error': 'Invalid JSON input. Missing "file_path" field.'}), 400
    except Exception as e:
        print("Error while checking file '", file_path, "': ", str(e))
        traceback.print_exception(type(e), e, e.__traceback__)
        return jsonify({'error': str(e)}), 500

# Test a WARC for viruses. Parameter:
#
#   - file_path: The absolute path to the WARC you want to analyze. 
#                It can be compressed or uncompressed.
#
@app.route('/test_antivirus', methods=['POST'])
def test_antivirus():
    try:
        data = request.json
        if 'file_path' in data:
            # Prepare the params
            file_path = data['file_path']
            results = {}
            
            # Now we run the workflow
            with suppressStdout():
                results = runAntivirus(file_path)
            
            # Return the JSON results
            return jsonify({'results': results})
        else:
            return jsonify({'error': 'Invalid JSON input. Missing "file_path" field.'}), 400
    except Exception as e:
        print("Error while checking file '", file_path, "': ", str(e))
        traceback.print_exception(type(e), e, e.__traceback__)
        return jsonify({'error': str(e)}), 500


# Test a WARC for viruses and NSFW content at the same time. Parameter:
#
#   - file_path: The absolute path to the WARC you want to analyze. 
#                It can be compressed or uncompressed.
#
@app.route('/test_all', methods=['POST'])
def test_all():
    try:
        data = request.json
        if 'file_path' in data:
            # Prepare the params
            file_path = data['file_path']
            results = {}
            
            # Now we run the workflow
            with suppressStdout():
                results = runEverything(file_path)
            
            # Return the JSON results
            return jsonify({'results': results})
        else:
            return jsonify({'error': 'Invalid JSON input. Missing "file_path" field.'}), 400
    except Exception as e:
        print("Error while checking file '", file_path, "': ", str(e))
        traceback.print_exception(type(e), e, e.__traceback__)
        return jsonify({'error': str(e)}), 500

