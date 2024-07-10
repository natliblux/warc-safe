from warcio.archiveiterator import ArchiveIterator
from nsfw_detector.model import Model
from codecs import decode
import json
import os
import tempfile
import sys
import stat
import re
import clamd
from contextlib import contextmanager

# Initialize the NSFW model
net = Model()
    
# Initialize the antivirus client
clamd_client = clamd.ClamdUnixSocket()
    
sys.path.append('ai')
from ai import handleRecordNsfw

sys.path.append('antivirus')
from antivirus import handleRecordAntivirus
#
# Runs every test on the given WARC file:
#   -- antivirus
#   -- nsfw classifier
#
def runEverything(input_file):
    results = {}
    tempfile.tempdir = "/tmp/"
    
    with open(input_file, 'rb') as stream:
        for record in ArchiveIterator(stream):
            if record.rec_type == 'response' and record.http_headers:
                
                # Construct the result entity
                result = {}
                result['mime'] = record.http_headers.get_header('Content-Type') 
                
                # NSFW content detection
                mime = record.http_headers.get_header('Content-Type')
                if mime and len(mime) > 6 and mime[0:6] == 'image/':
                    nsfw_result = handleRecordNsfw(record, net)
                    if 'nsfw_res' in nsfw_result:
                        result['nsfw_res'] = nsfw_result['nsfw_res']
                        result['nsfw_score'] = nsfw_result['nsfw_score']
                    
                # Virus detection
                av_result = handleRecordAntivirus(record, clamd_client)
                
                # If there are no results, we assume that this element is OK
                try:               
                    result['av_res'] = av_result['av_res']
                    result['av_details'] = av_result['av_details']
                except KeyError:
                    result['av_res'] = 'OK'
                    result['av_details'] = 'Null'
                    
                # Build the results
                result['filename'] = os.path.basename(record.rec_headers.get_header('WARC-Target-URI'))
                results[record.rec_headers.get_header('WARC-Record-ID')] = result
                    
    return results


@contextmanager
def suppressStdout():
    with open(os.devnull, 'w') as devnull:
        old_stderr = sys.stderr
        sys.stderr = devnull
        try:
            yield
        finally:
            sys.stderr = old_stderr