from warcio.archiveiterator import ArchiveIterator
import clamd
import os
import tempfile
import stat
from prettytable import PrettyTable

# Path where to store the temporary records while scanning them
tempfile.tempdir = "/tmp/"
    
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
def handleRecordAntivirus(record):
    # Initialize the antivirus client
    clamd_client = clamd.ClamdUnixSocket()
    
    # Set up the temp file
    memento = tempfile.NamedTemporaryFile(delete=False)
    mementofname = os.path.join("/tmp/", memento.name)
    res = {}
    res['mime'] = record.http_headers.get_header('Content-Type')
        
    try:
        # Write the record to disk so that it can be scanned
        memento.write(record.content_stream().read())
        memento.close()
        
        # Make sure it is readable by the AV
        os.chmod(mementofname, stat.S_IREAD | stat.S_IWRITE | stat.S_IROTH | stat.S_IWOTH)
        
        # The antivirus scan
        av = clamd_client.scan(mementofname)
        for i in av:
            res['av_res'] = av[i][0]
            res['av_details'] = av[i][1]
            
    except Exception as inst:
        res['err'] = str(inst)
        res['av_res'] = 'error'
        res['av_details'] = str(inst)
    finally:
        os.remove(mementofname)
                    
    return res

def runAntivirus(input_file):
    results = {}
    
    with open(input_file, 'rb') as stream:
        for record in ArchiveIterator(stream):
            if record.rec_type == 'response' and record.http_headers:
                # Run the antivirus and build the result entity
                result = handleRecordAntivirus(record)
                result['filename'] = os.path.basename(record.rec_headers.get_header('WARC-Target-URI'))
                results[record.rec_headers.get_header('WARC-Record-ID')] = result
                    
    return results


def printAvResults(results):
    table = PrettyTable(["File", "Virus test results"])
    table.align="l"
    
    for c in results.keys():
        
        # The AV results metadata
        metadata = results[c]
        filename = metadata['filename']
        
        # Some fancy output colouring
        output_color = bcolors.WARNING
        output_text = 'Unknown'
        
        # First, check for errors
        if 'err' in metadata:
            output_color = bcolors.FAIL
            output_text = metadata['err']
        elif 'av_res' in metadata:
            output_text = metadata['av_res']
            if output_text == "OK":
                output_color = bcolors.OKGREEN
            else:
                reason = metadata['av_details']
                output_text = f"{output_text}: {reason}"
                output_color = bcolors.FAIL
        else:
            output_color = bcolors.WARNING
            output_text = metadata['av_details']
        
        # Pretty print the results
        output = output_color + str(output_text) + bcolors.ENDC
             
        table.add_row([sanitizeString(filename), output])
        
    print(table)
    
    
def sanitizeString(input):
    if len(input) > 70:
        input = input[:70] + "..."
    
    return input