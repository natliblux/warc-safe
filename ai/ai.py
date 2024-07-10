from warcio.archiveiterator import ArchiveIterator
from nsfw_detector.model import Model
import os
import tempfile
import re
import subprocess
import stat
from prettytable import PrettyTable
    
net = Model()

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

re_file = re.compile(r'^([^\ ]+) image')
allowed_types = 'tif, tiff, TIF, TIFF, png, PNG, jpg, jpeg, JPG, JPEG, svg, SVG, webp, WEBP'

def isallowed(f):
    result = subprocess.run(['file', '-b', f],stdout=subprocess.PIPE)
    m = re_file.match(result.stdout.decode('utf-8'))
    if m:
        return m.group(1)
    
def handleRecordNsfw(record, net):
    tempfile.tempdir = "/tmp/"
    
    memento = tempfile.NamedTemporaryFile(delete=False)
    mementofname = os.path.join("/tmp/", memento.name)
        
    # Prepare the metadata
    res = {}
    res['mime'] = record.http_headers.get_header('Content-Type')    
    
    try:
        memento.write(record.content_stream().read())
     
        os.chmod(mementofname, stat.S_IREAD | stat.S_IWRITE | stat.S_IROTH | stat.S_IWOTH)
        
        # Should this record be checked?
        res['content_type'] = isallowed(mementofname)
        
        if res['content_type'] in allowed_types:
            output = net.predict(mementofname)
             
            for i in output:
                res['nsfw_res'] = output[i]['Label']
                res['nsfw_score'] = output[i]['Score']
            
            if not 'nsfw_res' in res:
                res['err'] = 'cannot load image'
                
    except Exception as inst:
        res['err'] = str(inst)
    finally:
        os.remove(mementofname)

    return res


def runNsfwClassifier(input_file):
    results = {}
    
    with open(input_file, 'rb') as stream:
        for record in ArchiveIterator(stream):
            if record.rec_type == 'response' and record.http_headers:
                mime = record.http_headers.get_header('Content-Type')
                if mime and mime.startswith('image/'):
                    # Launch the classifier and build the result entity
                    result = handleRecordNsfw(record, net)
                    result['filename'] = os.path.basename(record.rec_headers.get_header('WARC-Target-URI'))
                    results[record.rec_headers.get_header('WARC-Record-ID')] = result
                    
    return results
     
#
# Pretty prints the NSFW classifier results. For each file, it shows the corresponding
# NSFW probability, which is a float value between 0 (not NSFW) and 1 (certainly NSFW).
# Everything above 0.7 s printed in RED, between 0.7 and 0.3 as ORANGE, and below 0.3 as GREEN.
#
# Note: everything that has no classifier score is SKIPPED.
#
def printClassifierResults(results):
    table = PrettyTable(["File", "NSFW probability"])
    table.align="l"
    for c in results.keys():
        metadata = results[c]
        filename = metadata['filename']
        
        # Get the classifier score for this element. If there is no classifier score, we skip it.
        if 'nsfw_score' in metadata:
            prob = metadata['nsfw_score']
        else:
            continue
        
        # Pretty print the results
        output = ""
        if prob > 0.7:
            output = bcolors.FAIL + str(prob) + bcolors.ENDC
        elif prob > 0.3:
            output = bcolors.WARNING + str(prob) + bcolors.ENDC
        else:
            output = bcolors.OKGREEN + str(prob) + bcolors.ENDC
            
        table.add_row([sanitizeString(filename), output])
        
    print(table)

    
def sanitizeString(input):
    if len(input) > 70:
        input = input[:70] + "..."
    
    return input
