# Introduction

This is a Python program that scans WARC (web archive) files for NSFW (not-safe-for-work) content:

  - It detects violence/nudity using an AI model,
  - It detects viruses using the Linux `clamd` antivirus daemon.
  
You can either run it in test mode (check an individual WARC file) or in server mode (for easy integration into existing workflows).

The program accepts both compressed and uncompressed WARC files.


# Installation

Please use Python 3.9+. You can install the requirements as usual:

    pip install -r requirements.txt
    
If you want to use the antivirus feature, you will need to install the `clamd` antivirus daemon. On Ubuntu, you can do so like this:

    apt-get install clamav clamav-daemon -y
    
The first setup of `clamd` requires you to stop, update and start the service:

    systemctl stop clamav-freshclam
    freshclam
    systemctl start clamav-freshclam


# Usage

The tool scan be used in two ways:

  - test mode: scan a single warc on the command-line
  - server mode: use the REST API to scan WARC files programmatically
  
Note that the first time, the application will automatically download the classifier model to the current user's home folder. This might take a few seconds (or minutes) depending on your connection. You can check the progress in stdout.

## Test mode
    
You can start the application in test mode from the command-line as follows:

    python app.py --test-av </path/to/warc>
    python app.py --test-nsfw </path/to/warc>
    
The first example above runs the antivirus scan and the second the NSFW classifier.

## Server mode

You can start the application as a server like so:

    python app.py --server <port>

The application in server mode exposes the following endpoints:

  - `test_nsfw`: tests only for NSFW material,
  - `test_antivirus`: tests only for viruses,
  - `test_all`: tests for both of the above.

All these endpoints are POST and take a single argument, `file_path`, which is the absolute path to the WARC that you want to analyze (it can be compressed or uncompressed).

Here is an example request with `curl`:

    curl -X POST -H "Content-Type: application/json" -d '{"file_path": "/my/path/my.warc.gz"}' localhost:8123/test_all

## Return values

All endpoints return JSON. The root element is `results`, which is a list containing the WARC records together with their filter results. Each entry in the list is identified by its `WARC-Record-ID`. Here is an example:

````
{
  "results": {
    "<urn:uuid:ec2aa5f2-391e-530a-a9ed-b44f944fdcb9>": {
      "av_details": null,
      "av_res": "OK",
      "filename": "picture.jpg",
      "mime": "image/jpeg",
      "nsfw_res": "SFW",
      "nsfw_score": 0.35693745957662754
    },
    ...
    }
}
````

The fields available for each record are the following:
  - File name: `filename`,
  - Mime type: `mime`,
  - Antivirus: `av_details` and `av_res`,
  - NSFW: `nsfw_res` and `nsfw_score`,
  - Errors: `err`.

## NSFW scoring

The `nsfw_score` is a floating-point value between 0 (not NSFW at all) and 1 (certainly NSFW). On the other hand, the `nsfw_res` field returns either `NSFW` or `SFW` depending on what the AI has detected.


## Updating your antivirus database

From time to time it might make sense to update your `clamav` signature database. You can do so by running

    freshclam
    
You might also want to restart the service with

    systemctl restart clamav-freshclam
