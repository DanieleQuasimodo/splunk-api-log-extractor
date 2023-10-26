import os
import sys
import getpass
import argparse
import logging
import json
from urllib.error import HTTPError
import urllib.parse
import urllib.request



def raise_for_status(response): # NOTE: Copied and modified from Requests
    
    http_error_msg = ''
    if isinstance(response.reason, bytes):
        # We attempt to decode utf-8 first because some servers
        # choose to localize their reason strings. If the string
        # isn't utf-8, we fall back to iso-8859-1 for all other
        # encodings. (See PR #3538)
        try:
            reason = response.reason.decode('utf-8')
        except UnicodeDecodeError:
            reason = response.reason.decode('iso-8859-1')
    else:
        reason = response.reason

    if 400 <= response.status < 500:
        http_error_msg = (
            f'{response.status} Client Error: {reason} for url: {response.url}'
        )

    elif 500 <= response.status < 600:
        http_error_msg = (
            f'{response.status} Server Error: {reason} for url: {response.url}'
        )

    if http_error_msg:
        raise HTTPError(
            msg=http_error_msg,
            url=response.url,
            code=response.status,
            hdrs=response.headers,
            fp=response.fp
        )


def dict_from_cookiejar(cj): # NOTE: Copied from Requests
    cookie_dict = {}

    for cookie in cj:
        cookie_dict[cookie.name] = cookie.value

    return cookie_dict


def splunk_login(splunk_base_url, username, password):
    
    login_url = f'{splunk_base_url}/en-US/account/login'
    
    cookie_processor = urllib.request.HTTPCookieProcessor()
    opener = urllib.request.build_opener(cookie_processor)
    
    first_request = urllib.request.Request(
        login_url,
        method = 'HEAD'
    )
    
    try:
        with opener.open(first_request) as response:
            raise_for_status(response)
            cval_cookie_value = dict_from_cookiejar(cookie_processor.cookiejar)['cval']
            
    except Exception as e:
        logging.debug(e, exc_info = True)
        logging.critical('First request failed!')
        return None
    
    login_data = {
        'cval': cval_cookie_value,
        'username': username,
        'password': password
    }
    
    login_request = urllib.request.Request(
        login_url,
        data = urllib.parse.urlencode(login_data).encode('utf-8'),
        headers = { 'Content-Type': 'application/x-www-form-urlencoded' },
        method = 'POST'
    )
    
    try:
        with opener.open(login_request) as response:
            raise_for_status(response)
        return opener

    except Exception as e:
        logging.debug(e, exc_info = True)
        logging.critical('Login request failed!')
        return None


def splunk_search(opener, splunk_base_url, search_query, output_mode='raw'):
    
    encoded_search = urllib.parse.quote_plus(search_query)

    search_url = f'{splunk_base_url}/en-US/splunkd/__raw/services/search/jobs/export?output_mode={output_mode}&search={encoded_search}'
    
    search_request = urllib.request.Request(search_url)
    
    try:
        with opener.open(search_request) as response:
            raise_for_status(response)
            yield from response

    except Exception as e:
        logging.debug(e, exc_info = True)
        logging.error('Could not retrieve logs!')
        yield None


## MAIN ##

def main():
    parser = argparse.ArgumentParser(description = 'Splunk API log extractor')
    parser.add_argument(
        'search_query',
        nargs = '+',
        help = 'splunk search query (eg. "search earliest=-4h latest=-2h")'
    )
    choices=['rock', 'paper', 'scissors']
    parser.add_argument(
        '-f',
        '--format',
        choices=['atom', 'csv', 'json', 'json_cols', 'json_rows', 'raw', 'xml'],
        default = 'raw',
        help = 'splunk log format'
    )
    parser.add_argument(
        '-u',
        '--username',
        default = '',
        type = lambda s: s or getpass.getuser(),
        help = 'splunk username'
    )
    parser.add_argument(
        '-p',
        '--password',
        default = '',
        type = lambda s: s or getpass.getpass(),
        help = 'splunk password'
    )
    parser.add_argument(
        '-o',
        '--output-file',
        type = argparse.FileType('wb'),
        default = sys.stdout.buffer,
        help = 'output file'
    )
    parser.add_argument(
        '--splunk-base-url',
        default = '',
        type = lambda s: s or os.environ.get('SPLUNK_BASE_URL'),
        help = 'splunk server base url (if not provided defaults to SPLUNK_BASE_URL environment variable)'
    )
    args = parser.parse_args()
        
    # Login to Splunk API
    opener = splunk_login(args.splunk_base_url, args.username, args.password)
    if not opener:
        sys.exit(1)

    # Search the logs
    search_query = ' '.join(args.search_query)
    search_response = splunk_search(opener, args.splunk_base_url, search_query, output_mode = args.format)

    for chunk in search_response:
        if chunk:
            args.output_file.write(chunk)
            args.output_file.flush()


if __name__ == '__main__':
    main()