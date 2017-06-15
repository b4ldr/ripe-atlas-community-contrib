#!/usr/bin/env python

import logging
from pyasn import pyasn
from cymruwhois import Client
from prettytable import PrettyTable
from argparse import ArgumentParser
from collections import defaultdict
from ripe.atlas.sagan import Result, TracerouteResult
from ripe.atlas.cousteau import AtlasLatestRequest

def get_args():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('-v', '--verbose', action='count' )
    parser.add_argument('--pyasn-file')
    parser.add_argument('msm_id')
    return parser.parse_args()

def set_log_level(args_level):
    log_level = logging.ERROR
    lib_log_level = logging.ERROR
    if args_level == 1:
        log_level = logging.WARN
    elif args_level == 2:
        log_level = logging.INFO
        lib_log_level = logging.WARN
    elif args_level == 3:
        log_level = logging.DEBUG
    elif args_level > 3:
        lib_log_level = logging.DEBUG
    logging.basicConfig(level=log_level)
    logging.getLogger('requests').setLevel(lib_log_level)
    logging.getLogger('urllib3').setLevel(lib_log_level)

def report(headings, entries, sortby=None, reversesort=False):
    if len(entries) == 0:
        return '\nNo Data'
    table = PrettyTable(headings)
    for heading in headings:
        table.align[heading] = 'l'
    for entry in entries:
        table.add_row(entry)
    if sortby:
        return table.get_string(sortby=sortby, reversesort=reversesort)
    else:
        return table.get_string()

def reachability_report(paths):
    headings = ['ANS', 'unique paths', 'Min', 'Max']
    sortby   = 'Min'
    entries  = []
    entries = [[asn, len(paths), min(map(len, paths)), max(map(len, paths))] 
            for asn, paths in paths.items()]
    return report(headings, entries, sortby)

def remove_prepends(path):
    #http://stackoverflow.com/questions/480214/how-do-you-remove-duplicates-from-a-list-in-python-whilst-preserving-order
    seen     = set()
    seen_add = seen.add
    return tuple([x for x in path if not(x in seen or seen_add(x))])

def get_paths(asn_paths):
    '''sort through an array of paths and creat a dictionary of bgp paths.
    the key equals the starting asn and the value is a set of paths seen for
    that asn'''

    _asn_paths = defaultdict(set)
    for asn_path in asn_paths:
        full_path = remove_prepends(asn_path)
        logging.info('processing path: {}'.format(full_path))
        for asn in full_path:
            if asn == full_path[-1]:
                break
            path = full_path[full_path.index(asn):]
            logging.debug('adding new ASN({}) with path: {}'.format(asn, path)) 
            _asn_paths[asn].add(path)
    for asn, path in _asn_paths.items():
        logging.debug('found the following path: {} - {}'.format(asn, path))
    return _asn_paths

def get_aspath(sagan_results, pyasn_file=None):
    '''sort throught traceroute results.  it converts 
    the ip address of each hop in the traceroute to create
    and as hop path.  
    
    if pyasn_file is passed us that as the ipasn DB file.
    otherwise use tc whois'''
    if pyasn_file:
        asndb = pyasn(pyasn_file)
        def _lookup(ip):
            asn = asndb.lookup(ip)[0]
            if asn:
                return str(asn)
    else:
        whois = Client()
        def _lookup(ip):
            return whois.lookup(ip).asn
    asn_paths = []
    for result in sagan_results:
        if result.is_error:
            logging.error('{}: {}'.format(result, result.error_message))
            continue
        asn_path = []
        logging.debug('Checking: {}'.format(result.source_address))
        msm_asn = _lookup(result.source_address)
        if msm_asn:
            logging.debug('Adding: {}'.format(msm_asn))
            asn_path.append(msm_asn)
        for hop in result.hops:
            for packet in hop.packets:
                if packet.origin:
                    logging.debug('Checking: {}'.format(packet.origin))
                    asn = _lookup(packet.origin)
                    if asn and asn != asn[-1]:
                        logging.debug('Adding: {}'.format(asn))
                        asn_path.append(asn)
                    break
        logging.info('Found path: {}'.format(asn_path))
        asn_paths.append(asn_path)
    return asn_paths

def process_results(results):
    '''ensure we only use traceroute results'''
    sagan_results = []
    for result in results:
        sagan_result = Result.get(result)
        if type(sagan_result) != TracerouteResult:
            logging.warning('{} is {} not TracerouteResult'.format(
                sagan_result, type(sagan_result)))
            continue
        logging.debug('Adding: {}'.format(sagan_result))
        sagan_results.append(sagan_result)
    return sagan_results

def main():
    args = get_args()
    set_log_level(args.verbose)
    is_success, results = AtlasLatestRequest(args.msm_id).get()
    if is_success:
        sagan_results = process_results(results)
        asn_paths = get_aspath(sagan_results, args.pyasn_file)
        paths = get_paths(asn_paths)
        print reachability_report(paths)
        print '{} ANS analysed'.format(len(paths))


if __name__ == '__main__':
    main()
