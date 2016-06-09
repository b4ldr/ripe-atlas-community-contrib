#!/usr/bin/env python

import logging
from time import time
from prettytable import PrettyTable
from requests import get
from argparse import ArgumentParser
from collections import defaultdict

def get_args():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('-t', '--time', type=int, default=int(time()),
            help='unix time stamp to fetch data for')
    parser.add_argument('-d', '--disable-rrcs', type=int, nargs='*', default=[],
            help='space seperated list of rrcs to disable e.g. "1 2 3 4"')
    parser.add_argument('-v', '--verbose', action='count' )
    parser.add_argument('resource')
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

def remove_prepends(path):
    #http://stackoverflow.com/questions/480214/how-do-you-remove-duplicates-from-a-list-in-python-whilst-preserving-order
    seen     = set()
    seen_add = seen.add
    return tuple([x for x in path if not(x in seen or seen_add(x))])

def get_paths(initial_state):
    asn_paths = defaultdict(set)
    for state in initial_state:
        #we change path to a set to remove prepending
        full_path = remove_prepends(state['path'])
        logging.info('processing path: {}'.format(full_path))
        for asn in full_path:
            if asn == full_path[-1]:
                break
            path = full_path[full_path.index(asn):]
            logging.debug('adding new ASN({}) with path: {}'.format(asn, path)) 
            asn_paths[asn].add(path)
    for asn, path in asn_paths.items():
        logging.debug('found the following path: {} - {}'.format(asn, path))
    return asn_paths

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
    headings = ['ANS', 'Number of unique paths', 'Min hop count', 'Max hop count']
    sortby   = 'Min hop count'
    entries  = []
    entries = [[asn, len(paths), min(map(len, paths)), max(map(len, paths))] 
            for asn, paths in paths.items()]
    return report(headings, entries, sortby)


def main():
    stat_api = 'https://stat.ripe.net/data/bgplay/data.json'
    args = get_args()
    set_log_level(args.verbose)
    rrcs = ','.join([str(x) for x in range(22) if x not in args.disable_rrcs])
    stat_args = { 
            'resource'  : args.resource,
            'starttime' : args.time,
            'endtime'   : args.time,
            'rrcs'      : rrcs,
            }
    logging.debug('Using the following args: {}'.format(stat_args))
    data = get(stat_api, params=stat_args).json()
    logging.debug('Stat returned the following\n{}'.format(data))
    paths = get_paths(data['data']['initial_state'])
    print reachability_report(paths)
    print '{} ANS analysed'.format(len(paths))

if __name__ == '__main__':
    main()
