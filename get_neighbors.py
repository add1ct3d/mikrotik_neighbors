# !/usr/bin/python2
""" GET MIKROTIK NEIGHBORS """

import sys
from optparse import OptionParser
from utils import eprint, sprint
import snmp
from pysnmp.hlapi import *
import database

unicode_type = type(u'')

__version__ = "0.01"
__copyright__ = 'Vladimir Kushnir aka Kvantum i(c)2018'


def get_param(arguments=None):
    """Parse Command-Line parameters"""
    parser = OptionParser(usage="%prog <ip address> [options]", version="%prog " + __version__)
    parser.add_option('-t', '--level', dest='scan_lvl', type='int', help="Neighbors scan level", default=0)
    parser.add_option('-p', '--print', dest='scan_print', action="store_true", help="Print results", default=False)

    (opt, args) = parser.parse_args(arguments)

    if len(args) != 1:
        parser.error('You must specify IP address!')

    return args[0], opt.scan_lvl, opt.scan_print


def get_values(conn, obj):
    varBinds, Err = snmp.get(conn, obj)
    sprint(len(varBinds))
    for varBind in varBinds:
        name, value = varBind
        sprint(varBind,'Name:', name.items(),'Val:', value.prettyPrint())
    values = {}
    return {}


def get_neighbors(ip, lvl, prn):
    conn = snmp.ConnectionData(ip)
    obj = ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0))
    varBinds, err = snmp.get(conn, obj)
    if err:
        sys.exit(1)
    sprint('Scan:', ip, varBinds[0][1].prettyPrint())
    sprint('Get:', ip, 'NeighborIpAddress', '...')
    mtxrNeighborIpAddress = get_values(conn, ObjectType(ObjectIdentity('MIKROTIK-MIB', 'mtxrNeighborIpAddress', 5)))


def main():
    """Main procedure"""
    (scan_ip, scan_lvl, scan_prn) = get_param()
    get_neighbors(scan_ip, scan_lvl, scan_prn)


if __name__ == "__main__":
    main()
