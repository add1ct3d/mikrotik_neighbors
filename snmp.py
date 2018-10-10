# !/usr/bin/python2
""" SNMP UTILITES """

__all__ = ['get', 'set', 'walk', 'authentication', 'engine', 'mibViewController']

# Import required python libraries
import copy
import os

import pysnmp.smi
from pysnmp.hlapi import *

import database
from classes import ValueError
from utils import eprint


class AuthSNMP(object):
    def __init__(self):
        self._version = os.getenv('SNMP_VERSION', '2c')
        """ SNMP version to use """
        self.community = os.getenv('SNMP_COMMUNITY', 'sassnmp')
        """ SNMP community """
        self._auth_protocol = os.getenv('SNMP_APROTOCOL', 'MD5')
        """ SNMP authentication protocol (MD5|SHA) """
        self.auth_passphrase = os.getenv('SNMP_APASSPHRASE', '')
        """ SNMP authentication protocol pass phrase """
        self.security_engine_id = os.getenv('SNMP_SENGINE-ID', '')
        """ SNMP security engine ID (e.g. 800000020109840301) """
        self.context_engine_id = os.getenv('SNMP_CENGINE-ID', '')
        """ SNMP context engine ID (e.g. 800000020109840301) """
        self._level = os.getenv('SNMP_LEVEL', 'noAuthNoPriv')
        """ SNMP security level (noAuthNoPriv|authNoPriv|authPriv) """
        self.context = os.getenv('SNMP_CONTEXT', '')
        """ SNMP context name (e.g. bridge1) """
        self.user_name = os.getenv('SNMP_USER-NAME', '')
        """ SNMP security name (e.g. bert) """
        self._priv_protocol = os.getenv('SNMP_PPROTOCOL', 'DES')
        """  SNMP privacy protocol (DES|AES) """
        self.priv_passphrase = os.getenv('SNMP_PPASSPHRASE', '')
        """ SNMP privacy protocol pass phrase """
        self.boots_time = os.getenv('SNMP_BOOTS_TIME', '')
        """ SNMP destination engine boots/time """

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, value):
        if value in ('1', '2c', '3'):
            self._verson = value
        else:
            raise ValueError("SNMP version must be 1|2c|3")

    @property
    def auth_protocol(self):
        return self._auth_protocol

    @auth_protocol.setter
    def auth_protocol(self, value):
        if value in ('MD5', 'SHA'):
            self._auth_protocol = value
        else:
            raise ValueError("SNMP authentication protocol must be MD5|SHA")

    @property
    def level(self):
        return self._level

    @level.setter
    def level(self, value):
        if value in ('noAuthNoPriv', 'authNoPriv', 'authPriv'):
            self._level = value
        else:
            raise ValueError("SNMP security level must be noAuthNoPriv|authNoPriv|authPriv")

    @property
    def priv_protocol(self):
        return self._priv_protocol

    @priv_protocol.setter
    def priv_protocol(self, value):
        if value in ('DES', 'AES'):
            self._priv_protocol = value
        else:
            raise ValueError("SNMP privacy protocol must be DES|AES")


class ConnectionData(object):
    def __init__(self, ip, auth=None):
        self.snmpEngine = snmpEngine
        self.contextData = contextData
        self.transportTarget = UdpTransportTarget((ip, 161), timeout=snmp_timeout, retries=snmp_retries)
        if auth is None:
            authd = update_defaults(ip, authentication)
        else:
            authd = update_defaults(ip, auth)
        if authd.version == '1':
            self.authData = CommunityData(authd.community, mpModel=0)
        elif authd.version == '2c':
            self.authData = CommunityData(authd.community, mpModel=1)
        elif authd.version == '3':
            # TODO: Make v3 community auth
            pass
        else:
            self.authData = None


def get(conn, obj):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(conn.snmpEngine,
               conn.authData,
               conn.transportTarget,
               conn.contextData, obj,
               lookupNames=True, lookupValues=True))

    if errorIndication:
        eprint(errorIndication)
        return varBinds, True
    elif errorStatus:
        eprint('%s at %s' % (errorStatus.prettyPrint(),
                             errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        return varBinds, True
    else:
        return varBinds, False
        # for varBind in varBinds:
        #    sprint(' = '.join([x.prettyPrint() for x in varBind]))


def walk(conn, obj):
    varBindsArray = []
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
            conn.snmpEngine,
            conn.authData,
            conn.transportTarget,
            conn.contextData, obj,
            lexicographicMode=False):
        if errorIndication:
            eprint(errorIndication)
            return varBinds, True
        elif errorStatus:
            eprint('%s at %s' % (errorStatus.prettyPrint(),
                                 errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            return varBinds, True
        else:
            varBindsArray.append(varBinds)
        #    for varBind in varBinds:
        #        print(varBind)
    return varBindsArray, False


def set(conn, obj):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        setCmd(conn.snmpEngine,
               conn.authData,
               conn.transportTarget,
               conn.contextData, obj))

    if errorIndication:
        print(errorIndication)
        return varBinds, True
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        return varBinds, True
    else:
        return varBinds, False
        # for varBind in varBinds:
        #    print(' = '.join([x.prettyPrint() for x in varBind]))


def update_defaults(ip, defaults):
    result = copy.deepcopy(defaults)
    new = database.get_auth(ip)
    if new:
        if new['snmp_version'] is not None:
            result.verson = new['snmp_version']
        if new['snmp_community'] is not None:
            result.community = new['snmp_community']
        if new['snmp_aprot'] is not None:
            result.auth_protocol = new['snmp_aprot']
        if new['snmp_apass'] is not None:
            result.auth_passphrase = new['snmp_apass']
        if new['snmp_seng_id'] is not None:
            result.security_engine_id = new['snmp_seng_id']
        if new['snmp_ceng_id'] is not None:
            result.context_engine_id = new['snmp_ceng_id']
        if new['snmp_level'] is not None:
            result.level = new['snmp_level']
        if new['snmp_context'] is not None:
            result.context = new['snmp_context']
        if new['snmp_user'] is not None:
            result.user_name = new['snmp_user']
        if new['snmp_pprot'] is not None:
            result.priv_protocol = new['snmp_pprot']
        if new['snmp_ppass'] is not None:
            result.priv_passphrase = new['snmp_ppass']
        if new['snmp_boots'] is not None:
            result.boots_time = new['snmp_boots']
    return result


# Vendors

# Globals
snmp_timeout = int(os.getenv('SNMP_TIMEOUT', 5))
snmp_retries = int(os.getenv('SNMP_RETRIES', 2))
authentication = AuthSNMP()
snmpEngine = SnmpEngine()
contextData = ContextData()
mibBuilder = pysnmp.smi.builder.MibBuilder()
mibViewController = pysnmp.smi.view.MibViewController(mibBuilder)
pysnmp.smi.compiler.addMibCompiler(mibBuilder)
"""pysnmp.smi.compiler.addMibCompiler(mibBuilder,
    sources=['file:///usr/share/snmp/mibs',
             'http://mibs.snmplabs.com/asn1/@mib@'],
    destination='/usr/local/share/snmp/mibs')"""

sysObjectID = ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysObjectID', 0)) \
    .addMibSource('/usr/local/share/snmp/pysnmp_mibs/') \
    .addAsn1MibSource('file:///usr/local/share/snmp/mibs/@mib@.my') \
    .loadMibs('MIKROTIK-MIB')
