from abc import abstractclassmethod, abstractstaticmethod
from argparse import Namespace
from sys import stderr, argv
import os, os.path
from env import SerialDB, Settings, KEY_USAGE, EXTENDED_KEY_USAGE
from OpenSSL.crypto import (
    PKey,
    TYPE_RSA,
    X509,
    X509Extension,
    PKCS12,
    FILETYPE_PEM,
    FILETYPE_TEXT,
    load_privatekey,
    dump_privatekey,
    load_publickey,
    dump_publickey,
    load_certificate_request as load_csr,
    dump_certificate_request as dump_csr,
    load_certificate as load_crt,
    dump_certificate as dump_crt
)
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates as load_pkcs12

__all__=[
    'SUBJECT_FIELDS_ARGS',
    'CLI',
    'GenCA',
    'CAInfo'
]

SUBJECT_FIELDS_ARGS={
    "countryName": {
        'args': ('-C', '--country'),
        'kwargs': {
            'metavar': 'COUNTRY',
            'help': 'CA certificate subject\'s country code'
        }
    },
    "stateOrProvinceName": {
        'args': ('-ST', '--state'),
        'kwargs': {
            'metavar': 'STATE_OR_PROVINCE',
            'help': 'CA certificate subject\'s state or province name'
        }
    },
    "localityName": {
        'args': ('-L', '--locality'),
        'kwargs': {
            'metavar': 'LOCALITY',
            'help': 'CA certificate subject\'s locality name'
        }
    },
    "organizationName": {
        'args': ('-O', '--organization'),
        'kwargs': {
            'metavar': 'ORGANIZTION',
            'help': 'CA certificate subject\'s organization name'
        }
    },
    "organizationUnitName": {
        'args': ('-OU', '--org-unit'),
        'kwargs': {
            'metavar': 'ORG_UNIT',
            'help': 'CA certificate subject\'s organization unit name'
        }
    },
    "commonName": {
        'args': ('-CN', '--common-name'),
        'kwargs': {
            'metavar': 'COMMON_NAME',
            'help': 'CA certificate subject\'s organization unit name'
        }
    },
    "emailAddress": {
        'args':('--email',),
        'kwargs': {
            'metavar': 'EMAIL',
            'help': 'CA certificate subject\'s email address'
        }
    }
}


class CLI:
    class Command:
        @abstractclassmethod
        def register(cls, cli, subparsers, alias):
            pass

        @abstractstaticmethod
        def __new__(cls, settings:Settings, arguments:Namespace) -> int:
            pass

        @staticmethod
        def perror(*args):
            for arg in args:
                stderr.write('%s\n' % str(arg))


    def __init__(self, prog=None):
        from argparse import ArgumentParser
        self._parser=ArgumentParser(
            prog=prog if prog != None else argv[0],
            add_help=False
        )
        self._parser.add_argument('-?', '--help', action='help', help="Show this help and exit")
        self._parser.add_argument('-c', '--config', action='store', dest='config', metavar='CONFIG', help='Specifies PKI configuration file')
        subparsers=self._parser.add_subparsers(dest='command', required=True, help="Command for execution")
        self._commands={}

        GenCA.register(self, subparsers, 'gen-ca')
        CAInfo.register(self, subparsers, 'ca-info')
        Issue.register(self, subparsers, 'issue')

    def __call__(self, *args):
        parsed_args=self._parser.parse_args(args=args)
        settings=Settings(config=parsed_args.config)
        return self._commands[parsed_args.command](settings, parsed_args)


class GenCA(CLI.Command):
    @classmethod
    def register(cls, cli, subparsers, alias):
        subparser=subparsers.add_parser(alias, add_help=False, help="Generates pki CA key and certificate pair (PKCS12)")
        subject=subparser.add_argument_group("Subject", "Certificate authority subject fields")
        for dest, sf_arg in SUBJECT_FIELDS_ARGS.items():
            subject.add_argument(*sf_arg['args'], action='store', dest=dest, **sf_arg['kwargs'])
        others=subparser.add_argument_group("Others")
        others.add_argument('-f', '--overwrite', action='store_true', dest='overwrite', help="Overwrite CA certificate if exists")
        others.add_argument('-?', '--help', action='help', help="Show this help and exit")
        cli._commands[alias]=cls

    @staticmethod
    def __new__(cls, settings:Settings, arguments:Namespace):
        if os.path.exists(settings['cfg']['CA_KEYSTORE_PATH']) and not arguments.overwrite:
            cls.perror("CA certificate already exists.")
            return 1
        with SerialDB(settings) as serial_db:
            key=PKey()
            key.generate_key(TYPE_RSA, settings['cfg']['CA_KEY_SIZE'])
            
            serial=serial_db.read()+1
            
            cert=X509()
            cert.set_serial_number(serial)
            for sfName in SUBJECT_FIELDS_ARGS:
                if not hasattr(arguments, sfName):
                    continue
                sfValue=getattr(arguments, sfName)
                if sfValue!=None:
                    setattr(cert.get_subject(), sfName, sfValue)
            cert.add_extensions([
                X509Extension(b'basicConstraints', False, b'CA:true'),
                X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=cert),
                X509Extension(b'keyUsage', False, b'digitalSignature,keyCertSign,cRLSign')
            ])
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(int(settings['cfg']['CA_CRT_TTL'], base=10) *24*60*60)
            cert.set_issuer(cert.get_subject())
            cert.set_pubkey(key)
            cert.sign(key, 'sha-512')

            p12=PKCS12()
            p12.set_ca_certificates([cert])
            p12.set_certificate(cert)
            p12.set_privatekey(key)
            with open(settings['cfg']['CA_KEYSTORE_PATH'], "wb") as stream:
                stream.write(p12.export(settings['cfg']['CA_KEYSTORE_PASSPHRASE'].encode('utf-8')))
            os.chmod(path=settings['cfg']['CA_KEYSTORE_PATH'], mode=0o640)
            serial_db.write(serial)
            return 0


class CAInfo(CLI.Command):
    @classmethod
    def register(cls, cli, subparsers, alias):
        #subparser=
        subparsers.add_parser(alias, add_help=False, help="Prints CA certificate info")

        cli._commands[alias]=cls

    @staticmethod
    def __new__(cls, settings:Settings, arguments:Namespace)->int:
        if not os.path.exists(settings['cfg']['CA_KEYSTORE_PATH']):
            cls.perror("No certification authority found.")
            return 1
        with open(settings['cfg']['CA_KEYSTORE_PATH'], 'rb') as stream:
            key, cert, chain=load_pkcs12(stream.read(), settings['cfg']['CA_KEYSTORE_PASSPHRASE'].encode('utf-8'))
            print(str(dump_crt(FILETYPE_PEM, cert), 'utf-8'))
            return 0


class Issue(CLI.Command):
    class Method:
        @abstractclassmethod
        def register(cls, command, subparsers, alias):
            pass

        @abstractstaticmethod
        def __new__(cls, settings:Settings, arguments:Namespace, certificate:X509):
            pass


    class ByRequest(Method):
        @classmethod
        def register(cls, subparsers, alias):
            parser=subparsers.add_parser(alias, add_help=False,  help="Issues certificate by certificate signing request")
            parser.add_argument('-i', '--file', action='store', dest='csrFile', default='/dev/stdin', metavar='CSR_FILE', help="Path to csr file")
            parser.add_argument('-?', '--help', action='help', help="Show this help and exit")

        @staticmethod
        def __new__(cls, settings:Settings, arguments:Namespace, certificate:X509):
            with open(arguments.csrFile, 'rb') as csr_stream:
                csr=load_csr(FILETYPE_PEM, csr_stream.read())
            certificate.set_pubkey(csr.get_pubkey())
            certificate.set_subject(csr.get_subject())
            certificate.add_extensions(csr.get_extensions())


    class BySubject(Method):
        @classmethod
        def register(cls, subparsers, alias):
            parser=subparsers.add_parser(alias, add_help=False,  help="Issues certificate by subject fields")
            parser.add_argument('-i', '--file', action='store', dest='keyFile', default='/dev/stdin', metavar='KEY_FILE', help="Path to key file")
            subject_fields=parser.add_argument_group("Subject", "Certificate subject fields")
            for dest, sf_arg in SUBJECT_FIELDS_ARGS.items():
                subject_fields.add_argument(*sf_arg['args'], action='store', dest=dest, **sf_arg['kwargs'])
            ext=parser.add_argument_group("Extensions", "Certificate extensions")
            ext.add_argument('-u', '--key-usage', action='store', choices=[*KEY_USAGE, *EXTENDED_KEY_USAGE.keys()], dest='keyUsage', nargs='*', help='Appends value to certificate extension keyUsage (OID 2.5.29.15)')
            others=parser.add_argument_group("Others")
            others.add_argument('-?', '--help', action='help', help="Show this help and exit")

        @staticmethod
        def __new__(cls, settings:Settings, arguments:Namespace, certificate:X509):
            with open(arguments.keyFile, 'rb') as key_stream:
                key=load_publickey(FILETYPE_PEM, key_stream.read())
            certificate.set_pubkey(key)
            for sfName in SUBJECT_FIELDS_ARGS:
                if not hasattr(arguments, sfName):
                    continue
                sfValue=getattr(arguments, sfName)
                if sfValue!=None:
                    setattr(certificate.get_subject(), sfName, sfValue)
            if arguments.keyUsage != None:
                extendedKeyUsage=[value.encode('utf-8') for value in arguments.keyUsage if value in EXTENDED_KEY_USAGE]
                keyUsage=[value.encode('utf-8') for value in arguments.keyUsage if value in KEY_USAGE]
                for ku in arguments.keyUsage:
                    if ku in EXTENDED_KEY_USAGE:
                        keyUsage+=[aku for aku in EXTENDED_KEY_USAGE[ku] if aku not in keyUsage]
                certificate.add_extensions([
                    *([X509Extension(b'basicConstraints', False, b'CA:true')] if b'keyCertSign' in keyUsage else []),
                    X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=certificate),
                    *([ X509Extension(b'keyUsage', False, b','.join(keyUsage)) ] if len(keyUsage)>0 else []),
                    *([ X509Extension(b'extendedKeyUsage', False, b','.join(extendedKeyUsage)) ] if len(extendedKeyUsage)>0 else [])
                ])


    _methods:dict[str, Method]={
        'by-request':ByRequest,
        'by-subject':BySubject
    }


    @classmethod
    def register(cls, cli, subparsers, alias):
        subparser=subparsers.add_parser(alias, add_help=False, help="Issue certificate by PKI CA")
        subparser.add_argument('-?', '--help', action='help', help="Show this help and exit")
        
        method_subparsers=subparser.add_subparsers(dest='method', required=True, help="Certificate information source")

        for method in cls._methods:
            cls._methods[method].register(method_subparsers, method)

        cli._commands[alias]=cls

    @staticmethod
    def __new__(cls, settings:Settings, arguments:Namespace)->int:
        try:
            if not os.path.exists(settings['cfg']['CA_KEYSTORE_PATH']):
                cls.perror("No certification authority found.")
                return 1
            with open(settings['cfg']['CA_KEYSTORE_PATH'], 'rb') as stream:
                issuer_key, issuer_cert, issuer_chain=load_pkcs12(stream.read(), settings['cfg']['CA_KEYSTORE_PASSPHRASE'].encode('utf-8'))
            with SerialDB(settings) as serial_db:
                serial=serial_db.read()+1
                cert=X509()
                # Fill certificate info
                cls._methods[arguments.method](settings, arguments, cert)

                cert.set_serial_number(serial)
                cert.gmtime_adj_notBefore(0)
                cert.gmtime_adj_notAfter(int(settings['cfg']['CA_CRT_TTL'], base=10) *24*60*60)
                cert.set_issuer(X509.from_cryptography(issuer_cert).get_subject())
                cert.sign(PKey.from_cryptography_key(issuer_key), 'sha-512')
                print(dump_crt(FILETYPE_PEM, cert).decode('utf-8'))
                serial_db.write(serial)
                return 0
        except Exception as exception:
            cls.perror(str(exception))
            return 1
