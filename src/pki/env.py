import os, os.path, sys, pwd, grp, fcntl
from collections.abc import Mapping
import yaml, jinja2
from builtins import Exception as CoreException

KEY_USAGE=(
    'digitalSignature',
    'nonRepudiation',
    'keyEncipherment',
    'dataEncipherment',
    'keyAgreement',
    'keyCertSign',
    'cRLSign',
    'encipherOnly',
    'decipherOnly'
)
EXTENDED_KEY_USAGE={
    'serverAuth':(
        b'digitalSignature',
        b'keyEncipherment',
        b'keyAgreement',
    ),
    'clientAuth':(
        b'digitalSignature',
        b'keyAgreement',
    ),
    'codeSigning':(
        b'digitalSignature',
    ),
   'emailProtection':(
        b'digitalSignature',
        b'nonRepudiation',
        b'keyEncipherment',
        b'keyAgreement',
    ),
    'timeStamping':(
        b'digitalSignature',
        b'nonRepudiation',
    ),
   'OCSPSigning':(
        b'digitalSignature',
        b'nonRepudiation',
   )
}


class SettingsException(CoreException):
    pass

class Settings(Mapping):

    __fields__=('uid','usr','gid','grp','cfg')

    def __len__(self):
        return len(type(self).__fields__)

    def __iter__(self):
        return type(self).__fields__.__iter__()

    def __contains__(self, item):
        return item in type(self).__fields__

    def __getitem__(self, key):
        if key in self:
            attr='_%s' % key
            if hasattr(self, attr):
                return getattr(self, attr)
            else:
                return None
        else:
            raise KeyError('%s doesnot contains field named \'%s\'' % (self, key))

    def __init__(self, user=None, group=None, config=None):
        super().__init__()
        if user == None:
            import shutil
            try:
                _executable=os.path.realpath(shutil.which(sys.argv[0]))
            except TypeError as exception:
                _executable=os.path.realpath(sys.argv[0])
            _executable_stat = os.stat(_executable)
            self._uid = _executable_stat.st_uid
            self._usr = pwd.getpwuid(self._uid).pw_name
            if group == None:
                self._gid = _executable_stat.st_gid
                try:
                    self._grp = grp.getgrgid(self._gid).gr_name
                except KeyError:
                    pass
            else:
                self.setGroup(group)
        else:
            self.setUser(user)
            if group == None:
                self._gid=pwd.getpwuid(self._uid).pw_gid
                try:
                    self._grp=grp.getgrgid(self._gid).gr_name
                except KeyError:
                    pass
            else:
                self.setGroup(group)
        if config == None:
            self.setConfig(os.path.expanduser("~%s/config.yml" % self._usr))
        else:
            self.setConfig(os.path.realpath(config))

    def setUser(self, user):
        try:
            self._uid=pwd.getpwnam(user).pw_uid
        except KeyError as exception:
            raise SettingsException("Unknown user \"%s\"" % user) from exception
        self._usr=user

    def setGroup(self, group):
        try:
            self._gid=grp.getgrnam(group).gr_gid
        except KeyError as exception:
            raise SettingsException("Unknown group \"%s\"" % group) from exception
        self._grp=group

    def setConfig(self, path):
        self._cfg=Configuration(self, os.path.realpath(path))
Mapping.register(Settings)


class Configuration(dict):
    @staticmethod
    def _get_jinja2_environment(settings):
        env=jinja2.Environment()
        env.globals['pki']=settings
        for method in os.path.__all__:
            env.filters['path.%s' % method]=getattr(os.path, method)
        env.filters['file.read']=lambda path: [(
            '\n'.join([
                line.rstrip('\n') for line in stream.readlines()
            ]),
            stream.close()
        ) for stream in (open(path, 'r'),)][0][0]
        return env

    def __init__(self, settings, path):
        super().__init__()
        self._settings=settings
        self._path=path
        self._jinja2=type(self)._get_jinja2_environment(self._settings)
        self.reset()

    def reset(self):
        self.clear()
        with open(self._path, "r") as stream:
            for key, value in yaml.safe_load(stream).items():
                self[key]=value
        self.render(self, self)

    def render(self, node, data={}):
        import dis 
        for k, v in node.items():
            if isinstance(v, str):
                tpl = self._jinja2.from_string(v)
                node[k]=tpl.render(**data)
            if isinstance(v, list) or isinstance(v, dict):
                self.render(v, **data)


class SerialDBException(CoreException):
    pass


class SerialDB:
    def __init__(self, settings):
        self._settings=settings
        self._fd=None

    def __del__(self):
        pass

    def __enter__(self):
        if self._fd != None:
            raise SerialDBException("Already acquired")
        flags=os.O_APPEND | os.O_RDWR | os.O_CREAT
        self._fd=os.open(self._settings['cfg']['SERIAL_DB_PATH'], flags, 0o0640)
        fcntl.flock(self._fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc, traceback):
        if self._fd == None:
            raise SerialDBException("Already released")
        fcntl.flock(self._fd, fcntl.LOCK_UN)
        os.close(self._fd)
        self._fd=None

    def _read(self):
        os.lseek(self._fd, 0, os.SEEK_SET)
        content=os.read(self._fd, os.path.getsize(self._settings['cfg']['SERIAL_DB_PATH']))
        if len(content)==0:
            return -1
        return int(content, base=10)

    def read(self):
        if self._fd == None:
            with self:
                return self._read()
        return self._read()

    def _write(self, value):
        os.lseek(self._fd, 0, os.SEEK_SET)
        os.truncate(self._fd, 0)
        os.write(self._fd, ('%s' % value).encode())

    def write(self, serial):
        if self._fd == None:
            raise SerialDBException("Implicitly db locking is not allowed for write operation")
        return self._write(serial)