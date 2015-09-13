"""Redis UserStore implementation"""

import datetime
from redis import StrictRedis

from pyramid.settings import asbool

from osiris.store.interface import TokenStore


def includeme(config):
    settings = config.registry.settings
    host = settings.get('osiris.store.host', 'localhost')
    port = int(settings.get('osiris.store.port', '6379'))
    db = int(settings.get('osiris.store.db', '0'))
    secret = settings.get('osiris.store.secret', None)

    store = RedisStore(host=host, port=port, db=db, secret=secret)

    config.registry.osiris_store = store


class RedisStore(TokenStore):
    """Redis Storage for oAuth tokens"""
    def __init__(self, host='localhost', port=6379, db=0, secret=None):

        self.host = host
        self.port = port
        self.db = db
        self.secret = secret

    def _conn(self):
        """The Redis connection"""
        try:
            db_conn = StrictRedis(host=self.host, port=self.port,
                                  db=self.db, password=self.secret)
        except ConnectionFailure:
            raise Exception('Unable to connect to Redis')

        return db_conn

    def retrieve(self, **kw):
        r = self._conn()

        if 'token' in kw:
            return r.hgetall(kw['token'])

        keys = r.keys(pattern='*')
        for key in keys:
            if r.type(key) == 'hash':
                if not r.hexists(key, 'source'):
                    continue
                elif r.hget(key, 'source') == 'osiris':
                    found = True
                    for rec in kw.keys():
                        if not r.hexists(key, rec):
                            continue
                        if r.hget(key, rec) != kw[rec]:
                            found = False
                            break
                    if found:
                        return r.hgetall(key)
                    else:
                        continue
                            
        return None

    def store(self, token, username, scope, expires_in):
        r = self._conn()

        now = datetime.datetime.utcnow()
        expire = now + datetime.timedelta(seconds=int(expires_in))

        data = {
            'username': username,
            'token':    token,
            'scope':    scope,
            'issued':   now,
            'expires':  expire,
            'source':   'osiris',
        }

        try:
            r.hmset(token, data)
            r.expireat(token, expire)
        except:
            return False
        else:
            return True

    def delete(self, token):
        try:
            r = self._conn()
            r.delete(token)
        except:
            return False
        else:
            return True

    def purge_expired(self):
        pass
