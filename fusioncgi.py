#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ┬ ┬┌─┐┬ ┬┌─┐┌┐┌ ┌─┐┌─┐┌┬┐
# │││└─┐├─┤│ ││││ │  │ ││││
# └┴┘└─┘┴ ┴└─┘┘└┘o└─┘└─┘┴ ┴

import hashlib
import json
import os
import shelve
import sys
import uuid
import gzip
from operator import attrgetter

if sys.version_info < (3,):
    from Cookie import BaseCookie, SimpleCookie
else:
    from http.cookies import BaseCookie, SimpleCookie


class FusionCookie(SimpleCookie):

    def getvalue(self, key, default=None):
        """Dictionary style get() method, including 'value' lookup."""
        if key in self:
            value = self[key]
            if type(value) is type([]):
                return map(attrgetter('value'), value)
            else:
                return value.value
        else:
            return default


class Request:
    def __init__(self):
        pass

    @staticmethod
    def cookie():
        c = FusionCookie()
        if 'HTTP_COOKIE' in os.environ:
            cookie_string = os.environ.get('HTTP_COOKIE')
            c.load(cookie_string)
        return c


class _Response:
    _flush = sys.stdout.flush
    _write = sys.stdout.write

    def __init__(self):
        self._cookie = FusionCookie()
        self._header = {}

    def _write_cookie(self):
        if self._cookie:
            self._write(str(self._cookie) + "\n")
            self._cookie = None

    def _write_head(self):
        for k, v in self._header.items():
            self._write(k + ": " + v + "\n")
        self._write_cookie()
        self._write("\n\n")

    def _write_body(self, data):
        self._write(data)
        self._flush()

    def _write_done(self, data):
        self._write_head()
        self._write_body(data)
        exit(0)

    def set_header(self, header):
        self._header.update(header)

    def set_cookie(self, cookie):
        if isinstance(cookie, BaseCookie):
            self._cookie.update(cookie)

    def json(self, data, cookie=None):
        if "Content-Type" not in Response._header:
            self.set_header({"Content-Type": "application/json"})
        self.set_cookie(cookie)
        self._write_done(json.dumps(data))

    def sse_head(self, cookie=None):
        if "Content-Type" not in Response._header:
            self.set_header({"Content-Type": "text/event-stream"})
        self.set_cookie(cookie)
        self._write_head()

    def sse_body(self, data):
        self._write_body("data: {}\n\n".format(data))

    def sse_json(self, data):
        self.sse_body(json.dumps(data))


Response = _Response()


class DataManage:
    def __init__(self, name):
        self.__filepath = name
        self.__shelve = None

    def __enter__(self):
        self.__shelve = shelve.open(self.__filepath, writeback=True)
        return self.__shelve

    def __exit__(self, exit_type, exit_value, exit_trace):
        self.__shelve.close()


class Session:
    def __init__(self, sid):
        self._sid = sid
        self._value = None

    def __enter__(self):
        with DataManage('session.db') as db_session:
            self._value = db_session[self._sid]
            return self._value

    def __exit__(self, exit_type, exit_value, exit_trace):
        with DataManage('session.db') as db_session:
            db_session[self._sid] = self._value

    @staticmethod
    def check(session_key):
        with DataManage('session.db') as db_session:
            if db_session.get(session_key):
                return True
            return False

    @staticmethod
    def new():
        uid = str(uuid.uuid4())
        sid = ''.join(uid.split('-'))
        with DataManage('session.db') as db_session:
            db_session[sid] = {}
        return sid

    @staticmethod
    def remove(sid):
        with DataManage('session.db') as db_session:
            del db_session[sid]

    @staticmethod
    def clear(**kwargs):
        with DataManage('session.db') as db_session:
            sids = db_session.keys()
            for sid in sids:
                for k, v in kwargs.items():
                    if k in db_session[sid] and v == db_session[sid][k]:
                        del db_session[sid]


class Auth:
    def __init__(self):
        pass

    @staticmethod
    def pwd_check(username, password):
        with DataManage("user.db") as db_user:
            if username not in db_user:
                return False
            pwd_in = hashlib.sha224(str(password)).hexdigest()
            if db_user[username]["password"] != pwd_in:
                return False
        return True

    @staticmethod
    def need_login():
        c = Request.cookie()
        # noinspection PyUnresolvedReferences
        if Session.check(c.getvalue("sid")):
            return
        Response.json({
            "code": 10001,
            "message": "not login",
        })

    @staticmethod
    def login(username):
        Session.clear(username=username)

        sid = Session.new()
        with Session(sid) as session:
            session['username'] = username

        cookie = FusionCookie()
        cookie['sid'] = sid
        Response.set_cookie(cookie)

    @staticmethod
    def logout():
        c = Request.cookie()
        if "sid" in c and Session.check(c["sid"].value):
            Session.remove(c["sid"].value)


if __name__ == "__main__":
    with DataManage("user.db") as user:
        user['admin'] = {
            'name': 'admin',
            'password': hashlib.sha224(str('passwd')).hexdigest(),
        }
    pass
