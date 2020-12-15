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
from Cookie import SimpleCookie, SmartCookie
from operator import attrgetter


class SuperCookie(SimpleCookie):

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


class Web:
    def __init__(self):
        pass

    Cookie = SmartCookie

    @staticmethod
    def json_response(data, cookie=None):
        sys.stdout.write("Content-Type: application/json\n")
        if cookie:
            sys.stdout.write(str(cookie))
            sys.stdout.write("\n")

        sys.stdout.write("\n\n")
        sys.stdout.write(json.dumps(data))
        exit(0)

    @staticmethod
    def sse_head(cookie=None):
        sys.stdout.write("Content-type: text/event-stream\n")
        if cookie:
            sys.stdout.write(str(cookie))
            sys.stdout.write("\n")
        sys.stdout.write("\n\n")

    @staticmethod
    def sse_body(data):
        sys.stdout.write("data: {}\n\n".format(data))
        sys.stdout.flush()

    @staticmethod
    def sse_json(data):
        Web.sse_body(json.dumps(data))

    @staticmethod
    def cookie():
        c = SuperCookie()
        if 'HTTP_COOKIE' in os.environ:
            cookie_string = os.environ.get('HTTP_COOKIE')
            c.load(cookie_string)
        return c


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
                        break
                    pass
                pass
            pass
        pass


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
        c = Web.cookie()
        # noinspection PyUnresolvedReferences
        if Session.check(c.getvalue("sid")):
            return
        Web.json_response({
            "code": 10001,
            "message": "not login",
        })

    @staticmethod
    def login(username):
        Session.clear(username=username)

        sid = Session.new()
        with Session(sid) as session:
            session['username'] = username
        return sid

    @staticmethod
    def logout():
        c = Web.cookie()
        if "sid" in c and Session.check(c["sid"].value):
            Session.remove(c["sid"].value)


if __name__ == "__main__":
    with DataManage("user.db") as user:
        user['admin'] = {
            'name': 'admin',
            'password': hashlib.sha224(str('passwd')).hexdigest(),
        }
    pass
