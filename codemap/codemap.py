#!/usr/bin/env python
# -*- coding: utf-8 -*-

from idaapi import *
import idautils
import idc
import time
import os
import platform
import threading
import datetime
import sqlite3
from server.webserver import CodemapHTTPServer
from server.webserver import CodemapHTTPRequestHandler
from server.socketserver import *


class Codemap(object):
    def __init__(self):
        self.homedir = ''
        sysname = platform.system()
        if sysname in ('Darwin', 'Linux'):
            self.homedir = '%s/.idapro/codemap/' % os.environ['HOME']
        elif sysname == 'Windows':
            self.homedir = '%s\\Hex-Rays\\IDA Pro\\codemap\\' % os.environ['APPDATA']

        self.server = '127.0.0.1'
        self.port = 9165
        self.bpevent_bufsize = 1
        self.bpevent_bufsize_max = 128
        self.bpevent_buffer = []
        self.func_min_size = 16
        self.start = False
        self.pause = False
        self.data = ''
        self.mem_size = 32
        self.base = 0
        self.arch = 'x86'
        self.uid = 0
        self.sqlite_conn = None
        self.sqlite_cursor = None
        self.dygraph = None
        self.skel = None
        self.interaction = None
        self.regs = '"id","eip"'
        self.thread_lock = threading.Lock()
        self.thread_http = None
        self.thread_ws = None
        self.uid = '{:%Y%m%d%H%M%S}'.format(datetime.datetime.now())
        self.db_name = 'codemap.db'
        self.db_file_path = os.path.join(self.homedir, self.db_name)
        self.websocket_server = None
        self.web_server = None
        self.seq_dict = {}
        self.init_codemap()
        self.query = ''

        if os.path.exists(self.db_file_path):
            try:
                os.remove(self.db_file_path)
            except:
                print('Codemap Database is locked.')
                print('Please close another instance of Codemap and run IDA again')

    # init_arch func must called in BP.
    def init_arch(self):
        try:
            try:
                info = idaapi.get_inf_structure()
            except AttributeError:
                info = idaapi.cvar.inf
            bitness = idc.GetSegmentAttr(
                list(idautils.Segments())[0], idc.SEGATTR_BITNESS)

            if bitness == 0:
                bitness = 16
            elif bitness == 1:
                bitness = 32
            elif bitness == 2:
                bitness = 64
            print(bitness)
            if info.procName == 'metapc':
                if bitness == 64:
                    self.arch = X64()
                elif bitness == 32:
                    self.arch = X86()
            else:
                print('TODO: implement many architectures :)')
        except:
            print('init_arch except')

    def init_codemap(self):
        self.uid = '{:%Y%m%d%H%M%S}'.format(datetime.datetime.now())
        if not os.path.exists(self.homedir):
            os.makedirs(self.homedir)

        self.skel = open(self.homedir + 'ui/skel.htm', 'rb').read()
        self.dygraph = open(self.homedir + 'ui/dygraph.js', 'rb').read()
        self.interaction = open(
            self.homedir + 'ui/interaction.js', 'rb').read()
        self.skel = self.skel.replace('--REPLACE--', self.uid)

        self.bpevent_buffer = []
        self.bpevent_bufsize = 1
        self.start = False
        self.pause = False
        self.regs = '"id","eip"'

    def is_buffer_full(self):
        return len(self.bpevent_buffer) >= self.bpevent_bufsize

    def clear_bpevent_buffer(self):
        self.bpevent_buffer = []

    def db_create(self):
        try:
            self.sqlite_conn = self.sqlite_conn or sqlite3.connect(self.db_file_path)
            self.sqlite_cursor = self.sqlite_conn.cursor()

            fmt = self.arch.db_fmt
            lines = ','.join(fmt.format(reg) for reg in self.arch.reg_list)
            state_create = 'CREATE TABLE trace{}(id INTEGER PRIMARY KEY AUTOINCREMENT, {});'.format(self.uid, lines)
            self.sqlite_cursor.execute(state_create)
            return True
        except sqlite3.Error as e:
            print('DB create error! Error message:' + e.args[0])
            print('Create statement: ' + state_create)
            return False

    def db_insert_queue(self):
        _dict = self.arch.dict_all()
        self.bpevent_buffer.append(_dict)
        if self.is_buffer_full():
            self.db_insert()
            if self.bpevent_bufsize < self.bpevent_bufsize_max:
                self.bpevent_bufsize *= 2
                print('buffser size up to ', self.bpevent_bufsize)

    def db_insert(self):
        try:
            self.sqlite_conn = self.sqlite_conn or sqlite3.connect(self.db_file_path)
            self.sqlite_cursor = self.sqlite_conn.cursor()
            state_insert = "insert into trace{0} ".format(self.uid)

            fmt = '{0}, m_{0}'
            lines = ', '.join(fmt.format(reg) for reg in self.arch.reg_list)
            state_cols = '({})'.format(lines)

            fmt = ':{0}, :m_{0}'
            lines = ', '.join(fmt.format(reg) for reg in self.arch.reg_list)
            state_vals = 'VALUES({})'.format(lines)

            state_insert = ' '.join(state_insert, state_cols, state_vals)
            with self.thread_lock:
                self.sqlite_cursor.executemany(
                    state_insert, self.bpevent_buffer)
                self.sqlite_conn.commit()
            self.clear_bpevent_buffer()

            return True
        except sqlite3.Error as e:
            print('DB insert error! Error message: ' + e.args[0])
            print('Insert statement: ' + state_insert)
            return False

    def set_data(self):
        self.arch.set_reg()
        self.arch.set_memory(self.mem_size)

    def start_webserver(self):
        def webthread_start():
            print(time.asctime(), "Server Starts - %s:%s" % (self.server, self.port))
            self.web_server = CodemapHTTPServer(
                (self.server, self.port), CodemapHTTPRequestHandler)
            self.web_server.set_codemap(self)
            self.seq_dict.update({self.uid: []})
            try:
                self.web_server.serve_forever()
            except KeyboardInterrupt:
                pass
            self.web_server.server_close()
            print(time.asctime(), "Server Stops - %s:%s" % (self.server, self.port))

        if self.thread_http:
            pass
        self.thread_http = threading.Thread(target=webthread_start)
        self.thread_http.daemon = True
        self.thread_http.start()

    def start_websocketserver(self):
        def ws_start():
            self.websocket_server = SimpleWebSocketServer('', 4116, CodemapWSD)
            self.websocket_server.serveforever()
        if self.thread_ws:
            return
        self.thread_ws = threading.Thread(target=ws_start)
        self.thread_ws.daemon = True
        self.thread_ws.start()

    def ws_send(self, msg):
        if self.websocket_server:
            for conn in self.wsbsocket_server.connections.itervalues():
                conn.sendMessage(msg)


class BasicArchitecture(object):
    name = ''
    reg_list = []
    db_fmt = ''

    def __init__(self):
        self.reg = {}
        self.memory = {}

    # default set_reg handles everything as string(x64 use this).
    def set_reg(self):
        for i in self.reg_list:
            self.reg[i] = str(idc.GetRegValue(i))

    def set_memory(self, mem_size):
        for i in self.reg_list:
            # consider type of reg[i].
            self.memory[i] = idaapi.dbg_read_memory(int(self.reg[i]), mem_size)
            self.memory[i] = self.memory[i].encode('hex') if self.memory[i] else ''

    # TODO: Rename!!!!
    def dict_all(self):
        _dict = {}
        _dict.update(self.reg)
        for k in self.memory:
            _dict.update({'m_' + k: self.memory[k]})
        return _dict


class X86(BasicArchitecture):
    name = 'x86'
    reg_list = 'eip eax ebx ecx edx esi edi ebp esp arg1 arg2 arg3 arg4'.split()
    db_fmt = '{0} INT8, m_{0} VARCHAR(2048)'

    def __init__(self):
        self.reg = {k: 0 for k in self.reg_list}  # int
        self.memory = {k: '' for k in self.reg_list}

    def get_stack_arg(self, n):
        esp = idc.GetRegValue('esp') + n * 4
        val = idaapi.dbg_read_memory(esp, 4)[::-1].encode('hex')
        return int(val, 16)

    # x86 overrides set_reg for integer version? -> maybe
    def set_reg(self):
        for i in self.reg_list:
            if 'arg' not in i:
                self.reg[i] = idc.GetRegValue(i)

        self.reg['arg1'] = self.get_stack_arg(1)
        self.reg['arg2'] = self.get_stack_arg(2)
        self.reg['arg3'] = self.get_stack_arg(3)
        self.reg['arg4'] = self.get_stack_arg(4)


class X64(BasicArchitecture):
    name = 'x64'
    reg_list = '''rip rax rbx rcx rdx rsi rdi rbp rsp r8
                  r9 r10 r11 r12 r13 r14 r15'''.split()
    db_fmt = '{0} VARCHAR(32), m_{0} VARCHAR(2048)'

    def __init__(self):
        self.reg = {k: '' for k in self.reg_list}  # string
        self.memory = {k: '' for k in self.reg_list}
