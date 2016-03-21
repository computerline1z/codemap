# C:\Users\[USERNAME]\AppData\Roaming\Hex-Rays\IDA Pro\idapythonrc.py
from idaapi import *
from idautils import *
import idc
import zlib
import traceback
import webbrowser
from codemap import codemap

__version__ = '1.0'


def start_trace():
    '''
    setup all bp's you want(maybe using GETBPLIST or SetFunctionBP or manually)
    then execute this script in order to create dygraph trace.
    '''
    global codemap
    if codemap.start:
        codemap.pause = not codemap.pause
        print('Codemap Paused? : ', codemap.pause)
        if codemap.pause:
            codemap.db_insert()
            suspend_process()
        else:  # resume tracing
            continue_process()
        return
    elif idc.GetProcessState() is idc.DSTATE_NOTASK:
        print('IDA debugger not running')
        return

    codemap.init_arch()
    codemap.skel = codemap.skel.replace('--ARCH--', codemap.arch.name)
    hook_ida()

    print('hook ida done.')
    print('homedir : ', codemap.homedir)
    print('making table...')
    # initialize sqlite3 db
    print(codemap.db_create())

    # set default SQL
    if codemap.arch.name is 'x86':
        codemap.query = "select eip from trace{0}".format(codemap.uid)
    elif codemap.arch.name is 'x64':
        codemap.query = "select rip from trace{0}".format(codemap.uid)

    # if no baseaddr is configured then 0
    if codemap.base == 0:
        codemap.skel = codemap.skel.replace('--BASEADDR--', '0')
    else:
        codemap.skel = codemap.skel.replace(
            '--BASEADDR--', hex(codemap.base).replace('0x', ''))

    print('start HTTP server')
    # start HTTP server
    codemap.start_webserver()

    # fire up chrome!
    result = 'http://{}:{}/{}'.format(codemap.server,
                                      codemap.port,
                                      codemap.uid)
    webbrowser.open(result)
    print('start tracing...')
    codemap.start = True
    continue_process()


def set_function_bp():
    '''
    put cursor inside the IDA-recognized function then call this.
    bp will be toggle to all instructions of function
    '''
    ea = ScreenEA()
    if ea == idaapi.BADADDR:
        print("Could not get ScreenEA")
        return

    for chunk in Chunks(ea):
        chunk_startEA, chunk_endEA = chunk[:2]
        target = 0
        if chunk_startEA <= ea <= chunk_endEA:
            target = chunk_startEA
            break

    for fi in FuncItems(target):
        if get_bpt(fi, bpt_t()):
            del_bpt(fi)
        else:
            add_bpt(fi, 0, BPT_SOFT)


def set_range_bp():
    '''
    Get address range from user and setup bp to all instruction in that range.
    '''
    ea = ScreenEA()
    if ea == idaapi.BADADDR:
        print("Could not get ScreenEA")
        return
    start_addr = AskAddr(ea, 'Start Addr? (e.g. 0x8000) : ')
    end_addr = AskAddr(ea, 'End Addr? (e.g. 0xC000) : ')

    if not start_addr or not end_addr:
        print("AskAddr error")
        return

    for e in Heads(start_addr, end_addr):
        if get_bpt(e, bpt_t()):
            del_bpt(e)
        else:
            add_bpt(e, 0, BPT_SOFT)


def save_module_bp():
    '''
    open a dll file with IDA and execute this script after IDA analysis is done.
    the function offset information of dll will be saved to file inside Codemap directory
    '''
    global codemap
    try:
        modname = AskStr('', 'module name : ')
        if modname:
            bpo = ''
            for func in Functions():
                for chunk in Chunks(func):
                    chunk_startEA, chunk_endEA = chunk[:2]
                    length = chunk_endEA - chunk_startEA
                    if length < codemap.func_min_size:
                        continue
                    offset = chunk_startEA - get_imagebase()
                    bpo += str(offset) + '\n'
            print('bp offset generation complete! ' + str(len(bpo)))
            payload = bpo
            with open(codemap.homedir + modname + '.bpo', 'wb') as f:
                f.write(zlib.compress(payload))
    except:
        traceback.print_exc(file=sys.stdout)


def load_module_bp():
    '''
    while debugging the target app, put cursor somewhere inside the target module code. 
    execute the script and bp will be set for all functions specified in .bpo file
    '''
    global codemap
    try:
        # get current cursor
        ea = ScreenEA()
        baseaddr = 0

        # what module is my cursor pointing?
        for i in Modules():
            if ea > i.base and ea < i.base + i.size:
                baseaddr = i.base

        codemap.base = baseaddr         # this is needed.
        modname = AskStr('', 'module name : ')
        if modname:
            payload = ''
            with open(codemap.homedir + modname + '.bpo', 'rb') as f:
                payload = zlib.decompress(f.read())
            bps = payload.split()
            code = bytearray()
            for bp in bps:
                code += 'add_bpt({0}, 0, BPT_SOFT);'.format(baseaddr + int(bp))
            print('setting breakpoints...')
            # set bp!
            exec(str(code))
    except:
        traceback.print_exc(file=sys.stdout)


def set_module_bp():
    global codemap
    if not codemap.start:
        if idc.GetProcessState() is idc.DSTATE_NOTASK:
            save_module_bp()
        else:
            load_module_bp()


def listen_codemap():
    global codemap
    codemap.start_websocketserver()
    print("Listning to codemap connection...")


# print slows IDA down
class IDAHook(DBG_Hooks):
    global codemap

    def dbg_process_exit(self, pid, tid, ea, code):
        codemap.init_codemap()
        print("Process exited pid=%d tid=%d ea=0x%x code=%d" %
              (pid, tid, ea, code))

    def dbg_bpt(self, tid, ea):
        if codemap.pause:
            return 0  # stop visualizing

        codemap.set_data()
        codemap.db_insert_queue()
        continue_process()  # continue
        return 0  # no warning


def hook_ida():
    global debughook
    # Remove an existing debug hook
    try:
        if debughook:
            print("Removing previous hook ...")
            debughook.unhook()
    except:
        pass
    # Install the debug hook
    debughook = IDAHook()
    debughook.hook()
    debughook.steps = 0


codemap = codemap.Codemap()

CompileLine('static key_1() { RunPythonStatement("start_trace()"); }')
CompileLine('static key_2() { RunPythonStatement("set_function_bp()"); }')
CompileLine('static key_3() { RunPythonStatement("set_range_bp()"); }')
CompileLine('static key_4() { RunPythonStatement("set_module_bp()"); }')
CompileLine('static key_5() { RunPythonStatement("listen_codemap()"); }')

AddHotkey('Alt-1', 'key_1')
AddHotkey('Alt-2', 'key_2')
AddHotkey('Alt-3', 'key_3')
AddHotkey('Alt-4', 'key_4')
AddHotkey('Alt-5', 'key_5')

print('''ALT-1 : Start/Stop Codemap
ALT-2 : Set Function BP
ALT-3 : Set Range BP
ALT-4 : Create/Setup Module BP
ALT-5 : Connect Codemap Graph with IDA
Codemap Python Plugin is ready. enjoy. - by daehee''')
