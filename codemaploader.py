# C:\Users\[USERNAME]\AppData\Roaming\Hex-Rays\IDA Pro\idapythonrc.py
from idaapi import *
import idc
import zlib
import traceback
import webbrowser
from codemap import codemap
from codemap.ActionHandler import ActionHandler

__version__ = '2.0'

codemap = codemap.Codemap()


def IDA_State():
    if get_root_filename() is None:
        return 'empty'
    try:
        a = idc.GetRegValue('esp')
        return 'running'
    except:
        return 'static'


# batch function break point script - daehee
def Functions(start=None, end=None):
    if not start:
        start = cvar.inf.minEA
    if not end:
        end = cvar.inf.maxEA
    chunk = get_fchunk(start)
    if not chunk:
        chunk = get_next_fchunk(start)
    while chunk and chunk.startEA < end and (chunk.flags & FUNC_TAIL) != 0:
        chunk = get_next_fchunk(chunk.startEA)
    func = chunk
    while func and func.startEA < end:
        yield (func)
        func = get_next_func(func.startEA)


def FuncItems(start):
    func = get_func(start)
    if not func:
        return
    fii = func_item_iterator_t()
    ok = fii.set(func)
    while ok:
        yield fii.current()
        ok = fii.next_code()

'''
Returns a list of module objects with name,size,base and the rebase_to
'''
def Modules():
    mod = idaapi.module_info_t()
    result = idaapi.get_first_module(mod)
    while result:
        yield idaapi.object_t(name=mod.name, size=mod.size, base=mod.base, rebase_to=mod.rebase_to)
        result = idaapi.get_next_module(mod)


# print slows IDA down
class IDAHook(DBG_Hooks):
    global codemap

    def dbg_process_exit(self, pid, tid, ea, code):
        codemap.init_codemap()
        print("Process exited pid=%d tid=%d ea=0x%x code=%d" %
              (pid, tid, ea, code))

    def dbg_bpt(self, tid, ea):
        if codemap.pause:
            return 0    # stop visualizing

        codemap.set_data()
        codemap.db_insert_queue()
        continue_process()                  # continue
        return 0    # no warning


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

'''
- SetRangeBP - 
Get address range from user and setup bp to all instruction in that range.
'''
def SetRangeBP():
    if IDA_State() == 'empty':
        print 'no program loaded'
        return
    start_addr = AskStr('', 'Start Addr? (e.g. 0x401000) : ')
    end_addr = AskStr('', 'End Addr? (e.g. 0x401050) : ')
    
    if start_addr is None or end_addr is None:
        return

    start_addr = int(start_addr.replace('0x', ''), 16)
    end_addr = int(end_addr.replace('0x', ''), 16)

    for e in Heads(start_addr, end_addr):
        if get_bpt(e, bpt_t()):
            del_bpt(e)            
        else:
            add_bpt(e, 0, BPT_SOFT)

'''
- SetFunctionBP - 
put cursor inside the IDA-recognized function then call this. 
bp will be set to all instructions of function
'''
def SetFunctionBP():
    if IDA_State() == 'empty':
        print 'no program loaded'
        return
    ea = ScreenEA()
    target = 0
    for e in Functions():
        func = get_func(e)
        if func.startEA <= ea and ea <= func.endEA:
            target = func.startEA

    if target != 0:
        for e in FuncItems(target):
            if get_bpt(e, bpt_t()):
                del_bpt(e)
            else:
                add_bpt(e, 0, BPT_SOFT)
    else:
        Warning('put cursor in the function body')


'''
- Start Trace -
setup all bp's you want(maybe using GETBPLIST or SetFunctionBP or manually)
then execute this script in order to create dygraph trace.
'''
def StartTracing():
    global codemap
    if codemap.start is False and IDA_State() != 'running':
        print 'IDA debugger not running'
        return

    if codemap.start:
        codemap.pause = not codemap.pause
        print 'Codemap Paused? : ', codemap.pause
        if codemap.pause:    # resume tracing
            codemap.db_insert()
            suspend_process()
        else:
            continue_process()
        return

    elif idc.GetProcessState() is idc.DSTATE_NOTASK:
        print('IDA debugger not running')
        return

    codemap.init_arch()
    codemap.skel = codemap.skel.replace('--ARCH--', codemap.arch.name)
    hook_ida()

    print 'hook ida done.'
    print 'homedir : ', codemap.homedir
    print 'making table...'
    # initialize sqlite3 db
    print codemap.db_create()

    # set default SQL
    if codemap.arch.name == 'x86':
        codemap.query = "select eip from trace{0}".format(codemap.uid)
    elif codemap.arch.name == 'x64':
        codemap.query = "select rip from trace{0}".format(codemap.uid)

    # if no baseaddr is configured then 0
    if codemap.base == 0:
        codemap.skel = codemap.skel.replace('--BASEADDR--', '0')
    else:
        codemap.skel = codemap.skel.replace(
            '--BASEADDR--', hex(codemap.base).replace('0x', ''))
    #print codemap.skel
    print 'start HTTP server'
    # start HTTP server
    codemap.start_webserver()

    # start Websocket Server
    codemap.start_websocketserver()

    # fire up chrome!
    result = 'http://{0}:{1}/{2}'.format(codemap.server,
                                         codemap.port,
                                         codemap.uid)
    print result
    webbrowser.open(result)
    print 'start tracing...'
    codemap.start = True
    continue_process()


'''
- SaveModuleBP -
open a dll file with IDA and execute this script after IDA analysis is done.
the function offset information of dll will be saved to file inside Codemap directory
'''
def SaveModuleBP():
    global codemap
    try:
        modname = AskStr('', 'module name : ')
        
        if modname is None:
            return

        bpo = ''
        for f in Functions():
            e = get_func(f)
            func = e.startEA
            length = e.endEA - e.startEA
            if length < codemap.func_min_size:
                continue
            offset = func - get_imagebase()
            bpo += str(offset) + '\n'
        print 'bp offset generation complete! ' + str(len(bpo))
        payload = bpo
        with open(codemap.homedir + modname + '.bpo', 'wb') as f:
            f.write(zlib.compress(payload))
    except:
        traceback.print_exc(file=sys.stdout)
        
'''
- LoadModuleBP -
while debugging the target app, put cursor somewhere inside the target module code. 
execute the script and bp will be set for all functions specified in .bpo file
'''
def LoadModuleBP():
    global codemap
    try:
        # get current cursor
        cur = get_screen_ea()
        baseaddr = 0
        modname = ''
        # what module is my cursor pointing?
        for i in Modules():
            if cur > i.base and cur < i.base + i.size:
                modname = i.name.split('\x00')[0]
                modname = modname.split('\\')[-1:][0]
                baseaddr = i.base

        codemap.base = baseaddr         # this is needed.
        modname = AskStr('', 'module name : ')
        payload = ''
        with open(codemap.homedir + modname + '.bpo', 'rb') as f:
            payload = zlib.decompress(f.read())
        bps = payload.split()
        code = bytearray()
        for bp in bps:
            code += 'add_bpt({0}, 0, BPT_SOFT);'.format(baseaddr + int(bp))
        print 'setting breakpoints...'
        # set bp!
        exec(str(code))
    except:
        traceback.print_exc(file=sys.stdout)

def SetModuleBP():
    global codemap
    if codemap.start is False and IDA_State() is 'static':
        SaveModuleBP()
    if codemap.start is False and IDA_State() is 'running':
        LoadModuleBP()

def ListenCodemap():
    global codemap
    if codemap.start:
        codemap.start_websocketserver()
        print "Listning to codemap connection..."
    else:
        print "Codemap is not loaded !"

'''
CompileLine('static key_1() { RunPythonStatement("StartTracing()"); }')
CompileLine('static key_2() { RunPythonStatement("SetFunctionBP()"); }')
CompileLine('static key_3() { RunPythonStatement("SetRangeBP()"); }')
CompileLine('static key_4() { RunPythonStatement("SetModuleBP()"); }')
CompileLine('static key_5() { RunPythonStatement("ListenCodemap()"); }')

AddHotkey('Alt-1', 'key_1')
AddHotkey('Alt-2', 'key_2')
AddHotkey('Alt-3', 'key_3')
AddHotkey('Alt-4', 'key_4')
AddHotkey('Alt-5', 'key_5')

print 'ALT-1 : Start/Stop Codemap'
print 'ALT-2 : Set Function BP'
print 'ALT-3 : Set Range BP'
print 'ALT-4 : Create/Setup Module BP'
print 'ALT-5 : Connect Codemap Graph with IDA'
'''
print 'Codemap Python Plugin is ready. enjoy. - by daehee'

icons_path = os.path.join(idc.GetIdaDirectory(), 'plugins', 'codemap', 'icons')

class StartStopCodemapHandler(ActionHandler):
    TEXT = "Start/Stop Codemap"
    ICON = idaapi.load_custom_icon(os.path.join(icons_path, 'start.png'))
    def _activate(self, ctx):
        StartTracing()


class SetFunctionBPHandler(ActionHandler):
    TEXT = "Set Function BP"
    ICON = idaapi.load_custom_icon(os.path.join(icons_path, 'funcbp.png'))
    def _activate(self, ctx):
        SetFunctionBP()

class SetRangeBPHandler(ActionHandler):
    TEXT = "Set Range BP"
    ICON = idaapi.load_custom_icon(os.path.join(icons_path, 'rangebp.png'))
    def _activate(self, ctx):
        SetRangeBP()

class SetModuleBPHandler(ActionHandler):
    TEXT = "Create/Setup Module BP"
    ICON = idaapi.load_custom_icon(os.path.join(icons_path, 'modulebp.png'))
    def _activate(self, ctx):
        SetModuleBP()

class ListenCodemapHandler(ActionHandler):
    TEXT = "Connect Codemap Graph with IDA"
    ICON = idaapi.load_custom_icon(os.path.join(icons_path, 'connect.png'))
    def _activate(self, ctx):
        ListenCodemap()

class Hooks(idaapi.UI_Hooks):
    def populating_tform_popup(self, form, popup):
        # You can attach here.
        pass

    def finish_populating_tform_popup(self, form, popup):
        # Or here, after the popup is done being populated by its owner.

        if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, StartStopCodemapHandler.get_name(), "")
            idaapi.attach_action_to_popup(form, popup, SetFunctionBPHandler.get_name(), "")
            idaapi.attach_action_to_popup(form, popup, SetRangeBPHandler.get_name(), "")
            idaapi.attach_action_to_popup(form, popup, SetModuleBPHandler.get_name(), "")
            idaapi.attach_action_to_popup(form, popup, ListenCodemapHandler.get_name(), "")

#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class codemap_t(plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Codemap is a binary analysis tool for run-trace visualization provided as IDA plugin"
    help = ""
    wanted_name = "IDA Codemap"
    wanted_hotkey = ""

    def init(self):

        if not idaapi.is_idaq():
            return PLUGIN_SKIP
        # We need to use some global val

        StartStopCodemapHandler.register()
        SetFunctionBPHandler.register()
        SetRangeBPHandler.register()
        SetModuleBPHandler.register()
        ListenCodemapHandler.register()

        self.hooks = Hooks()
        self.hooks.hook()
        return idaapi.PLUGIN_KEEP

    def term(self):
        StartStopCodemapHandler.unregister()
        SetFunctionBPHandler.unregister()
        SetRangeBPHandler.unregister()
        SetModuleBPHandler.unregister()
        ListenCodemapHandler.unregister()

    def run(self, arg):
        pass

#---------------------------------------------------------------------
# Init Plugin
#---------------------------------------------------------------------
def PLUGIN_ENTRY():
    return codemap_t()
