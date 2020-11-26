#Capa analysis importer for Ghidra.
#@author @reb311ion
#@keybinding shift O
#@category Analysis
#@toolbar capaexplorer.png

import json
from ghidra.framework.cmd import Command
from ghidra.program.database import ProgramBuilder
from ghidra.program.database.function import OverlappingFunctionException
from ghidra.program.model.address import Address
from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import *
from ghidra.program.model.symbol import *
from ghidra.util.exception import DuplicateNameException
from ghidra.util.exception import InvalidInputException 
from ghidra.app.cmd.label import *
from ghidra.program.model.symbol.SourceType import *
from ghidra.util.exception import DuplicateNameException

gnamespace = currentProgram.getGlobalNamespace()
symbolTable = currentProgram.getSymbolTable()
nmm = currentProgram.getNamespaceManager()
fm = currentProgram.getFunctionManager()

class capa_item:
    def __init__(self, namespace, scope, capability, match, label_list, attack=None):
        self.namespace = namespace
        self.scope = scope
        self.capability = capability
        self.match = match
        self.label_list = label_list
        self.attack = attack


def add_label(address, label_text):
    addr = toAddr(address)
    symbolTable = currentProgram.getSymbolTable()

    is_function_start = getFunctionAt(addr)
    instr = getInstructionAt(addr)

    if is_function_start: 
        if not is_function_start.getParentNamespace().toString().startswith("capa::"):
            label_text = is_function_start.getName()

    elif instr.getFlowType().isCall() and len(instr.getReferencesFrom()):
        symbol = getSymbolAt(instr.getReferencesFrom()[0].getToAddress())
        if symbol:
            if len(symbol.getName().split("_")) == 3:
                symbol_name = symbol.getName().split("_")[1]
                for external_function in fm.getExternalFunctions():
                    if external_function.getName() == symbol_name:
                        label_text = external_function.getName()
                        break
            else:
                label_text = symbol.getName()

    return symbolTable.createLabel(addr, label_text, USER_DEFINED)


def add_bookmark(addr, bookmark_text, category="CapaExplorer",):
    bm = currentProgram.getBookmarkManager()
    bm.setBookmark(addr, "Info", category, bookmark_text)


def create_namespace(namespace_path):
    cmd = CreateNamespacesCmd(namespace_path, SourceType.USER_DEFINED)
    cmd.applyTo(currentProgram)
    return cmd.namespace


def get_namespace(namespace, namespace_path):
    for symbol in currentProgram.symbolTable.getSymbols(namespace):
        if symbol.getSymbolType() == SymbolType.NAMESPACE:
            if symbol.getName() in namespace_path and symbol.getName() != namespace_path:
                get_namespace(symbol.namespace, namespace_path)
            if symbol.getName() == namespace_path:
                return symbol
    else:
        return None


def get_match_locations(match_dict):
    matches = []
    if 'locations' in match_dict.keys():
        return match_dict['locations']

    if match_dict['children']:
        for child in match_dict['children']:
            matches += get_match_locations(child)
    return matches


def parse_json(data):
    capa_items = []
    capabilities = list(data['rules'].keys())
    for capability in range (0, len(capabilities)):    
        Current_capability = capabilities[capability]
        Current_scope = data['rules'][capabilities[capability]]['meta']['scope']
        Matches_list = list(data['rules'][capabilities[capability]]['matches'].keys())

        if 'namespace' in data['rules'][capabilities[capability]]['meta']:
            Current_namespace = data['rules'][capabilities[capability]]['meta']['namespace'].replace("/", "::")
        else:
            Current_namespace = "N/A"
        
        meta = data['rules'][capabilities[capability]]['meta']
        if not 'lib' in meta.keys() or meta['lib'] == False:
            addr_list = []
            for match in data['rules'][capabilities[capability]]['matches'].keys():
                addr_list += get_match_locations(data['rules'][capabilities[capability]]['matches'][match])

            attack = []
            if "att&ck" in meta.keys():
                attack = meta['att&ck'] 
            for match in range (0, len(Matches_list)):
                item = capa_item(Current_namespace, Current_scope, Current_capability, int(Matches_list[match]), addr_list, attack)
                
            capa_items.append(item)
    return capa_items


def capa_place(items):
    for item in items:
        namespace = create_namespace("capa::" + item.namespace)
        match_function = getFunctionContaining(toAddr(item.match))
        if match_function:
            match_function.addTag(item.capability)
            if item.attack:
                for tactic in item.attack:
                    add_bookmark(match_function.getEntryPoint(), tactic, "CapaExplorer - Mitre ATT&CK")

        for label in item.label_list:
                add_bookmark(toAddr(label), item.capability)
                label_handle = add_label(label, hex(label))
                if label_handle:
                    try:
                        label_handle.setNamespace(namespace)
                    except DuplicateNameException:
                        pass
                    

if __name__ == '__main__':
    log_path = askFile("Drltrace log", "Choose file:")
    log_path = str(log_path)
    data = ""
    with open(log_path, "rb") as file:
        data = file.read()
    data = json.loads(data)
    capa_items = parse_json(dict(data))
    capa_place(capa_items)
