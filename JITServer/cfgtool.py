# Copyright 2018 Google LLC
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This code is intended for security research purposes

import idaapi
from idc import Byte
from idc import Word
from idc import Dword
from idc import Qword
from idautils import Functions
from idautils import XrefsTo

cfg_functions = None

def maybe_get_name(ea):
  name = hex(ea)
  funcname = idaapi.get_func_name(ea)
  if not funcname:
    return name
  demangled_name = idaapi.demangle_name(funcname, idaapi.cvar.inf.short_demnames)
  if not demangled_name:
    return funcname
  return demangled_name
  
def print_chain(chain):
  print 'Found chain:'
  chain.reverse()
  for c in chain:
    print c
  print '' 

def find_chain_helper(chain, cfg_whitelist, startaddress, depth):
  xrefs = set()
  for xref in XrefsTo(startaddress, 0):
    for f in Functions(xref.frm, xref.frm): 
      xrefs.add(f)
  for xref in xrefs:
    if xref in cfg_whitelist:
      newchain = chain[:]
      newchain.append(maybe_get_name(xref))
      print_chain(newchain)
  if depth <= 1:
    return
  for xref in xrefs:
    newchain = chain[:]
    newchain.append(maybe_get_name(xref))
    find_chain_helper(newchain, cfg_whitelist, xref, depth-1)
  
def find_chain(startaddress, depth, include_supressed = False):
  if not cfg_functions:
    get_cfg_functions()

  cfg_whitelist = set()
  for f in cfg_functions:
    if (f['flags'] & 2) and (not include_supressed):
      continue
    cfg_whitelist.add(f['ea'])

  chain = [maybe_get_name(startaddress)]
  find_chain_helper(chain, cfg_whitelist, startaddress, depth-1)

def search_cfg_functions(pattern):
  if not cfg_functions:
    get_cfg_functions()

  for f in cfg_functions:
    if pattern in str(f['name']):
      print hex(f['ea']) + ' : ' + str(f['name']) + ' flags : ' + str(f['flags'])

def print_cfg_functions():
  if not cfg_functions:
    get_cfg_functions()

  for f in cfg_functions:
    print hex(f['ea']) + ' : ' + str(f['name']) + ' flags : ' + str(f['flags'])

def get_cfg_functions():
  global cfg_functions

  cfg_functions = []

  header = Dword(idaapi.get_imagebase()+0x3C)
  magic = Word(idaapi.get_imagebase()+header+4+20)
  if (magic != 0x10b) and (magic != 0x20b):
    print('Error: unknown format')
  if magic == 0x10b:
    loadconfig = Dword(idaapi.get_imagebase()+header+4+20+176)
    GuardCFFunctionTable = Dword(idaapi.get_imagebase()+loadconfig+80)
    GuardCFFunctionCount = Dword(idaapi.get_imagebase()+loadconfig+84)
    headersize = (Qword(idaapi.get_imagebase()+loadconfig+88) & 0xF0000000) >> 28
  else:
    loadconfig = Dword(idaapi.get_imagebase()+header+4+20+192)
    GuardCFFunctionTable = Qword(idaapi.get_imagebase()+loadconfig+128)
    GuardCFFunctionCount = Qword(idaapi.get_imagebase()+loadconfig+136)
    headersize = (Qword(idaapi.get_imagebase()+loadconfig+144) & 0xF0000000) >> 28

  entrysize = 4 + headersize

  for i in range(0, GuardCFFunctionCount):
    entryaddress = GuardCFFunctionTable + i * entrysize
    function = Dword(entryaddress) + idaapi.get_imagebase()
    flags = 0
    if headersize >= 1:
      flags = Byte(entryaddress+4)
    if idaapi.get_func(function):
      funcname = maybe_get_name(function)
      cfg_functions.append({'ea': function, 'name': funcname, 'flags': flags})


