# Copyright 2024 Google LLC
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

import idautils
import idc
import ida_bytes

def export(filename):
  segments = []
  
  f = open(filename, 'wb')

  for s in idautils.Segments():
    segment = {}
    segment['start'] = idc.get_segm_start(s)
    segment['end'] = idc.get_segm_end(s)
    segment['perm'] = idc.get_segm_attr(s, idc.SEGATTR_PERM)
    segments.append(segment)
    
  numsegments = len(segments)
  f.write(numsegments.to_bytes(8, byteorder='little'))
  
  for s in segments:
    f.write(s['start'].to_bytes(8, byteorder='little'))
    f.write(s['end'].to_bytes(8, byteorder='little'))
    f.write(s['perm'].to_bytes(8, byteorder='little'))

  for s in segments:
    f.write(ida_bytes.get_bytes(s['start'], s['end']-s['start']))

  num_names = 0
  names_bytes = []
  l = 0
  for ea, name in idautils.Names():
    b = ea.to_bytes(8, byteorder='little') + name.encode() + b'\0'
    l += len(b)
    names_bytes.append(b)
    num_names += 1
  f.write(num_names.to_bytes(8, byteorder='little'))
  f.write(l.to_bytes(8, byteorder='little'))
  for b in names_bytes:
    f.write(b)

