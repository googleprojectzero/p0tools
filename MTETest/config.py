#! /usr/bin/python3

# Copyright 2023 Google LLC
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

class Config(object):
	def __init__(self, cpu, start, end, threshold_latency):
		self.cpu = cpu
		self.start = start
		self.end = end
		self.threshold_latency = threshold_latency

CONFIG = [
	# This should be filled with Config objects according to your CPU under test.
	# threshold_latency is only used during graphing, so you can start collecting
	# data first and then update the threshold latency value later once you have
	# some data.
]