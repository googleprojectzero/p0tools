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

from config import CONFIG

from collections import defaultdict
import io
import os
import numpy as np
import pandas as pd
import random
import re
import subprocess
import sys


def load_data(data_dir):
  index_re = re.compile('speculation_window_(\\d+).pqt')
  max_index = 0
  dfs = [pd.DataFrame(columns=['cpu', 'tag_match', 'nop_count', 'latency'])]
  for root, dirs, files in os.walk(data_dir):
    for file in files:
      index_match = index_re.search(file)
      if index_match:
        index = int(index_match.group(1))
        if index > max_index:
          max_index = index
        df = pd.read_parquet(os.path.join(root, file))
        dfs.append(df)
  return max_index, pd.concat(dfs, ignore_index=True)


def run(cpu, start, end):
  try:
    seed = random.randrange(0, 0xffffffff);
    result = subprocess.run(
      ['adb', 'shell', f'sh -c "/data/local/tmp/speculation_window {cpu} {seed} 4096 {start} {end}"'],
      capture_output=True, timeout=10)
    stdout = result.stdout.decode('utf8')
    buffer = io.StringIO(stdout)
    # NOTE: If you want to store some data that doesn't fit in a uint8, you need
    # to change the dtype for that column! eg. if you have a higher precision
    # clock, this might be necessary for the latency column.
    df = pd.read_csv(buffer, names=['cpu', 'tag_match', 'nop_count', 'latency'], index_col=False, dtype=defaultdict(np.uint8))

    return df
  except subprocess.TimeoutExpired:
    return pd.DataFrame(columns=['cpu', 'tag_match', 'nop_count', 'latency'])


if __name__ == '__main__':
  random.seed()
  data_dir = sys.argv[1]

  index, df = load_data(data_dir)
  counts = {}

  for config in CONFIG:
    counts[config.cpu] = len(df.query(f'cpu == {config.cpu} & nop_count == {config.start}'))

  while True:
    print(counts)

    config = None
    for config_ in CONFIG:
      if config is None or counts[config_.cpu] < counts[config.cpu]:
        config = config_

    df = run(config.cpu, config.start, config.end)
    counts[config.cpu] += len(df.query(f'cpu == {config.cpu} & nop_count == {config.start}'))

    df.to_parquet(f'{data_dir}/speculation_window_{index}.pqt')
    index += 1
