#! /usr/bin/python3

from config import CONFIG

from multiprocessing import Pool as Pool
import matplotlib.pyplot as plt
import numpy as np
import os
import pandas as pd
import re
import scipy.stats as stats
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


max_index, df = load_data(sys.argv[1])
df_size = len(df)

start = {}
threshold_latency = {}
start_row = {}

# First prepare a template dataframe that we're going to use to store each
# chunk of the processed data.

out_df_cpu = []
out_df_tag_match = []
out_df_nop_count = []

for config in CONFIG:
  start[config.cpu] = config.start
  threshold_latency[config.cpu] = config.threshold_latency
  start_row[config.cpu] = len(out_df_cpu)

  for i in range(config.start, config.end):
    out_df_cpu.append(config.cpu)
    out_df_tag_match.append(0)
    out_df_nop_count.append(i)
    out_df_cpu.append(config.cpu)
    out_df_tag_match.append(1)
    out_df_nop_count.append(i)

out_df_template = {
  'cpu': out_df_cpu,
  'tag_match': out_df_tag_match,
  'nop_count': out_df_nop_count,
  'hit_count': np.zeros(len(out_df_nop_count)),
  'miss_count': np.zeros(len(out_df_nop_count))
}


def new_df():
  out_df = pd.DataFrame(out_df_template)
  out_df['cpu'] = out_df['cpu'].astype('uint8')
  out_df['tag_match'] = out_df['tag_match'].astype('uint8')
  out_df['nop_count'] = out_df['nop_count'].astype('uint8')
  out_df['hit_count'] = out_df['hit_count'].astype('uint32')
  out_df['miss_count'] = out_df['miss_count'].astype('uint32')
  return out_df


# Process a slice of the source dataset down to hit/miss counts
def single_task(args):
  print(args)
  start_index, end_index = args
  out_df = new_df()

  miss_count_loc = out_df.columns.get_loc('miss_count')
  hit_count_loc = out_df.columns.get_loc('hit_count')

  for i in range(start_index, end_index):
    row = df.iloc[i]

    index = start_row[row.cpu] + (row.nop_count - start[row.cpu]) * 2 + row.tag_match

    if row.latency > threshold_latency[row.cpu]:
      out_df.iloc[index, miss_count_loc] += 1
    else:
      out_df.iloc[index, hit_count_loc] += 1

  return out_df


# Parallel processing to count all of the cache-hit / cache-misses from the raw
# latency values. This just splits the source dataframe into chunks and maps
# the computation across those chunks before coalescing the results at the end.
task_queue = []
for i in range(0, df_size, 8192):
  task_queue.append((i, min(i + 8192, df_size - 1)))

results = []
with Pool() as pool:
  results = pool.map(single_task, task_queue)

df = new_df()
hit_count_loc = df.columns.get_loc('hit_count')
miss_count_loc = df.columns.get_loc('miss_count')

for result in results:
  for i in range(len(result)):
    df.iloc[i, hit_count_loc] += result.iloc[i, hit_count_loc]
    df.iloc[i, miss_count_loc] += result.iloc[i, miss_count_loc]

print(df)

# Now compute percentages and graph the results
def miss_percentage(cpu, tag_match, nop_count):
  row = df.query(f'cpu == {cpu} & nop_count == {nop_count} & tag_match == {tag_match}')
  return (row.miss_count / (row.hit_count + row.miss_count))

fail_miss_percentages = []
pass_miss_percentages = []

for i, config in enumerate(CONFIG):
  fail_miss_percentages.append(np.zeros((config.end - config.start, ), dtype=float))
  pass_miss_percentages.append(np.zeros((config.end - config.start, ), dtype=float))

  for j in range(config.start, config.end):
    fail_miss_percentages[i][j - config.start] = miss_percentage(config.cpu, 0, j)
    pass_miss_percentages[i][j - config.start] = miss_percentage(config.cpu, 1, j)

fig, axs = plt.subplots(nrows=len(CONFIG), ncols=1)

fig.supxlabel("NOP count")
fig.supylabel("Cache miss probability")
fig.tight_layout()

for i, config in enumerate(CONFIG):
  axs[i].set_title(f'CPU {config.cpu}')
  axs[i].plot(pass_miss_percentages[i], 'g,', linestyle='-', linewidth=1)
  axs[i].plot(fail_miss_percentages[i], 'r,', linestyle='-', linewidth=1)

plt.show()