#  Copyright 2023 Younis Khalil
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
#  documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
#  persons to whom the Software is furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
#  Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
#  BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
#  DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
#

import os
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def generate_plots(path, name_x, name_y, height, width, x_axis=None, mult_factor_x_axis=1,
                   legend=("PFS", "Baseline")):
    stats = pd.read_csv(path + ".txt", header=None).iloc[:, 0].to_numpy()
    stats_baseline = pd.read_csv(path + "_baseline.txt", header=None).iloc[:, 0].to_numpy()
    plt.figure(figsize=(width, height))
    plt.ylabel(name_y)
    plt.xlabel(name_x)
    range_x = x_axis if x_axis else np.arange(1, len(stats) + 1) * mult_factor_x_axis
    plt.plot(range_x, stats / 1e6, stats_baseline / 1e6)
    # plt.xticks(range_x)
    plt.ylim(bottom=0)
    plt.legend(legend)
    split_path = path.split('/')
    file_name = split_path[-1]
    directory = "/".join(split_path[:-1]) + "/plots/"
    os.makedirs(directory, exist_ok=True)
    plt.savefig(directory + file_name + ".png", dpi=300)


def generate_simple_plot(path, name_x, name_y, height, width, mult_factor_x_axis=1):
    stats = pd.read_csv(path + ".txt", header=None)
    plt.figure(figsize=(width, height))
    plt.ylabel(name_y)
    plt.xlabel(name_x)
    range_x = np.arange(0, len(stats)) * mult_factor_x_axis
    plt.plot(range_x, stats / 1e6)
    plt.ylim(bottom=0)
    split_path = path.split('/')
    file_name = split_path[-1]
    directory = "/".join(split_path[:-1]) + "/plots/"
    os.makedirs(directory, exist_ok=True)
    plt.savefig(directory + file_name + ".png", dpi=300)


def get_path_for_bench(bench_name, directory):
    files = list(filter(lambda x: str(x).startswith(bench_name), os.listdir(directory)))
    sizes = str(files[0])[len(bench_name):len(bench_name) + 8]
    return directory + "/" + bench_name + sizes

# generate the plots for simple benchmarks
if __name__ == '__main__':
    benches = ["put_small", "put_large", "delete"]
    descriptions = ["number of put operations", "number of put operations", "number of delete operations"]
    dir = sys.argv[1]
    for b, d in zip(benches, descriptions):
        try:
            generate_plots(get_path_for_bench(b, dir), d, "time (ms)", 8, 12)
        except:
            pass
    generate_plots(get_path_for_bench("rot_keys", dir), "number of shred operations", "time (ms)", 8, 12,
                   x_axis=[1000, 2000], legend=("local operations", "cloud overhead"))