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
import csv
import os
import sys

import matplotlib.pyplot as plt
import pandas as pd
import numpy as np


def generate_simple_plot(hist, name_x, name_y, height, width, mult_factor_x_axis=1, outname="out"):
    fig, ax1 = plt.subplots(figsize=(width, height), sharex='all')
    fig.subplots_adjust(right=0.75)
    ax1.set_ylabel(name_y)
    ax1.set_xlabel(name_x)
    deletes = hist['action'] == 'D'
    dirDeletes = hist['action'] == 'DD'
    adds = hist['action'] == 'A'
    mods = hist['action'] == 'M'
    # ax1.plot(adds[adds].index, hist['t'][adds] / 1e6, "b.", label="add")
    # ax1.plot(mods[mods].index, hist['t'][mods] / 1e6, "m.", label="mod")
    ax1.plot(deletes[deletes].index, hist['t'][deletes] / 1e6, "g.", label="shred")
    if len(dirDeletes[dirDeletes]) != 0:
        ax1.plot(dirDeletes[dirDeletes].index, hist['t'][dirDeletes] / 1e6, "b.", label="shred directory")
    # ax1.set_ylim(bottom=0)
    ax1.set_yscale('log')
    ax2 = ax1.twinx()
    key_sizes = hist['key_size']
    mask_unique = key_sizes.diff() == 0
    unique_key_sizes = key_sizes.mask(mask_unique)
    ax2.plot(unique_key_sizes.index, unique_key_sizes / (1 << 20), "m.", label='key size')
    ax2.set_ylabel("Key size [MB]")
    try:
        numDirs = hist['numDirs']
        if np.sum(numDirs) > 0:
            ax3 = ax1.twinx()
            ax3.spines.right.set_position(("axes", 1.1))
            ax3.set_ylabel("Number of directories")
            # ax3.set_yscale('log')
            ax3.plot(numDirs.index, numDirs, "k:", label="directory count")
    except KeyError:
        pass
    fig.legend()
    ax2.set_ylim(bottom=0)
    os.makedirs("./plots", exist_ok=True)
    fig.savefig("./plots/" + outname + ".png", dpi=450)

# plots a github benchmark output
if __name__ == '__main__':
    histFile = sys.argv[1]
    hist = pd.read_csv(histFile, sep=',', header=0,
                       dtype={"action": str, "t": float, "key_size": int, "numDirs": int},
                       on_bad_lines='warn')

    name = histFile.split('/')[-1].split('_')[0]
    generate_simple_plot(hist, "operations", "time [ms]", 8, 18, outname=name)