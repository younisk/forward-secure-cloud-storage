import sys

import pandas as pd

if __name__ == '__main__':
    dfs = []
    for i in range(1, len(sys.argv)):
        # print("Reading file " + sys.argv[i])
        df = pd.read_csv(sys.argv[i], header=0, sep=',', on_bad_lines='skip')
        # print("found header " + str(df.columns))
        dfs.append(df)
    mean = pd.concat(dfs).groupby(level=0).median()
    # print(mean.head())
    pd.DataFrame({'action': dfs[0]['action'], 't': mean['t'], 'key_size': mean['key_size']}).to_csv(
        "git_bench_results/freeCodeCamp_2023_06_09_med_10.csv", header=True, index=False)