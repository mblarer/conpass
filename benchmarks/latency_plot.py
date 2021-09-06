import matplotlib.pyplot as plt
import pandas as pd

for enum in [("n", "none"), ("c", "client-side"), ("s", "server-side")]:
    fig, axs = plt.subplots(3, 1)

    dfs05 = pd.read_table(f'data/latencies_05_{enum[0]}', sep=' ')
    axs[0].plot(dfs05['hops'], dfs05['duration']/dfs05['n']/1_000_000)
    axs[0].set_title(f'k = 5, enumeration: {enum[1]}')
    axs[0].set_xlabel('hops per segment')
    axs[0].set_ylabel('duration [ms]')
    axs[0].grid(True)

    dfs10 = pd.read_table(f'data/latencies_10_{enum[0]}', sep=' ')
    axs[1].plot(dfs10['hops'], dfs10['duration']/dfs10['n']/1_000_000)
    axs[1].set_title(f'k = 10, enumeration: {enum[1]}')
    axs[1].set_xlabel('hops per segment')
    axs[1].set_ylabel('duration [ms]')
    axs[1].grid(True)

    dfs20 = pd.read_table(f'data/latencies_20_{enum[0]}', sep=' ')
    axs[2].plot(dfs20['hops'], dfs20['duration']/dfs20['n']/1_000_000)
    axs[2].set_title(f'k = 20, enumeration: {enum[1]}')
    axs[2].set_xlabel('hops per segment')
    axs[2].set_ylabel('duration [ms]')
    axs[2].grid(True)

    fig.tight_layout()
    fig.savefig(f'plots/latencies_{enum[0]}.jpg')
