import matplotlib.pyplot as plt
import pandas as pd

for enum in [("n", "none"), ("c", "client-side"), ("s", "server-side")]:
    fig, axs = plt.subplots(3, 1)

    dfs05 = pd.read_table(f'message_sizes_05_{enum[0]}.data', sep=' ')
    axs[0].plot(dfs05['hops'], dfs05['send'], dfs05['hops'], dfs05['recv'])
    axs[0].set_title(f'k = 5, enumeration: {enum[1]}')
    axs[0].set_xlabel('hops per segment')
    axs[0].set_ylabel('bytes')
    axs[0].grid(True)

    dfs10 = pd.read_table(f'message_sizes_10_{enum[0]}.data', sep=' ')
    axs[1].plot(dfs10['hops'], dfs10['send'], dfs10['hops'], dfs10['recv'])
    axs[1].set_title(f'k = 10, enumeration: {enum[1]}')
    axs[1].set_xlabel('hops per segment')
    axs[1].set_ylabel('bytes')
    axs[1].grid(True)

    dfs20 = pd.read_table(f'message_sizes_20_{enum[0]}.data', sep=' ')
    axs[2].plot(dfs20['hops'], dfs20['send'], dfs20['hops'], dfs20['recv'])
    axs[2].set_title(f'k = 20, enumeration: {enum[1]}')
    axs[2].set_xlabel('hops per segment')
    axs[2].set_ylabel('bytes')
    axs[2].grid(True)

    fig.tight_layout()
    fig.savefig(f'plot_message_sizes_{enum[0]}.jpg')
