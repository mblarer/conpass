import matplotlib.pyplot as plt
import pandas as pd

for enum in [("n", "none"), ("c", "client-side"), ("s", "server-side")]:
    fig, axs = plt.subplots(3, 2)

    dfs05 = pd.read_table(f'data/message_sizes_05_{enum[0]}', sep=' ')
    axs[0][0].plot(dfs05['hops'], dfs05['send']/1024, dfs05['hops'], dfs05['recv']/1024)
    axs[0][0].set_title(f'k = 5, enumeration: {enum[1]}')
    axs[0][0].set_xlabel('hops per segment')
    axs[0][0].set_ylabel('data [KiB]')
    axs[0][0].grid(True)
    axs[0][1].plot(dfs05['hops'], dfs05['recv']/dfs05['send'])
    axs[0][1].set_title('amplification')
    axs[0][1].set_xlabel('hops per segment')
    axs[0][1].grid(True)

    dfs10 = pd.read_table(f'data/message_sizes_10_{enum[0]}', sep=' ')
    axs[1][0].plot(dfs10['hops'], dfs10['send']/1024, dfs10['hops'], dfs10['recv']/1024)
    axs[1][0].set_title(f'k = 10, enumeration: {enum[1]}')
    axs[1][0].set_xlabel('hops per segment')
    axs[1][0].set_ylabel('data [KiB]')
    axs[1][0].grid(True)
    axs[1][1].plot(dfs10['hops'], dfs10['recv']/dfs10['send'])
    axs[1][1].set_title('amplification')
    axs[1][1].set_xlabel('hops per segment')
    axs[1][1].grid(True)

    dfs20 = pd.read_table(f'data/message_sizes_20_{enum[0]}', sep=' ')
    axs[2][0].plot(dfs20['hops'], dfs20['send']/1024, dfs20['hops'], dfs20['recv']/1024)
    axs[2][0].set_title(f'k = 20, enumeration: {enum[1]}')
    axs[2][0].set_xlabel('hops per segment')
    axs[2][0].set_ylabel('data [KiB]')
    axs[2][0].grid(True)
    axs[2][1].plot(dfs20['hops'], dfs20['recv']/dfs20['send'])
    axs[2][1].set_title('amplification')
    axs[2][1].set_xlabel('hops per segment')
    axs[2][1].grid(True)

    fig.tight_layout()
    fig.savefig(f'plots/message_sizes_{enum[0]}.jpg')
