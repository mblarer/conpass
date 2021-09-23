import matplotlib.pyplot as plt
import pandas as pd


for enum in [("n", "none"), ("c", "client"), ("s", "server")]:
    fig, axs = plt.subplots(3, 2)
    for k in [(0, 5, "05"), (1, 10, "10"), (2, 20, "20")]:
        df = pd.read_table(f'data/throughput_{k[2]}_{enum[0]}', sep=' ')
        axs[k[0]][0].plot(df['workers'], df['n']*1_000_000_000/df['duration'])
        axs[k[0]][0].set_title(f'throughput (k = {k[1]})')
        axs[k[0]][0].set_xlabel('workers')
        axs[k[0]][0].set_ylabel('throughput [neg/s]')
        axs[k[0]][0].grid(True)
        axs[k[0]][1].plot(df['workers'], df['memory']/1_000)
        axs[k[0]][1].set_title(f'memory (k = {k[1]})')
        axs[k[0]][1].set_xlabel('workers')
        axs[k[0]][1].set_ylabel('peak memory [MB]')
        axs[k[0]][1].grid(True)
    fig.tight_layout()
    fig.savefig(f'plots/throughput_{enum[0]}.jpg')
