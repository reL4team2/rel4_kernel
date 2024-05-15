import pandas as pd
from pandas.core.frame import DataFrame
import seaborn as sns
import matplotlib.pyplot as plt

test_conn_num = [1, 2, 4, 8, 16, 32]
colors = ["pink", "skyblue", "red", "green", "black", "yellow"]
for i in range(6):
    file_name = "./data/delay_data_" + str(test_conn_num[i])
    with open(file_name, 'r') as file:
        content = file.read().strip()
    delay_array = content.split(',')
    delay_array = [float(x) for x in delay_array]
    delay_array = DataFrame({"delay": delay_array})
    sns.kdeplot(delay_array["delay"], color=colors[i], label="connections_" + str(test_conn_num[i]), shade=True, bw_adjust=0.5)

plt.legend()
plt.savefig("./delay.png")