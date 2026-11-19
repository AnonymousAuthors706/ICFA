import os
"""
A simple script to undo loop counters in TRACES logs. Used to expand entries for 'unoptimized baseline' comparisons
"""


def main():
    """
    The main method to read in TRACES logs, expand them, and output the unoptimized logs
    """
    logs = os.listdir()
    #print(logs)
    logs.sort()
    #print(logs)
    
    transfers = []
    for log in logs:
        print(log)
        if ".cflog" in log:
            with open(log, "r") as ifp:
                for line in ifp.readlines():
                    transfers.append(line.strip())

    #print(len(transfers), len(transfers)*4)
    rebuilt_log = []
    for i in range(len(transfers)):
        transfer = transfers[i]
        if transfer[0:4] == "ffff":  # Loop counters all start with FFFF
            #print(transfer)
            count = transfer[4:]
            #print(count)
            count = int(count, 16)
            #print(count)
            for j in range(count):
                rebuilt_log.append(transfers[i-1])
        else:
            rebuilt_log.append(transfer)

    # Easy reporting
    print(f"Transfer count: {len(rebuilt_log)}\nSize: {len(rebuilt_log)*4}")
    with open("rebuilt_cflog.txt", "w") as ofp:
        for line in rebuilt_log:
            ofp.write(line+"\n")


if __name__ == "__main__":
    main()
    

