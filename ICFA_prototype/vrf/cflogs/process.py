import pandas
"""
A simple script to calculate the statistics of a test's timing results
"""

def main():
    """
    The main method
    """
    times = []
    with open("data/baseline/mouse/cleaned_times.txt", "r") as ifp:  # change path to folder test folder you want to compute for
        for line in ifp.readlines():
            time = line.split("ms")[0].strip()
            times.append(float(time))
                
    
    time_frame = pandas.DataFrame()
    time_frame["times"] = times
    print(time_frame.describe())
    print(time_frame.var())


if __name__ == "__main__":
    main()
