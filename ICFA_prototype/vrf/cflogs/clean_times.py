"""
A simple script to extract total run-time results from aggregated attestation attempts 
"""


def main():
    """
    The main method (and only mfunction)
    """
    
    times = []
    with open("raw_timing", "r") as ifp:
        for line in ifp.readlines():
            line = line.strip()
            if "total time" in line.lower():
                time = line.split(":")[1].strip()
                times.append(time)
                
    print(len(times))
    
    with open("cleaned_times.txt", "w") as ofp:
        for time in times[-25:]:
            ofp.write(f"{time}\n")  


if __name__ == "__main__":
    main()
