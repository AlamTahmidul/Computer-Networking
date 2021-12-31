### Usage ###
    The code in `pinger.py` was tested on Linux OS. To run the program on Linux:
        1. Open up Terminal (Ctrl + Alt + T). Make sure you have full administrator root privileges otherwise the program will not run.
        2. cd into the folder that pinger.py is in
        3. Run `sudo python3 pinger.py address` where address is 127.0.0.1 or any other URLs like google.com or stonybrook.edu
            a. Example 1: sudo python3 pinger.py 127.0.0.1
            b. Example 2: sudo python3 pinger.py google.com
            b. Example 3: sudo python3 pinger.py du.ac.bd

### NOTES ###
    - The code does not work with cs.stonybrook.edu and some URLs of university websites in Africa such as the University of Cape Town.
        - There may be other university URLs that this program might not work with.
    - "Work With" -> Request Timeout