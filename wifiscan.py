from who_is_on_my_wifi import *
import time
import logging


def scan():
    devices = who()
    for d in devices:
        print(d)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print("Start scanning")

    while 1:
        scan()
        time.sleep(10)
        print(" ")
