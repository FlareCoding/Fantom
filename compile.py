import os

if __name__ == "__main__":
    os.system("g++ -c main.c")
    os.system("g++ -c network/local_net_data.c")
    os.system("g++ -c network/utils.c")
    os.system("g++ -c network/arp.c")
    os.system("g++ -c network/network.c")

    os.system("g++ -pthread network.o arp.o local_net_data.o utils.o main.o -o fantom")

    os.system("rm network.o")
    os.system("rm arp.o")
    os.system("rm local_net_data.o")
    os.system("rm utils.o")
    os.system("rm main.o")

