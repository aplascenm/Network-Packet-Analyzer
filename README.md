# Network Packet Analyzer

A simple **Network Packet Analyzer** written in **C++** using the **libpcap** library.

This tool analyzes previously captured network packets using a network protocol analyzer. Please ensure that the files are in the .bin format. 

This software can be used for learning about packet structures and basic protocol handling.

## Features

Analyzes network packets previously captured
Parse common protocols (Ethernet, ARP, IPv4/IPv6, ICMP, etc.)
Simple and educational implementation for understanding packet processing

## Stack

- **C++**
- **libpcap** (packet capture library)

Developed as a learning project to explore raw packet analysis

## Getting Started

### Prerequisites

Before building the project, make sure you have:

- A C++ compiler

- `libpcap` installed on your system

- A .bin file. You can capture your own packets or you can download samples from: https://wiki.wireshark.org/SampleCaptures

On Debian-based systems you can install libpcap with:

```bash
sudo apt update
sudo apt install libpcap-dev
```

## Running the program
```bash
g++ main.cpp -lpcap
```
The program then will ask you to input the name of the file. The file needs to be inside the project folder.
