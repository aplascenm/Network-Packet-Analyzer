#Network Packet Analyzer

A simple Network Packet Analyzer written in C++ using the libpcap library.

This tool captures and analyzes network packets from a selected interface. It can be used for learning about packet structures and basic protocol handling.

##Features

Capture network packets from an interface
Parse common protocols (Ethernet, ARP, IPv4/IPv6, ICMP, etc.)
Simple and educational implementation for understanding packet processing


##Stack

C++

libpcap (packet capture library)

Developed as a learning project to explore raw packet analysis

##Getting Started

###Prerequisites

Before building the project, make sure you have:

A C++ compiler

libpcap installed on your system

On Debian-based systems you can install libpcap with:

sudo apt update
sudo apt install libpcap-dev
