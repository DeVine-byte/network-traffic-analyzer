# Network Traffic Analyzer
=======================

Copyright 2024 [Oghosa Divine Osaigbovo]

Licensed under the GNU General Public License, version 3

## Description
This project captures network traffic, decodes packets, and provides insightful analyses through visualizations. It utilizes the `pyshark` and `dpkt` libraries for capturing and decoding network packets, and `pandas` and `matplotlib` for data analysis and visualization.

## Features
- Captures network traffic from a specified interface.
- Decodes captured packets.
- Provides visualizations for protocol distribution and packet size distribution.
- Displays top TCP and UDP talkers.

## Requirements
Make sure you have the following Python libraries installed:

- `pyshark`
- `dpkt`
- `pandas`
- `matplotlib`

You can install the required libraries using pip:

```bash
pip install -r requirements.txt

## Usage
 git clone https://github.com/DeVine-byte/network-traffic-analyzer.git
cd network-traffic-analyzer

## Run
sudo python analyzer.py

Enter the network interface you want to capture traffic on when prompted.

##License
This project is licensed under the GNU General Public License. See the LICENSE file for details.

##Author
Oghosa Divine Osaigbovo
