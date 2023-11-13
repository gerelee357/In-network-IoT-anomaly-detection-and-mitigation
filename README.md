# Overview

This repository contains the implementation of a real-time IoT anomaly detection and mitigation solution in a Software-Defined Networking (SDN) environment. 
The solution utilizes In-band Network telemetry (INT) data to address the challenges posed by vulnerable Internet of Things (IoT) devices, including their limited capabilities and susceptibility to attacks.

## Features

- Real-time Anomaly Detection: Utilizes INT data to detect IoT attacks in real-time, providing quick response to DDoS attacks.

- Low Detection Delay: Implemented directly within the data plane, ensuring real-time processing for every operation.

- High Detection Accuracy: Achieves high detection accuracy, enhancing the security posture of IoT devices within the network.

# Publication

I presented this research at the 12th International Conference on Applied Informatics (ICAI 2023) conference and it is accepted for publication in the Infocommunications journal [1].

- [1] Gereltsetseg Altangerel and Máté Tejfel. In-network DDoS detection and mitigation using int data for IoT ecosystem. Infocommunications Journal, Special Issue on Applied Informatics, 2023, pp. 49-54, 2023.
- https://doi.org/10.36244/ICJ.2023.5.8

# Getting Started

1. Building SDN environment with INT-enabled Network Devices according to building_p4_env.md.

2. Run the proposed application according to running_p4_applications.md. 





