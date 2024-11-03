# simple_IDS


DESCRIPTION : 

This project is a simple Intrusion Detection System (IDS) that monitors network traffic in real time, aiming to detect potential security threats like Distributed Denial of Service (DDoS) attacks. It captures packets using the PyShark library, analyzes key packet attributes (such as source and destination IP addresses and protocol type), and flags traffic that fits the profile of known threat patterns. 

When a potential threat is detected, the IDS logs an alert into an SQLite database with relevant details, including timestamps, source and destination IPs, and threat type. The database creates a persistent record of detected threats, making it easy to analyze or retrieve information on past network activity.

This project offers foundational insight into network security, packet analysis, and database logging, making it a useful starting point for learning about cybersecurity and data monitoring techniques. It’s simple enough to demonstrate key principles but versatile enough to expand upon, allowing for more complex threat detection and data visualization in future iterations.
