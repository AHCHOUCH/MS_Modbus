a basic Modbus Traffic Generator

A Python-based GUI application for generating and testing Modbus TCP traffic, developed by Natsu.

 Features

- Master (Client) Functionality:
  - Send Modbus requests to slave devices
  - Supports function codes: 1 (Read Coils), 3 (Read Holding Registers), 6 (Write Single Register)
  - Configurable server IP and port
  - Real-time logging of requests and responses

- Slave (Server) Functionality:
  - Create a Modbus TCP slave server
  - Configurable bind IP and port
  - Set initial coil and holding register values
  - Start/stop server controls

- User-Friendly Interface:
  - Tabbed layout for easy navigation
  - Comprehensive help documentation
  - Real-time logging in both master and slave modes

 Requirements

- Python 3.6+
- Required packages:
  - pymodbus (>= 2.5.0)
  - tkinter (usually included with Python)

 Installation

1. Clone the repository or download the source files
2. Install the required packages

 Run
