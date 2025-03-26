import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import logging
import socket
import threading
import traceback
from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSlaveContext, ModbusSequentialDataBlock, ModbusServerContext
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException

class ModbusTrafficGenerator:
    def __init__(self, master):
        self.master = master
        master.title("MS_Modbus")
        master.geometry("700x700")

        # Configure logging
        self.setup_logging()

        # Create Notebook (Tabbed Interface)
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)

        # Create tabs
        self.create_tabs()

        # Add credit label at the bottom
        credit_label = ttk.Label(master, text="Modbus Traffic Generator - Made by AHCHOUCH", 
                               font=('Arial', 8), foreground='gray')
        credit_label.pack(side=tk.BOTTOM, pady=5)

        # Server management
        self.slave_server_thread = None
        self.slave_server_stop_event = threading.Event()

    def setup_logging(self):
        """Configure logging to file and console"""
        # Create logger with credit
        self.logger = logging.getLogger('MS_Modbus')
        self.logger.setLevel(logging.DEBUG)

        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # Create file handler
        try:
            file_handler = logging.FileHandler('modbus_traffic_generator.log')
            file_handler.setLevel(logging.DEBUG)
        except PermissionError:
            messagebox.showwarning("Logging Warning", 
                "Could not create log file. Logging will be console-only.")
            file_handler = logging.NullHandler()

        # Create formatters with credit
        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s - MS_Modbus')
        file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        # Add formatters to handlers
        console_handler.setFormatter(console_formatter)
        file_handler.setFormatter(file_formatter)

        # Add handlers to logger
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

    def create_tabs(self):
        """Create all tabs for the application"""
        # Create tab frames
        self.master_frame = ttk.Frame(self.notebook)
        self.slave_frame = ttk.Frame(self.notebook)
        self.help_frame = ttk.Frame(self.notebook)

        # Add tabs to notebook
        self.notebook.add(self.master_frame, text="Master (Client)")
        self.notebook.add(self.slave_frame, text="Slave (Server)")
        self.notebook.add(self.help_frame, text="Help")

        # Create each tab's content
        self.create_master_tab()
        self.create_slave_tab()
        self.create_help_tab()

    def create_master_tab(self):
        """Create Master (Client) tab"""
        # Use grid layout for better organization
        frame = self.master_frame
        frame.grid_columnconfigure(1, weight=1)

        # Server Connection Details
        ttk.Label(frame, text="Slave Server IP:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.ip_entry = ttk.Entry(frame, width=50)
        self.ip_entry.insert(0, "localhost")
        self.ip_entry.grid(row=0, column=1, sticky='ew', padx=5, pady=5)

        ttk.Label(frame, text="Server Port:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.port_entry = ttk.Entry(frame, width=50)
        self.port_entry.insert(0, "1503")
        self.port_entry.grid(row=1, column=1, sticky='ew', padx=5, pady=5)

        # Modbus Request Configuration
        ttk.Label(frame, text="Function Code:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.func_code_combo = ttk.Combobox(frame, 
            values=[1, 3, 6], 
            width=47,
            state="readonly"
        )
        self.func_code_combo.set(3)
        self.func_code_combo.grid(row=2, column=1, sticky='ew', padx=5, pady=5)

        ttk.Label(frame, text="Register Address:").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        self.address_entry = ttk.Entry(frame, width=50)
        self.address_entry.insert(0, "0")
        self.address_entry.grid(row=3, column=1, sticky='ew', padx=5, pady=5)

        ttk.Label(frame, text="Data (Write only):").grid(row=4, column=0, sticky='w', padx=5, pady=5)
        self.data_entry = ttk.Entry(frame, width=50)
        self.data_entry.insert(0, "123")
        self.data_entry.grid(row=4, column=1, sticky='ew', padx=5, pady=5)

        # Send Request Button
        self.send_button = ttk.Button(
            frame, 
            text="Send Modbus Request", 
            command=self.send_modbus_request
        )
        self.send_button.grid(row=5, column=0, columnspan=2, pady=10)

        # Log Display
        ttk.Label(frame, text="Master Logs:").grid(row=6, column=0, columnspan=2, sticky='w', padx=5)
        self.master_log_display = scrolledtext.ScrolledText(
            frame, 
            height=10, 
            width=80, 
            wrap=tk.WORD
        )
        self.master_log_display.grid(row=7, column=0, columnspan=2, padx=5, pady=5)

    def create_slave_tab(self):
        """Create Slave (Server) tab"""
        frame = self.slave_frame
        frame.grid_columnconfigure(1, weight=1)

        # Server Configuration
        ttk.Label(frame, text="Bind IP:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.slave_ip_entry = ttk.Entry(frame, width=50)
        self.slave_ip_entry.insert(0, "localhost")
        self.slave_ip_entry.grid(row=0, column=1, sticky='ew', padx=5, pady=5)

        ttk.Label(frame, text="Bind Port:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.slave_port_entry = ttk.Entry(frame, width=50)
        self.slave_port_entry.insert(0, "1503")
        self.slave_port_entry.grid(row=1, column=1, sticky='ew', padx=5, pady=5)

        # Initial Register Configuration
        ttk.Label(frame, text="Initial Coil Values:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.slave_coil_entry = ttk.Entry(frame, width=50)
        self.slave_coil_entry.insert(0, "0,0,0,0,0")
        self.slave_coil_entry.grid(row=2, column=1, sticky='ew', padx=5, pady=5)

        ttk.Label(frame, text="Initial Holding Registers:").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        self.slave_holding_entry = ttk.Entry(frame, width=50)
        self.slave_holding_entry.insert(0, "100,200,300,400,500")
        self.slave_holding_entry.grid(row=3, column=1, sticky='ew', padx=5, pady=5)

        # Server Control Buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)

        self.start_server_button = ttk.Button(
            button_frame, 
            text="Start Slave Server", 
            command=self.start_slave_server
        )
        self.start_server_button.pack(side=tk.LEFT, padx=5)

        self.stop_server_button = ttk.Button(
            button_frame, 
            text="Stop Slave Server", 
            command=self.stop_slave_server,
            state=tk.DISABLED
        )
        self.stop_server_button.pack(side=tk.LEFT, padx=5)

        # Log Display
        ttk.Label(frame, text="Slave Logs:").grid(row=5, column=0, columnspan=2, sticky='w', padx=5)
        self.slave_log_display = scrolledtext.ScrolledText(
            frame, 
            height=10, 
            width=80, 
            wrap=tk.WORD
        )
        self.slave_log_display.grid(row=6, column=0, columnspan=2, padx=5, pady=5)

    def create_help_tab(self):
        """Create Help tab with usage instructions"""
        frame = self.help_frame
        
        # Use a text widget for scrollable help content
        help_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=80, height=30)
        help_text.pack(padx=10, pady=10, expand=True, fill=tk.BOTH)

        # Help content with credit
        help_content = """
        MS_Modbus Traffic Generator - Help Guide

        1. Modbus Basics
        ---------------
        Modbus is a communication protocol used in industrial automation.
        - Master (Client): Sends requests to a Slave
        - Slave (Server): Responds to Master's requests

        2. Slave (Server) Tab
        --------------------
        - Configure Server IP and Port
        - Set initial Coil and Holding Register values
        - Start the Slave Server before sending requests

        3. Function Codes
        ----------------
        - 1: Read Coils (Digital Outputs)
        - 3: Read Holding Registers (Analog Outputs)
        - 6: Write Single Register

        4. Master (Client) Tab
        ---------------------
        - Enter Slave Server's IP and Port
        - Select Function Code
        - Specify Register Address
        - For Write requests, provide Data value

        5. Logging
        ----------
        - Logs are displayed in each tab
        - Detailed logs are saved in 'modbus_traffic_generator.log'

        6. Common Issues
        ---------------
        - Ensure Slave Server is running before sending requests
        - Check IP and Port configurations
        - Verify network connectivity

        7. Troubleshooting
        -----------------
        - Check console or log file for detailed error messages
        - Verify Modbus device compatibility

        This tool was developed for Modbus protocol testing and demonstration.
        """

        help_text.insert(tk.END, help_content)
        help_text.config(state=tk.DISABLED)  # Make read-only

    def start_slave_server(self):
        """Start Modbus TCP slave server in a separate thread"""
        try:
            # Validate inputs
            slave_ip = self.slave_ip_entry.get()
            slave_port = int(self.slave_port_entry.get())
            
            # Parse register values
            coil_values = [int(x) for x in self.slave_coil_entry.get().split(',')]
            holding_values = [int(x) for x in self.slave_holding_entry.get().split(',')]

            # Reset stop event
            self.slave_server_stop_event.clear()

            def run_server():
                try:
                    # Create slave context
                    store = ModbusSlaveContext(
                        di=ModbusSequentialDataBlock(0, [0] * 100),
                        co=ModbusSequentialDataBlock(0, coil_values),
                        hr=ModbusSequentialDataBlock(1, holding_values),
                        ir=ModbusSequentialDataBlock(0, [0] * 100)
                    )
                    context = ModbusServerContext(slaves=store, single=True)

                    # Log server start
                    self.slave_log(f"Starting Slave Server on {slave_ip}:{slave_port}")
                    
                    # Start server
                    StartTcpServer(context, address=(slave_ip, slave_port))

                except Exception as e:
                    self.slave_log(f"Server Start Error: {e}")
                    self.logger.error(f"Slave Server Error: {traceback.format_exc()}")
                finally:
                    # Update UI
                    self.master.after(0, self.on_server_stop)

            # Start server thread
            self.slave_server_thread = threading.Thread(target=run_server, daemon=True)
            self.slave_server_thread.start()

            # Update UI
            self.start_server_button.config(state=tk.DISABLED)
            self.stop_server_button.config(state=tk.NORMAL)

        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
            self.logger.error(f"Input Error: {e}")

    def stop_slave_server(self):
        """Attempt to stop the slave server"""
        try:
            # Set stop event
            self.slave_server_stop_event.set()
            
            # Wait for thread to terminate
            if self.slave_server_thread:
                self.slave_server_thread.join(timeout=2)
                self.slave_log("Slave Server Stopped")

        except Exception as e:
            self.slave_log(f"Server Stop Error: {e}")
            self.logger.error(f"Server Stop Error: {traceback.format_exc()}")
        finally:
            self.on_server_stop()

    def on_server_stop(self):
        """Handle UI updates when server stops :)"""
        self.start_server_button.config(state=tk.NORMAL)
        self.stop_server_button.config(state=tk.DISABLED)

    def send_modbus_request(self):
        """Send Modbus request from Master tab"""
        try:
            # Validate inputs
            ip = self.ip_entry.get()
            port = int(self.port_entry.get())
            function_code = int(self.func_code_combo.get())
            address = int(self.address_entry.get())
            data = int(self.data_entry.get()) if self.data_entry.get() else None

            # Create Modbus client
            client = ModbusTcpClient(host=ip, port=port)
            
            # Attempt connection
            if not client.connect():
                self.master_log(f"Connection to {ip}:{port} failed")
                self.logger.error(f"Connection failed to {ip}:{port}")
                return

            # Process request based on function code
            try:
                if function_code == 1:  # Read Coils
                    response = client.read_coils(address, count=1)
                    self.master_log(f"Read Coils at {address}: {response.bits}")
                elif function_code == 3:  # Read Holding Registers
                    response = client.read_holding_registers(address, count=1)
                    self.master_log(f"Read Holding Registers at {address}: {response.registers}")
                elif function_code == 6:  # Write Single Register
                    if data is not None:
                        response = client.write_register(address, data)
                        self.master_log(f"Write Register at {address} with value {data}")
                    else:
                        self.master_log("Data required for Write Register")
                        return

                # Check for Modbus errors
                if response.isError():
                    self.master_log(f"Modbus Error: {response}")
                    self.logger.error(f"Modbus Error: {response}")

            except ModbusException as e:
                self.master_log(f"Modbus Protocol Error: {e}")
                self.logger.error(f"Modbus Protocol Error: {traceback.format_exc()}")
            except Exception as e:
                self.master_log(f"Request Error: {e}")
                self.logger.error(f"Request Error: {traceback.format_exc()}")
            finally:
                client.close()

        except ValueError as e:
            messagebox.showerror("Input Error", "Please enter valid numeric values.")
            self.logger.error(f"Input Error: {e}")
        except Exception as e:
            self.master_log(f"Unexpected Error: {e}")
            self.logger.error(f"Unexpected Error: {traceback.format_exc()}")

    def master_log(self, message):
        """Log messages to the master log widget"""
        self.master_log_display.insert(tk.END, f"{message}\n")
        self.master_log_display.see(tk.END)
        self.logger.info(f"[Master] {message}")

    def slave_log(self, message):
        """Log messages to the slave log widget"""
        self.slave_log_display.insert(tk.END, f"{message}\n")
        self.slave_log_display.see(tk.END)
        self.logger.info(f"[Slave] {message}")

def main():
    root = tk.Tk()
    # Set a modern theme if available
    try:
        root.tk.call('source', 'azure.tcl')
        root.tk.call('set_theme', 'light')
    except:
        pass
    
    app = ModbusTrafficGenerator(root)
    root.mainloop()

if __name__ == "__main__":
    main()