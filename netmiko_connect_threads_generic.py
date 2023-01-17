# Importing Netmiko modules
import csv
import timeit

import netmiko
import textfsm
from netmiko import Netmiko, NetMikoAuthenticationException, NetMikoTimeoutException

# Additional modules imported for getting password, pretty print
import getpass
import signal

# Queuing and threading libraries
from queue import Queue
import threading

# Ask input for username.
username = input('Username: ')
# Ask input for user password. Getpass obscures input.
password = getpass.getpass(prompt='Password: ')
# If your switch secret is different that your connection password, uncomment the secret = getpass.getpass line.
secret = password
# secret = getpass.getpass(prompt='Password: ')


# Set up thread count for number of threads to spin up
num_threads = 8
# This sets up the queue
enclosure_queue = Queue()
# Set up thread lock so that only one thread prints at a time
print_lock = threading.Lock()
# Global failed devices variable
failed_devices = []
# Captures errors related to ctrl+c.
signal.signal(signal.SIGINT, signal.SIG_DFL)  # KeyboardInterrupt: Ctrl-C
# Change this variable to change the name of the spreadsheet you'd like to use.
network_filename = "network_IP.csv"


def get_csv(filename):
    # Create blank list to hold our csv information.
    networklist = []
    # Iterate through csv file, and append information to our newly created list.
    with open(filename, newline='') as csvfile:
        networkcsv = csv.reader(csvfile, delimiter=' ', quotechar='|')
        for row in networkcsv:
            networklist.append(''.join(row))
    return networklist


def netmiko_connector(inner_thread, inner_enclosure_queue):
    # Sets up the initial threads and prints the information for each switch that is put into a thread.
    while True:
        print("{}: Waiting for IP address...\n".format(inner_thread))
        ip = inner_enclosure_queue.get()
        print("{}: Acquired IP: {}\n".format(inner_thread, ip))
        # Our netmiko dictionary that gets populated from our thread information.
        device_dict = {
            'host': ip,
            'username': username,
            'password': password,
            'secret': password,
            'device_type': 'cisco_ios'
        }
        # Start a timer to see how long the changes take on this device.
        start_time = timeit.default_timer()
        # Try to connect to the device.
        try:
            nc = Netmiko(**device_dict)
            # Basic check for C9500's, or 3560X's as our hostnames would contains this information and we don't want
            # them changed.
            if '3560X' or 'C9500' in ip:
                failed_devices.append(ip + ' - Unsupported device.')
                inner_enclosure_queue.task_done()
                continue
            # Enable access o nthe switch.
            nc.enable()
        # Below are a series of error handling exceptions to ensure our threads don't become locked by a switch that
        # fails for some reason. This failed devices gets appened to a failed device readout.
        except NetMikoTimeoutException:
            with print_lock:
                print("\n{}: ERROR: Connection to {} timed-out.\n".format(inner_thread, ip))
            inner_enclosure_queue.task_done()
            failed_devices.append(ip + " - Timed Out")
            continue
        except NetMikoAuthenticationException:
            with print_lock:
                print("\n{}: ERROR: Authentication failed for {}. Stopping script. \n".format(inner_thread, ip))
            inner_enclosure_queue.task_done()
            failed_devices.append(ip + " - Authentication Error")
            continue
        # A generic exception to catch all other non-specific issues to not lock up our threads.
        except Exception as e:
            with print_lock:
                print("\n{}: ERROR: Something failed for {}. Stopping script. \n".format(inner_thread, ip))
            inner_enclosure_queue.task_done()
            failed_devices.append(ip + " - Generic Error: " + e)
            continue
        # Take hostname from switch via find_prompt()
        hostname = nc.find_prompt()
        # Cut off the last character on the hostname from the prompt. Usually "#" or ">".
        hostname = hostname[:-1]
        # Set up our lists to hold our valid ports, and trunk ports.
        valid_ports = []
        valid_tports = []
        # Try sending commands to the switch to pull all relevant data from the switchports. Parsed via textfsm. Failed
        # devices are entered into the failed_devices global list.
        try:
            switch_ports = nc.send_command('show interface switchport', use_textfsm=True)
            switch_count = nc.send_command('show switch detail', use_textfsm=True)
        except netmiko.exceptions.ReadTimeout:
            failed_devices.append(ip + " - unable to acquire switch portcount or detail. Console timeout.")
            inner_enclosure_queue.task_done()
            continue
        # Closing thread if there's a textFSM error.
        except textfsm.parser.TextFSMError:
            failed_devices.append(ip + " - unable to parse to textFSM. Device may be unsupported.")
            inner_enclosure_queue.task_done()
            continue
        # Capture any netmiko errors to provide more specificity in issues.
        except netmiko.exceptions as netmikoerror:
            failed_devices.apped(f"{ip} - {netmikoerror!r} - netmiko error. Device failed getting port info.")
            inner_enclosure_queue.task_done()
            continue
        # Generic error to prevent thread getting locked for anything else that may fail.
        except Exception as e:
            failed_devices.append(f"{ip} - {e!r}  - Device failed getting port info.")
            inner_enclosure_queue.task_done()
            continue

        # Find all of the explicitly defined access ports. This example collects all of our defined access ports,
        # and all of our defined trunk ports.
        for port in switch_ports:
            if port['admin_mode'] == 'static access':
                valid_ports.append(port['interface'])
            if port['admin_mode'] == 'trunk':
                valid_tports.append(port['interface'])
        # Prints out switch info based on ports found on device, and how many switches in the stack.
        switch_info = (f"""{hostname}:
Switches in stack are: {str(len(switch_count))}
Amount of Switch Ports targeted is: {str(len(valid_ports))}
Amount of Trunk Ports is: {str(len(valid_tports))}
""")
        # This policy map information has been made generic for security purposes. But this config set can contain
        # anything that may be required to configure the switch at the "configure terminal" level.
        policymap_configset = ['policy-map Generic-Policy-Map',
                               'no class Silver',
                               'no class Bronze',
                               'no class Gold',
                               'no class class-default',
                               'exit',
                               ]
        # Print Lock to ensure there's no conflicts for output.
        with print_lock:
            print(switch_info)
        # Initialize config set list that will be built programatically.
        config_set = []
        # More print locks to echo what work is being done within the thread.
        with print_lock:
            print("Building config for ", hostname, ".")
        # Begin to build our list for targetted access ports.
        for access_port in valid_ports:
            config_set.append('interface ' + access_port)
            # Pull current config on network port.
            port_check = nc.send_command("show run int " + access_port)
            # This is a check for the currently targetted access port for service policies
            for lines in port_check.splitlines():
                if "service-policy input" in lines:
                    config_set.append("no service-policy input Generic-Policy-Map")
                if "service-policy output" in lines:
                    config_set.append("no service-policy output Generic-Policy-Map")
            # -----------------------------------------
            # If you add a command inside of "config_set.append" here, it will run it
            # config_set.append("service-policy input Generic-Policy-Map 2")
            # _________________________________________
        for trunk_port in valid_tports:
            config_set.append('interface ' + trunk_port)
            # Pull current config on network port.
            port_check = nc.send_command("show run int " + trunk_port)
            # This is a check for the currently targetted trunk port for service policies
            for lines in port_check.splitlines():
                if "service-policy input" in lines:
                    config_set.append("no service-policy input Generic-Policy-Map")
                if "service-policy output" in lines:
                    config_set.append("no service-policy output Generic-Policy-Map")
            config_set.append("exit")
        print("Applying config to ports on " + hostname + ".")

        # Try sending config set that was build for the switches targetted ports.
        try:
            nc.send_config_set(config_set)
        # More error handling to not lock our threads.
        except netmiko.exceptions.ReadTimeout:
            failed_devices.append(ip + " - unable to complete config set. Console timeout. Please retry.")
            inner_enclosure_queue.task_done()
            continue

        print("Removing policymap on ", hostname)
        try:
            nc.send_config_set(policymap_configset)
        except netmiko.exceptions.ReadTimeout:
            failed_devices.append(ip + " - unable to complete policy map removal. Console timeout. Please retry.")
            inner_enclosure_queue.task_done()
            continue
        except netmiko.exceptions as netmikoerror:
            failed_devices.append(f"{ip} failed due to netmiko error: {netmikoerror!r}.")
            inner_enclosure_queue.task_done()
            continue
        # Print out elapsed time for thread and how long switch took to complete searching/applying config
        elapsed = timeit.default_timer() - start_time

        with print_lock:
            print(hostname, "config complete!")
            print(hostname, " took ", elapsed, " seconds to complete.")
        # --------------------------------------------------------------------------------------------
        # Save config on switch. Comment this out if you don't want automated changes to be permanent!
        # --------------------------------------------------------------------------------------------
        try:
            nc.send_command("wr", read_timeout=25)
        except netmiko.exceptions.ReadTimeout:
            failed_devices.append(ip + " - unable to write memory. Console timeout. Please write manually.")
            inner_enclosure_queue.task_done()
            continue

        nc.disconnect()
        inner_enclosure_queue.task_done()


if __name__ == '__main__':
    # Setting up threads based on number set above
    for i in range(num_threads):
        # Create the thread using 'netmiko_connector' as the function, passing in
        # the thread number and queue object as parameters
        thread = threading.Thread(target=netmiko_connector, args=(i, enclosure_queue,))
        # Set the thread as a background daemon/job
        thread.setDaemon(True)
        # Start the thread
        thread.start()
    # Call the get_csv function to bring in our spreadsheet.
    network_list = get_csv(network_filename)
    # Goes through our gathered CSV file.
    for ip_addr in network_list:
        enclosure_queue.put(ip_addr)

    # Wait for all tasks in the queue to be marked as completed (task_done)
    enclosure_queue.join()

    # Print out any failed devices collected from within the threads and added to global failed_devices list.
    # This also prints out any exception errors that were captured as well.
    if failed_devices:
        with print_lock:
            print("The following devices have failed:")
        for device in failed_devices:
            with print_lock:
                print(device)

    print("*** Script complete ***")
