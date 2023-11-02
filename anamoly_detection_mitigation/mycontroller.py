#!/usr/bin/env python3
import argparse
import os
import sys
import time
import datetime
from time import sleep

import grpc

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections


def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.
    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, the tunnel ID)
    """
    with open("example.txt", "a") as f:

        for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
            for entity in response.entities:
                counter = entity.counter_entry
                ts=datetime.datetime.now()
                print("timestamp", ts, file=f)
                print(" %s %s %d: %d packets (%d bytes)"  % (
                        sw.name, counter_name, index,
                        counter.data.packet_count, counter.data.byte_count
                        ), file=f)


def updateCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.
    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, the tunnel ID)
    """
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            if counter.data.packet_count==100:
                counter.data.packet_count=0
                counter.data.byte_count=0
            else:
                print("%s %s %d: %d packets (%d bytes)" % (
                        sw.name, counter_name, index,
                        counter.data.packet_count, counter.data.byte_count
                        ))


def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        print("Register id", p4info_helper.get_registers_id("MyEgress.pkt_counter"))
        print("Global Register id", p4info_helper.get_registers_id("behave_states"))

        #s1.writeCounters(p4info_helper.get_counters_id("MyIngress.port_counter"), 2)
        """print("%s %s: %d packets (%d bytes)" % (
                        s1, behave_states,
                        counter.data.packet_count, counter.data.byte_count
                        )) """
        #s1.ReadRegisters(p4info_helper.get_registers_id("behave_states"))

                # Print the tunnel counters every 2 seconds
        while True:
            sleep(2)
            print('\n----- Reading ingress port counters -----')
            #printCounter(p4info_helper, s1, "MyIngress.port_counter", 2)
            printCounter(p4info_helper, s1, "MyIngress.port_counter", 1)
            printCounter(p4info_helper, s1, "MyIngress.port_counter", 2)
            printCounter(p4info_helper, s1, "MyIngress.port_counter", 3)
            printCounter(p4info_helper, s1, "MyIngress.port_counter", 5)
            #printCounter(p4info_helper, s2, "MyIngress.port_counter", 100)

            # with open("example.txt", "w") as f:
            #     for word in words:
            #          f.write(word)

            #print('\n----- Reading egress port counters -----')
            #printCounter(p4info_helper, s1, "MyIngress.port_counter", 2)
            printCounter(p4info_helper, s1, "MyEgress.egress_port_counter", 3)
            #printCounter(p4info_helper, s2, "MyIngress.port_counter", 100)



    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/mri.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/mri.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
