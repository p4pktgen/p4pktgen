import logging
import os
import subprocess
import sys
import time

from scapy.all import *

from p4pktgen.p4_hlir import P4_HLIR
from p4pktgen.config import Config
from p4pktgen.switch.runtime_CLI import RuntimeAPI, PreType, thrift_connect, load_json_config
from p4pktgen.p4_hlir import SourceInfo


def logf_append(s):
    return    # Comment out this line to debug things with logf_append
    with open('/tmp/simple_switch-err-log.txt', 'a') as f:
        tmp = str('pid %d time %s ' % (os.getpid(), time.time()))
        f.write(tmp + s + '\n')


# The order of things here might seem a bit odd.  We agree.

# We want _not_ to have to run as the super-user root, and yet run
# test cases through simple_switch.  This means we must avoid using
# Ethernet interfaces, whether physical or virtual, because sending
# packets to those requires root privileges.  (Yes, it would be
# possible to create some little helper process that runs as root that
# only sends and receives packets, limiting the amount of code that
# needs to run as root, but that currently seems like more trouble
# than it is worth, and still requires the user to have root access.)

# simple_switch has a --use-files command line option that causes it
# to read input packets from pcap files, and write output packets to
# pcap files.  It does not require root privileges.

# What we want is to run simple_switch, add some table entries to one
# or more of its tables, and when the table entries are finished being
# added, only then start processing packets.

# Later we will also want to capture the output packets and check
# them, but we will save that for another day.

# One option is to run simple_switch with the command line option
# '--use-files 1', where 1 is the number of seconds that simple_switch
# will wait before starting to read the the pcap input files, during
# which you can do control plane operations to set up table entries.
# This is undesirable in that if you don't beat the deadline, packets
# could be processed before all table entries are set up.  We could
# pick a very long time, with the down side that simple_switch will
# always wait that amount of time before starting processing packets,
# even if table entries are set up long before that.

# Here is one way to set up table entries, then start processing
# packets, when running simple_switch the the '--use-files 0' command
# line option, which is what we are implementing here.  Some of the
# code for this approach was inspired by the program
# p4c/backends/bmv2/bmv2stf.py in the Github repository
# https://github.com/p4lang/p4c

# (1) Create named pipes for each input pcap file.  simple_switch
# expects these files to exist _very_ soon after it starts, and we
# don't want it to fail by racing it and losing that race.

# (2) Start simple_switch with '--use-files 0' and a separate '-i
# <number>@<name>' argument for each interface you want to run your P4
# program with.  We also open it as a child process with its output
# from its '--log-console' option being read by this program, so we
# can parse and check messages in that output.

# (3) Open all input pcap named pipes for writing, and write a pcap
# file header to it.  This is done in method open_pcap_in_intf()

# (4) Wait until we see the message 'Pcap reader: starting
# PcapFilesReader' in simple_switch's written to its console log.
# This is a basic level of initialization at which time it should be
# ready to accept adding table entries.

# (5) Open Thrift TCP connection to simple_switch's port where it is
# listening for control plane commands.

# (6) Send messages over the Thrift TCP connection to add the desired
# table entries.  In this program this is done via calls to methods
# table_add() and table_set_default().  Those methods are implemented
# by calling code from bmv2's simple_switch_CLI program, and I believe
# that they wait for a success or fail response from simple_switch_CLI
# for each one.  If so, this should indicate that the table
# modification is complete before the method called here returns.

# (7) Then send the packet by calling method
# send_and_check_only_1_packet().  Currently p4pktgen only sends 1
# packet per test case, but in general it could be more.

# An odd thing is that even if we do all of the flushing we want after
# writing a single small packet, simple_switch will not read the
# packet from the named pipe until after we close the named pipe.  I
# do not know the precise reasons for this, but suspect that if we
# wrote over one named pipe OS buffer's worth of packets,
# simple_switch would return before we close the named pipe.  If so,
# very likely the reason simple_switch doesn't process any packets
# until we close the pipe, when writing only 1 small packet, is that
# simple_switch's OS call to read packets is blocking until it gets a
# buffer's worth of data (e.g. maybe something like 4 Kbyte or 16
# Kbyte worth of data), or until the file is closed.

# I have done experiments trying unbuffered named pipe opening for
# writing in bmv2stf.py as well, and there also, simple_switch does
# not start processing any packets until bmv2stf.py closes the named
# pipes it creates.

# (8) Given the oddness of behavior mentioned just above, we must then
# close the named pipes in order for simple_switch to actually start
# processing the packets.  We do this now by closing all of the named
# pipes we opened in step (3), during step (7), inside method
# send_and_check_only_1_packet().

# (9) Later, if we want to check all output packets, we will probably
# need to have a 1 or several-second sleep call here, to have some
# kind of likelihood that we have collected all of the output packets
# that simple_switch has generated.  If simple_switch had a way to
# query it and ask "Hey, are you still planning to generate any more
# output packets?", with a response of "yes, I have completely
# processed all packets I have received, and here is how many I have
# received." or "No, I'm not done with the packets I have received up
# until now.", then we could avoid such a sleep call, but I don't
# think simple_switch has anything like that.  Such an approach would
# work for other P4 implementations, too, and likely they also do not
# have a convenient way to query whether they are done or not.  This
# is a common issue with black box testing of computer systems, so
# nothing unique to simple_switch here.

class SimpleSwitch:

    def __init__(self, json_file, folder, num_ports=8):
        self.modified_tables = []

        self.json_file = json_file
        self.json_file_abspath = os.path.abspath(json_file)
        self.num_ports = num_ports
        self.pcap_filename_prefix = 'pcap'

        # TBD: See bmv2stf.py for ideas on running multiple
        # simple_switch processes in parallel on the same machine.
        # This code does not support that yet.
        self.folder = folder
        self.thrift_port_num = 9090

        # See step (1) above
        intf_args = []
        self.intf_info = {}
        for i in range(self.num_ports):
            intf_args.append('-i')
            intf_args.append(self.intf_num_to_simple_switch_arg(i))
            self.intf_info[i] = {
                'pcap_in_fname': self.intf_num_to_filename(i, 'in'),
                'pcap_out_fname': self.intf_num_to_filename(i, 'out')}
            logging.debug("Creating named pipe '%s'"
                          "" % (self.intf_info[i]['pcap_in_fname']))
            os.mkfifo(self.intf_info[i]['pcap_in_fname'])

        # Workaround for problem that I have only seen on some
        # systems, but not others, for reasons that I don't
        # understand.  The symptom of the problem is that when running
        # pytest, even as root, multiple of the test cases fail with
        # "Exception: Initializing simple_switch failed", and the
        # following output labeled "Captured stderr call".

        # Nanomsg returned a exception when trying to bind to address 'ipc:///tmp/bmv2-0-notifications.ipc'.
        # The exception is: Address already in use
        # This may happen if
        # 1) the address provided is invalid,
        # 2) another instance of bmv2 is running and using the same address, or
        # 3) you have insufficent permissions (e.g. you are using an IPC socket on Unix, the file already exists and you don't have permission to access it)

        # I have tried adding debug messages to a few places in the
        # simple_switch executable to discover why this failure
        # occurs, but haven't discovered a reason for it.  Removing
        # this file seems to avoid the problem.
        ipc_fname = '/tmp/bmv2-0-notifications.ipc'
        if os.path.exists(ipc_fname):
            logf_append('Found file %s -- try to remove it' % (ipc_fname))
            os.remove('/tmp/bmv2-0-notifications.ipc')
            if os.path.exists(ipc_fname):
                logf_append('After trying to remove file %s it still exists'
                            '' % (ipc_fname))
            else:
                logf_append('File %s successfully removed' % (ipc_fname))
        else:
            logf_append('No file found: %s -- good' % (ipc_fname))

        # Start simple_switch.   See step (2) above.
        ss_cmd_args = (['simple_switch',
                        '--log-console',
                        '--thrift-port', str(self.thrift_port_num),
                        '--use-files', '0' ] +
                       intf_args + [self.json_file_abspath])
        logging.debug("Starting simple_switch in directory %s with args: %s"
                      "" % (self.folder, ss_cmd_args))
        self.proc = subprocess.Popen(ss_cmd_args, stdout=subprocess.PIPE,
                                     cwd=self.folder)

        # See step (3) above.
        # p4c/backends/bmv2/bmv2stf.py has scary-looking "DANGER"
        # comment about opening the named fifos in the same order that
        # simple_switch does, else things can deadlock.  Not sure why
        # deadlock might occur, but may as well do it the same order
        # here.
        for i in sorted(self.intf_info):
            self.open_pcap_in_intf(i)

        # Wait for simple_switch to finish initializing
        # See step (4) above.
        init_done = False
        ss_ready_msg = 'Pcap reader: starting PcapFilesReader'
        logging.debug("Waiting for this line of output from simple_switch: %s",
                      ss_ready_msg)
        for line in iter(self.proc.stdout.readline, ''):
            logging.debug("Line from simple_switch log: %s", line.rstrip())
            if ss_ready_msg in str(line):
                logging.debug("Found expected log line.  Considering"
                              " simple_switch initialized enough to continue")
                init_done = True
                break

        if not init_done:
            raise Exception('Initializing simple_switch failed')

        # See step (5) above.
        # XXX: read params from config
        pre = PreType.SimplePreLAG
        num_tries = 0
        while True:
            try:
                standard_client, mc_client = thrift_connect(
                    'localhost', str(self.thrift_port_num),
                    RuntimeAPI.get_thrift_services(pre))
            except:
                num_tries += 1
                time.sleep(1)
                logging.debug("Failed thrift_connect attempt try #%d"
                              "" % (num_tries))
                if num_tries == 3:
                    logging.error("Failed 3 times in a row. Giving up.")
                    sys.exit(1)
            else:
                break

        load_json_config(standard_client)
        self.api = RuntimeAPI(pre, standard_client, mc_client)

    def intf_num_to_simple_switch_name(self, intf_num):
        return "%s%d" % (self.pcap_filename_prefix, intf_num)

    def intf_num_to_filename(self, intf_num, direction):
        """Given an interface number from the perspective of the P4 program,
        e.g. 0, 1, 2, etc., and a direction 'in' (from the outside world
        to simple_switch) or 'out' (from simple_switch to the outside
        world), return the name of the pcap file that simple_switch reads
        (for 'in') or writes (for 'out').  Except for the prefix, this
        file name is determined by code inside of simple_switch."""

        return "%s/%s_%s.pcap" % (self.folder,
                                  self.intf_num_to_simple_switch_name(intf_num),
                                  direction)

    def intf_num_to_simple_switch_arg(self, intf_num):
        """This is the command line option to give to simple_switch, after a
        -i option, and after giving it the --use-files <seconds> option,
        that will cause it to use the filenames returned by
        intf_num_to_filename."""

        return "%d@%s" % (intf_num,
                          self.intf_num_to_simple_switch_name(intf_num))

    def intf_filename_to_num_direction(self, intf_filename):
        """The reverse direction transformation of method
        intf_num_to_filename."""

        assert (intf_filename[:len(self.pcap_filename_prefix)] ==
                self.pcap_filename_prefix)
        tmp = intf_filename[len(self.pcap_filename_prefix):]
        assert tmp[-5:] == ".pcap"
        tmp = tmp[:-5]
        match = re.match(r"(\d+)_(in|out)^$", tmp)
        assert match
        intf_num = int(match.group(1))
        direction = match.group(2)
        return intf_num, direction

    def open_pcap_in_intf(self, intf_num):
        tmp_fname = self.intf_info[intf_num]['pcap_in_fname']
        if os.path.exists(tmp_fname):
            logging.debug("File '%s' exists.  Good." % (tmp_fname))
        else:
            logging.debug("File '%s' does NOT exist.  BAD." % (tmp_fname))
        logging.debug("Opening file '%s' using RawPcapWriter()" % (tmp_fname))
        fp = RawPcapWriter(tmp_fname, linktype=0)
        logging.debug("Calling _write_header(None) on fp"
                      " returned by RawPcapWriter")
        fp._write_header(None)
        fp.flush()
        logging.debug("Calling fp.flush() after _writer_header(None)")
        self.intf_info[intf_num]['pcap_in_fp'] = fp

    def table_add(self, table, action, values, params, priority):
        self.modified_tables.append(table)
        priority_str = ""
        if priority:
            priority_str = " %d" % (priority)
        self.api.do_table_add(
            '{} {} {} => {}{}'.format(table, action, ' '.join(
                values), ' '.join([str(x) for x in params]), priority_str))

    def table_set_default(self, table, action, params):
        self.modified_tables.append(table)
        self.api.do_table_set_default('{} {} {}'.format(
            table, action, ' '.join([str(x) for x in params])))

    def clear_tables(self):
        """Clears all modified tables."""
        for table in self.modified_tables:
            self.api.do_table_clear(table)
        self.modified_tables = []

    def send_and_check_only_1_packet(self, packet, source_info_to_node_name):
        # TBD: Right now we always send packets into port 0 of
        # simple_switch.  Later should generalize to enable sending
        # packets into any of several ports.
        intf_num = 0
        logging.info('Sending packet to port {}'.format(intf_num))
        self.intf_info[intf_num]['pcap_in_fp']._write_packet(packet)
        for i in sorted(self.intf_info):
            self.intf_info[i]['pcap_in_fp'].flush()
            self.intf_info[i]['pcap_in_fp'].close()
        logging.debug('Finished _write_packet() to %s',
                      self.intf_info[intf_num]['pcap_in_fname'])

        # Extract the parse states from the simple_switch output
        extracted_path = []
        prev_match = None
        table_name = None
        for b_line in iter(self.proc.stdout.readline, b''):
            line = str(b_line)
            logging.debug("Line from simple_switch log: %s", line.strip())
            m = re.search(r'Parser state \'(.*)\'', line)
            if m is not None:
                extracted_path.append(m.group(1))
                prev_match = 'parser_state'
                continue
            m = re.search(r'Applying table \'(.*)\'', line)
            if m is not None:
                table_name = m.group(1)
                prev_match = 'table_apply'
                continue
            m = re.search(r'Action ([0-9a-zA-Z_.]*)$', line)
            if m is not None:
                if m.group(1) != 'add_header':
                    assert prev_match == 'table_apply'
                    extracted_path.append((table_name, m.group(1)))
                    prev_match = 'action'
                continue
            m = re.search(r'Exception while parsing: ([0-9a-zA-Z_]*)$', line)
            if m is not None:
                extracted_path.append(m.group(1))
                prev_match = 'parse_exception'
                continue
            m = re.search(
                r'\[cxt \d+\] (.*?)\((\d+)\) Condition "(.*)" (?:\((.*)\) )?is (.*)', line)
            if m is not None:
                filename = m.group(1)
                lineno = int(m.group(2))
                source_frag = m.group(3)
                condition_node_name = m.group(4)
                condition_value = m.group(5)
                if condition_node_name is not None:
                    node_name = condition_node_name
                else:
                    # If the node name is not in simple_switch's console
                    # log, try to map file name, line number, and source
                    # fragment back to a node name.  Give an error if
                    # there are duplicate occurrences of the same source
                    # info for different condition nodes in the bmv2 JSON
                    # file.
                    source_info = SourceInfo(filename, source_frag, lineno)
                    logging.debug("filename '%s' lineno=%d source_frag='%s'"
                                  "" % (filename, lineno, source_frag))
                    assert source_info in source_info_to_node_name
                    assert len(source_info_to_node_name[source_info]) > 0
                    node_names = source_info_to_node_name[source_info]
                    if len(node_names) > 1:
                        logging.error(
                            "JSON file contains multiple different conditions"
                            " with the same expression '%s' in the same file"
                            " '%s' on the same line %d."
                            "  It is not possible to convert simple_switch"
                            " log output lines back to unique node names."
                            "  Consider changing your P4 source code"
                            " to avoid this situation, or upgrade to a newer"
                            " version of p4lang/behavioral-model code that"
                            " includes unique node names in the console log"
                            " for condition evaluation lines."
                            "" % (source_frag, filename, lineno))
                        logging.error("Here is a list of all node names"
                                      " with the same source info: %s"
                                      "" % (', '.join(node_names)))
                        assert False
                    else:
                        node_name = node_names[0]
                assert condition_value == 'true' or condition_value == 'false'
                if condition_value == 'true':
                    condition_value = True
                else:
                    condition_value = False
                extracted_path.append((node_name, (condition_value,
                                                   (filename, lineno,
                                                    source_frag))))
                prev_match = 'condition'
                continue
            if 'Parser \'parser\': end' in line:
                extracted_path.append('sink')
                prev_match = 'parser_exception'
                continue
            m = re.search(r'Exception while parsing: PacketTooShort', line)
            if m is not None:
                extracted_path.append(P4_HLIR.PACKET_TOO_SHORT)
                prev_match = 'parser_packet_too_short'
                continue
            if 'Pipeline \'ingress\': end' in line:
                break

        # Ignore remaining output generated by the packet
        for b_line in iter(self.proc.stdout.readline, b''):
            line = str(b_line)
            logging.debug(line.strip())
            if 'Pipeline \'egress\': end' in line or 'Dropping packet at the end of ingress' in line:
                break

        return extracted_path

    def remove_file_if_exists(self, fname):
        if os.path.exists(fname):
            os.remove(fname)
            if os.path.exists(fname):
                logging.error("File '%s' should have been removed,"
                              " but still exists." % (fname))
                raise Exception("File not removed")
            else:
                logging.debug("File '%s' no longer exists after being removed."
                              "" % (fname))
        else:
            logging.debug("No file named '%s' to remove" % (fname))

    def shutdown(self):
        logging.debug("Killing simple_switch process")
        self.proc.kill()
        for i in sorted(self.intf_info):
            self.remove_file_if_exists(self.intf_info[i]['pcap_in_fname'])
            self.remove_file_if_exists(self.intf_info[i]['pcap_out_fname'])


# TBD: bmv2stf.py removes /tmp/bmv2-%d-notifications.ipc file when
# finished running simple_switch.  We should probably do the same, to
# clean up after ourselves.  Search for code that mentions this file
# name in bmv2stf.py
