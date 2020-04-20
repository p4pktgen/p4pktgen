import os
import logging
import tempfile

from enum import Enum

from collections import OrderedDict

from p4pktgen.config import Config
from p4pktgen.switch.simple_switch import SimpleSwitch


TestPathResult = Enum(
    'TestPathResult',
    'SUCCESS NO_PACKET_FOUND TEST_FAILED UNINITIALIZED_READ INVALID_HEADER_WRITE PACKET_SHORTER_THAN_MIN'
)


# TBD: There is probably a better way to convert the params from
# whatever type they are coming from the SMT solver, to something that
# can be written out as JSON.  This seems to work, though.
def model_value_to_long(model_val):
    try:
        return long(str(model_val))
    except ValueError:
        # This can happen when trying to convert values that are
        # actually still variables in the model.  For example, when a
        # key in a table is used that way, without first being
        # initialized.
        return None


def source_info_to_dict(source_info):
    if source_info is None:
        return None
    return OrderedDict(
        [('filename', source_info.filename), ('line', source_info.line),
         ('column', source_info.column), ('source_fragment',
                                          source_info.source_fragment)])


def table_set_default_cmd_string(table, action, params):
    return ('{} {} {}'.format(table, action,
                              ' '.join([str(x) for x in params])))


def table_add_cmd_string(table, action, values, params, priority):
    priority_str = ""
    if priority:
        priority_str = " %d" % (priority)
    return ('{} {} {} => {}{}'.format(table, action, ' '.join(values),
                                      ' '.join([str(x) for x in params]),
                                      priority_str))


class TestCaseBuilder(object):
    def __init__(self, json_file, pipeline):
        if Config().get_run_simple_switch():
            self.json_file = json_file
        else:
            self.json_file = None
        self.pipeline = pipeline

    def build(self, context, model, sym_packet, expected_path,
              parser_path, control_path, is_complete_control_path,
              source_info_to_node_name, count):
        packet_hexstr = None
        payload = None
        ss_cli_setup_cmds = []
        table_setup_cmd_data = []
        uninitialized_read_data = None
        invalid_header_write_data = None
        actual_path_data = None
        result = None

        if model is not None:
            payload = sym_packet.get_payload_from_model(model)

            # Determine table configurations
            table_configs = []
            for t in control_path:
                table_name = t.src
                transition = t
                if table_name in self.pipeline.tables \
                        and context.has_table_values(table_name):
                    runtime_data_values = []
                    for i, runtime_param in enumerate(
                            transition.action.runtime_data):
                        runtime_data_values.append(
                            (runtime_param.name,
                             model[context.get_table_runtime_data(table_name, i)]))
                    table_key_values = context.get_table_key_values(
                        model, table_name)

                    table = self.pipeline.tables[table_name]
                    table_key_values_strs = []
                    table_key_data = []
                    table_entry_priority = None
                    for table_key, table_key_value in zip(
                            table.key, table_key_values):
                        key_field_name = '.'.join(table_key.target)
                        sym_table_value_long = model_value_to_long(
                            table_key_value)
                        if table_key.match_type == 'lpm':
                            bitwidth = context.get_header_field_size(
                                table_key.target[0], table_key.target[1])
                            table_key_values_strs.append(
                                '{}/{}'.format(table_key_value, bitwidth))
                            table_key_data.append(
                                OrderedDict([
                                    ('match_kind', 'lpm'),
                                    ('key_field_name', key_field_name),
                                    ('value', sym_table_value_long),
                                    ('prefix_length', bitwidth),
                                ]))
                        elif table_key.match_type == 'ternary':
                            # Always use exact match mask, which is
                            # represented in simple_switch_CLI as a 1 bit
                            # in every bit position of the field.
                            bitwidth = context.get_header_field_size(
                                table_key.target[0], table_key.target[1])
                            mask = (1 << bitwidth) - 1
                            table_key_values_strs.append(
                                '{}&&&{}'.format(table_key_value, mask))
                            table_entry_priority = 1
                            table_key_data.append(
                                OrderedDict([('match_kind', 'ternary'), (
                                    'key_field_name', key_field_name), (
                                                 'value', sym_table_value_long),
                                             (
                                                 'mask', mask)]))
                        elif table_key.match_type == 'range':
                            # Always use a range where the min and max
                            # values are exactly the one desired value
                            # generated.
                            table_key_values_strs.append('{}->{}'.format(
                                table_key_value, table_key_value))
                            table_entry_priority = 1
                            table_key_data.append(
                                OrderedDict([('match_kind', 'range'), (
                                    'key_field_name', key_field_name
                                ), ('min_value', sym_table_value_long), (
                                                 'max_value',
                                                 sym_table_value_long)]))
                        elif table_key.match_type == 'exact':
                            table_key_values_strs.append(str(table_key_value))
                            table_key_data.append(
                                OrderedDict([('match_kind', 'exact'), (
                                    'key_field_name', key_field_name), (
                                    'value', sym_table_value_long)]))
                        else:
                            raise Exception('Match type {} not supported'.
                                            format(table_key.match_type))

                    logging.debug("table_name %s"
                                  " table.default_entry.action_const %s" %
                                  (table_name,
                                   table.default_entry.action_const))
                    if (len(table_key_values_strs) == 0
                            and table.default_entry.action_const):
                        # Then we cannot change the default action for the
                        # table at run time, so don't remember any entry
                        # for this table.
                        pass
                    else:
                        table_configs.append(
                            (table_name, transition, table_key_values_strs,
                             table_key_data, runtime_data_values,
                             table_entry_priority))

            # Print table configuration
            for table, action, values, key_data, params, priority in table_configs:
                # XXX: inelegant
                const_table = self.pipeline.tables[table].has_const_entries()

                params2 = []
                param_vals = []
                for param_name, param_val in params:
                    param_val = model_value_to_long(param_val)
                    param_vals.append(param_val)
                    params2.append(
                        OrderedDict([('name', param_name), ('value', param_val)
                                     ]))
                if len(values) == 0 or const_table or action.default_entry:
                    ss_cli_cmd = ('table_set_default ' +
                                  table_set_default_cmd_string(
                                      table, action.get_name(), param_vals))
                    logging.info(ss_cli_cmd)
                    table_setup_info = OrderedDict(
                        [("command", "table_set_default"), ("table_name",
                                                            table),
                         ("action_name",
                          action.get_name()), ("action_parameters", params2)])
                else:
                    ss_cli_cmd = ('table_add ' + table_add_cmd_string(
                        table, action.get_name(), values, param_vals,
                        priority))
                    table_setup_info = OrderedDict(
                        [("command", "table_add"), ("table_name",
                                                    table), ("keys", key_data),
                         ("action_name",
                          action.get_name()), ("action_parameters", params2)])
                    if priority is not None:
                        table_setup_info['priority'] = priority
                logging.info(ss_cli_cmd)
                ss_cli_setup_cmds.append(ss_cli_cmd)
                table_setup_cmd_data.append(table_setup_info)
            packet_len_bytes = len(payload)
            packet_hexstr = ''.join([('%02x' % (x)) for x in payload])
            logging.info("packet (%d bytes) %s"
                         "" % (packet_len_bytes, packet_hexstr))

            if len(context.uninitialized_reads) != 0:
                result = TestPathResult.UNINITIALIZED_READ
                uninitialized_read_data = []
                for uninitialized_read in context.uninitialized_reads:
                    var_name, source_info = uninitialized_read
                    logging.error('Uninitialized read of {} at {}'.format(
                        var_name, source_info))
                    uninitialized_read_data.append(
                        OrderedDict([("variable_name", var_name), (
                            "source_info", source_info_to_dict(source_info))]))
            elif len(context.invalid_header_writes) != 0:
                result = TestPathResult.INVALID_HEADER_WRITE
                invalid_header_write_data = []
                for invalid_header_write in context.invalid_header_writes:
                    var_name, source_info = invalid_header_write
                    logging.error('Invalid header write of {} at {}'.format(
                        var_name, source_info))
                    invalid_header_write_data.append(
                        OrderedDict([("variable_name", var_name), (
                            "source_info", source_info_to_dict(source_info))]))
            elif len(payload) >= Config().get_min_packet_len_generated():
                if Config().get_run_simple_switch() \
                        and is_complete_control_path:
                    extracted_path = self.test_packet(payload, table_configs,
                                                      source_info_to_node_name)

                    if is_complete_control_path:
                        match = (expected_path == extracted_path)
                    else:
                        len1 = len(expected_path)
                        len2 = len(extracted_path)
                        match = (expected_path == extracted_path[0:len1]
                                 ) and len1 <= len2
                else:
                    match = True
                if match:
                    logging.info('Test successful: {}'.format(expected_path))
                    result = TestPathResult.SUCCESS
                else:
                    logging.error('Expected and actual path differ')
                    logging.error('Expected: {}'.format(expected_path))
                    logging.error('Actual:   {}'.format(extracted_path))
                    result = TestPathResult.TEST_FAILED
                    assert False
            else:
                result = TestPathResult.PACKET_SHORTER_THAN_MIN
                logging.warning('Packet not sent (%d bytes is shorter than'
                                ' minimum %d supported)' %
                                (len(payload),
                                 Config().get_min_packet_len_generated()))
        else:
            logging.info(
                'Unable to find packet for path: {}'.format(expected_path))
            result = TestPathResult.NO_PACKET_FOUND

        if packet_hexstr is None:
            input_packets = []
        else:
            input_metadata = {
                '.'.join(var_name):
                    model.eval(value, model_completion=True).as_long()
                for (var_name, value) in context.input_metadata.iteritems()
            }
            input_packets = [
                OrderedDict([
                    # TBD: Currently we always send packets into port 0.
                    # Should generalize that later.
                    ("port", 0),
                    ("packet_len_bytes", packet_len_bytes),
                    ("packet_hexstr", packet_hexstr),
                    ("input_metadata", input_metadata),
                ])
            ]

        # TBD: Would be nice to get rid of u in front of strings on
        # paths, e.g. u'node_2', u'p4_programs/demo1b.p4'.  Maybe it
        # is beneficial to leave those in there for some reason, but I
        # suspect a change in representation of parser paths and/or
        # control paths could make bigger changes there such that we
        # want to wait until those changes are made before mucking
        # around with how they are returned.

        # Instead of calling str() on every element of a path, might
        # be nicer to convert them to a type that can be more easily
        # represented as separate parts in JSON, e.g. nested lists or
        # dicts of strings, numbers, booleans.
        test_case = OrderedDict([
            ("log_file_id", count),
            ("result", result.name),
            ("expected_path", map(str, expected_path)),
            ("complete_path", is_complete_control_path),
            ("ss_cli_setup_cmds", ss_cli_setup_cmds),
            ("input_packets", input_packets),
            # ("expected_output_packets", TBD),
            ("parser_path_len", len(parser_path)),
            ("ingress_path_len", len(control_path)),
        ])
        if uninitialized_read_data:
            test_case["uninitialized_read_data"] = uninitialized_read_data
        if invalid_header_write_data:
            test_case["invalid_header_write_data"] = invalid_header_write_data
        if actual_path_data:
            test_case["actual_path"] = map(str, actual_path_data)

        # Put details like these later in OrderedDict test_case,
        # especialy long ones.  This makes the shorter and/or more
        # essential information like that above come first, and
        # together.

        # Should be filled in by calling function, order will be maintained.
        test_case["time_sec_generate_ingress_constraints"] = None
        test_case["time_sec_solve"] = None
        test_case["time_sec_simulate_packet"] = None

        test_case["parser_path"] = map(str, parser_path)
        test_case["ingress_path"] = map(str, control_path)
        test_case["table_setup_cmd_data"] = table_setup_cmd_data

        payloads = []
        if payload:
            payloads.append(payload)

        return result, test_case, payloads

    def test_packet(self, packet, table_configs, source_info_to_node_name):
        """This function starts simple_switch, sends a packet to the switch and
        returns the parser states that the packet traverses based on the output of
        simple_switch."""

        with SimpleSwitch(self.json_file) as switch:
            for table, action, values, _, params, priority in table_configs:
                # XXX: inelegant
                const_table = self.pipeline.tables[table].has_const_entries()

                # Extract values of parameters, without the names
                param_vals = map(lambda x: x[1], params)
                if len(values) == 0 or const_table or action.default_entry:
                    switch.table_set_default(table, action.get_name(),
                                             param_vals)
                else:
                    switch.table_add(table, action.get_name(), values,
                                     param_vals, priority)

            extracted_path = switch.send_and_check_only_1_packet(
                packet, source_info_to_node_name)

            switch.clear_tables()

        return extracted_path
