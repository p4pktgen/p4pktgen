import logging

from enum import Enum

from collections import OrderedDict

from p4pktgen.config import Config
from p4pktgen.switch.simple_switch import SimpleSwitch


TestPathResult = Enum(
    'TestPathResult',
    'SUCCESS NO_PACKET_FOUND TEST_FAILED UNINITIALIZED_READ INVALID_HEADER_WRITE'
)


def record_test_case(result, is_complete_control_path):
    if result in [TestPathResult.UNINITIALIZED_READ,
                  TestPathResult.INVALID_HEADER_WRITE]:
        return True
    if result == TestPathResult.SUCCESS and is_complete_control_path:
        return True
    return False


# TBD: There is probably a better way to convert the params from
# whatever type they are coming from the SMT solver, to something that
# can be written out as JSON.  This seems to work, though.
def model_value_to_int(model_val):
    try:
        return int(str(model_val))
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

    def get_table_entry_config(self, table_name, action_name, is_default,
                               key_values, runtime_data_values):

        table = self.pipeline.tables[table_name]
        key_value_strs = []
        key_data = []
        priority = None
        for table_key, table_key_value in zip(table.key, key_values):
            key_field_name = '.'.join(table_key.target)
            int_value = model_value_to_int(table_key_value)
            if table_key.match_type == 'lpm':
                bitwidth = table_key_value.size()
                key_value_strs.append(
                    '{}/{}'.format(table_key_value, bitwidth))
                key_data.append(
                    OrderedDict([
                        ('match_kind', 'lpm'),
                        ('key_field_name', key_field_name),
                        ('value', int_value),
                        ('prefix_length', bitwidth),
                    ]))
            elif table_key.match_type == 'ternary':
                # Always use exact match mask, which is
                # represented in simple_switch_CLI as a 1 bit
                # in every bit position of the field.
                bitwidth = table_key_value.size()
                mask = (1 << bitwidth) - 1
                key_value_strs.append(
                    '{}&&&{}'.format(table_key_value, mask))
                priority = 1
                key_data.append(
                    OrderedDict([('match_kind', 'ternary'), (
                        'key_field_name', key_field_name), (
                            'value', int_value), (
                                'mask', mask)]))
            elif table_key.match_type == 'range':
                # Always use a range where the min and max
                # values are exactly the one desired value
                # generated.
                key_value_strs.append('{}->{}'.format(
                    table_key_value, table_key_value))
                priority = 1
                key_data.append(
                    OrderedDict([('match_kind', 'range'), (
                        'key_field_name', key_field_name
                    ), ('min_value', int_value), (
                        'max_value', int_value)]))
            elif table_key.match_type == 'exact':
                key_value_strs.append(str(table_key_value))
                key_data.append(
                    OrderedDict([('match_kind', 'exact'), (
                        'key_field_name', key_field_name), (
                        'value', int_value)]))
            else:
                raise Exception('Match type {} not supported'.
                                format(table_key.match_type))

        logging.debug("table_name %s"
                      " table.default_entry.action_const %s" %
                      (table_name,
                       table.default_entry.action_const))

        if (len(key_value_strs) == 0
                and table.default_entry.action_const):
            # Then we cannot change the default action for the
            # table at run time, so don't remember any entry
            # for this table.
            return None

        return (table_name, action_name, is_default,
                key_value_strs, key_data, runtime_data_values,  priority)

    def get_table_setup_cmd(self, entry_config):
        table_name, action_name, is_default, values, \
            key_data, params, priority = entry_config
        # XXX: inelegant
        const_table = self.pipeline.tables[table_name].has_const_entries()

        params2 = []
        param_vals = []
        for param_name, param_val in params:
            param_val = model_value_to_int(param_val)
            param_vals.append(param_val)
            params2.append(
                OrderedDict(
                    [('name', param_name), ('value', param_val)]))
        if len(values) == 0 or const_table or is_default:
            cmd = ('table_set_default ' +
                   table_set_default_cmd_string(
                       table_name, action_name, param_vals))
            logging.info(cmd)
            cmd_data = OrderedDict(
                [("command", "table_set_default"), ("table_name", table_name),
                 ("action_name", action_name), ("action_parameters", params2)])
        else:
            cmd = ('table_add ' +
                   table_add_cmd_string(
                       table_name, action_name, values, param_vals, priority))
            cmd_data = OrderedDict(
                [("command", "table_add"), ("table_name", table_name),
                 ("keys", key_data),
                 ("action_name", action_name), ("action_parameters", params2)])
            if priority is not None:
                cmd_data['priority'] = priority

        logging.info(cmd)
        return cmd, cmd_data

    def table_config_for_path(self, context, model, control_path):
        # Determine the minimal table configuration for this path, produce
        # setup commands and associated data.
        table_config = []  # [(cmd, cmd_data), ...]
        if model is None:
            return table_config

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
                         model.eval(context.get_table_runtime_data(table_name, i),
                                    model_completion=True)))
                table_key_values = context.get_table_key_values(
                    model, table_name)

                entry_config = self.get_table_entry_config(
                    table_name, transition.get_name(),
                    transition.default_entry,
                    table_key_values, runtime_data_values)
                if entry_config is None:
                    continue

                # Get table configuration commands and associated data
                table_config.append(self.get_table_setup_cmd(entry_config))

        return table_config

    @staticmethod
    def build(model, sym_packet, path, input_metadata,
              uninitialized_reads, invalid_header_writes, table_config):
        """Should take only explicit references to all variables to ensure that
        none are missed when separating paths for consolidated solving."""

        packet_hexstr = None
        payload = None
        ss_cli_setup_cmds = []
        table_setup_cmd_data = []
        uninitialized_read_data = None
        invalid_header_write_data = None
        actual_path_data = None
        result = None

        if model is not None:
            # Do this first to ensure all packet fields are in model.
            payload = sym_packet.get_payload_from_model(model)

            if table_config:
                # Unzip [(x, y), ...] to [x, ...], [y, ...]
                ss_cli_setup_cmds, table_setup_cmd_data = \
                    (list(x) for x in zip(*table_config))

            packet_len_bytes = len(payload)
            packet_hexstr = ''.join([('%02x' % (x)) for x in payload])
            logging.info("packet (%d bytes) %s"
                         "" % (packet_len_bytes, packet_hexstr))

            if uninitialized_reads:
                result = TestPathResult.UNINITIALIZED_READ
                uninitialized_read_data = []
                for uninitialized_read in uninitialized_reads:
                    var_name, source_info = uninitialized_read
                    logging.error('Uninitialized read of {} at {}'.format(
                        var_name, source_info))
                    uninitialized_read_data.append(
                        OrderedDict([("variable_name", var_name), (
                            "source_info", source_info_to_dict(source_info))]))
            elif invalid_header_writes:
                result = TestPathResult.INVALID_HEADER_WRITE
                invalid_header_write_data = []
                for invalid_header_write in invalid_header_writes:
                    var_name, source_info = invalid_header_write
                    logging.error('Invalid header write of {} at {}'.format(
                        var_name, source_info))
                    invalid_header_write_data.append(
                        OrderedDict([("variable_name", var_name), (
                            "source_info", source_info_to_dict(source_info))]))
            else:
                assert len(payload) >= Config().get_min_packet_len_generated()
                logging.info('Found packet for path: {}'.format(path.expected_path))
                result = TestPathResult.SUCCESS
        else:
            logging.info(
                'Unable to find packet for path: {}'.format(path.expected_path))
            result = TestPathResult.NO_PACKET_FOUND

        if packet_hexstr is None:
            input_packets = []
        else:
            input_metadata = {
                '.'.join(var_name):
                    model.eval(value, model_completion=True).as_long()
                for (var_name, value) in input_metadata.items()
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
            ("log_file_id", path.id),
            ("result", result.name),
            ("expected_path", map(str, path.expected_path)),
            ("complete_path", path.is_complete),
            ("ss_cli_setup_cmds", ss_cli_setup_cmds),
            ("input_packets", input_packets),
            # ("expected_output_packets", TBD),
            ("parser_path_len", len(path.parser_path)),
            ("ingress_path_len", len(path.control_path)),
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

        test_case["parser_path"] = map(str, path.parser_path)
        test_case["ingress_path"] = map(str, path.control_path)
        test_case["table_setup_cmd_data"] = table_setup_cmd_data

        payloads = []
        if payload:
            payloads.append(payload)

        return result, test_case, payloads

    def build_for_path(self, context, model, sym_packet, path):
        return self.build(
            model, sym_packet, path,
            context.input_metadata, context.uninitialized_reads,
            context.invalid_header_writes,
            self.table_config_for_path(context, model, path.control_path)
        )

    def run_simple_switch(self, expected_path, test_case, payloads,
                          is_complete_control_path, source_info_to_node_name):
        result = TestPathResult[test_case['result']]
        if is_complete_control_path and result == TestPathResult.SUCCESS:
            assert len(payloads) == 1
            extracted_path = self.test_packet(payloads[0],
                                              test_case['ss_cli_setup_cmds'],
                                              source_info_to_node_name)

            if expected_path != extracted_path:
                logging.error('Expected and actual path differ')
                logging.error('Expected: {}'.format(expected_path))
                logging.error('Actual:   {}'.format(extracted_path))
                result = TestPathResult.TEST_FAILED
                assert False
            else:
                logging.info('Test successful: {}'.format(expected_path))
        return result

    def test_packet(self, packet, ss_cli_setup_cmds, source_info_to_node_name):
        """This function starts simple_switch, sends a packet to the switch and
        returns the parser states that the packet traverses based on the output of
        simple_switch."""

        with SimpleSwitch(self.json_file) as switch:
            for cmd in ss_cli_setup_cmds:
                switch.table_cmd(cmd)

            extracted_path = switch.send_and_check_only_1_packet(
                packet, source_info_to_node_name)

            switch.clear_tables()

        return extracted_path
