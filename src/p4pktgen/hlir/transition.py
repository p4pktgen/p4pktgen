from enum import Enum
from p4pktgen.util.graph import Edge

TransitionType = Enum(
    'TransitionType',
    'PARSER_OP_TRANSITION ACTION_TRANSITION CONST_ACTION_TRANSITION BOOL_TRANSITION'
)


class Transition(Edge):
    def __init__(self, transition_type, src, dst):
        super(Transition, self).__init__(src, dst)
        self.transition_type = transition_type


class ParserOpTransition(Transition):
    def __init__(self, state_name, op, op_idx, next_state, error_str):
        super(ParserOpTransition, self).__init__(
            TransitionType.PARSER_OP_TRANSITION, state_name, next_state)
        self.op = op
        self.op_idx = op_idx
        self.next_state = next_state
        self.error_str = error_str


class ActionTransition(Transition):
    def __init__(self, src, dest, action):
        super(ActionTransition,
              self).__init__(TransitionType.ACTION_TRANSITION, src, dest)
        self.action = action

    def get_name(self):
        return self.action.name

    def __repr__(self):
        # XXX: better output (will need to change test cases)
        return 'u\'{}\''.format(self.action.name)

    def __eq__(self, other):
        return self.action.name == str(other)

    def __hash__(self):
        return hash(self.action.name)


class ConstActionTransition(Transition):
    def __init__(self, src, dest, action, action_data):
        super(ConstActionTransition,
              self).__init__(TransitionType.CONST_ACTION_TRANSITION, src, dest)
        self.action = action
        self.action_data = action_data


class BoolTransition(Transition):
    def __init__(self, src, dest, val, source_info):
        super(BoolTransition, self).__init__(TransitionType.BOOL_TRANSITION,
                                             src, dest)
        assert isinstance(val, bool)
        self.val = val
        self.source_info = source_info

    def __repr__(self):
        # XXX: hack for test cases
        return '({}, {})'.format(self.val, self.source_info)

    def __eq__(self, other):
        return (self.val, (self.source_info.filename, self.source_info.line,
                           self.source_info.source_fragment)) == other

    def __hash__(self):
        # XXX: hack for test cases
        return hash((self.val, self.source_info))
