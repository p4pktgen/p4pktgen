from enum import Enum
from p4pktgen.util.graph import Edge

TransitionType = Enum(
    'TransitionType',
    'PARSER_ERROR_TRANSITION ACTION_TRANSITION CONST_ACTION_TRANSITION'
    ' BOOL_TRANSITION NOOP_TRANSITION'
)


class Transition(Edge):
    def __init__(self, transition_type, src, dst):
        super(Transition, self).__init__(src, dst)
        self.transition_type = transition_type


class ParserTransition(Edge):
    """
    Class representing the P4 parser transitions
    """

    def __init__(self,
                 state_name,
                 type_=None,
                 next_state_name=None,
                 next_state=None,
                 mask=None,
                 value=None):
        # XXX: remove 'sink' hack
        super(ParserTransition, self).__init__(state_name, next_state_name
                                               if next_state_name is not None
                                               else 'sink')

        assert (state_name is not None)
        self.type_ = type_
        self.next_state_name = next_state_name
        self.next_state = next_state
        self.mask = mask
        self.value = value

    def __eq__(self, other):
        return isinstance(other, ParserTransition) and \
            self.type_ == other.type_ and \
            self.next_state_name == other.next_state_name and \
            self.mask == other.mask and \
            self.value == other.value

    def __hash__(self):
        return hash((self.type_, self.next_state_name, self.mask, self.value))


class ParserCompositeTransition(Edge):
    """
    Class representing parallel P4 parser transitions that have been merged.
    """
    def __init__(self, components):
        # Check that edges are parallel parser transitions
        assert all(isinstance(t, ParserTransition) for t in components)
        assert len(components) > 0
        src = components[0].src
        dst = components[0].dst
        for c in components[1:]:
            assert c.src == src and c.dst == dst
        self.components = components
        super(ParserCompositeTransition, self).__init__(src, dst)

    def __eq__(self, other):
        if isinstance(other, ParserTransition):
            return other in self.component_edges
        return super(ParserCompositeTransition, self).__eq__(other)

    def __hash__(self):
        return hash(tuple(self.components))


class ParserErrorTransition(Transition):
    def __init__(self, state_name, op, op_idx, next_state, error_str):
        super(ParserErrorTransition, self).__init__(
            TransitionType.PARSER_ERROR_TRANSITION, state_name, next_state)
        self.op = op
        self.op_idx = op_idx
        self.next_state = next_state
        self.error_str = error_str

    def __repr__(self):
        return '{} -({})-> {}'.format(self.src, self.error_str, self.dst)


class ActionTransition(Transition):
    def __init__(self, src, dest, action, default_entry, action_data):
        super(ActionTransition,
              self).__init__(TransitionType.ACTION_TRANSITION, src, dest)
        self.action = action
        self.default_entry = default_entry
        self.action_data = action_data

    def get_name(self):
        return self.action.name

    def __repr__(self):
        # XXX: better output (will need to change test cases)
        return 'u\'{}\''.format(self.action.name)

    def __eq__(self, other):
        if isinstance(other, ActionTransition):
            return self.action == other.action
        else:
            return self.action.name == str(other)

    def __hash__(self):
        return hash(self.action.name)


class ConstActionTransition(Transition):
    def __init__(self, src, dest, action, action_data, prev_const_action_transition):
        super(ConstActionTransition,
              self).__init__(TransitionType.CONST_ACTION_TRANSITION, src, dest)
        self.action = action
        self.action_data = action_data
        self.prev_const_action_transition = prev_const_action_transition


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
        if isinstance(other, BoolTransition):
            return self.val == other.val and self.source_info == other.source_info
        else:
            if self.source_info is not None:
                return (self.val,
                        (self.source_info.filename, self.source_info.line,
                         self.source_info.source_fragment)) == other
            else:
                # XXX: hack
                return self.val == other[0]

    def __hash__(self):
        # XXX: hack for test cases
        return hash((self.val, self.source_info))


class NoopTransition(Transition):
    """Used to represent empty control graphs.  Does not represent a real
    node or transition."""
    def __init__(self, src, dest):
        super(NoopTransition, self).__init__(TransitionType.NOOP_TRANSITION,
                                             src, dest)

    def __repr__(self):
        return u'\'No-Op\''

    def __eq__(self, other):
        if isinstance(other, NoopTransition):
            return True
        return other == 'No-Op'

    def __hash__(self):
        return hash('No-Op')
