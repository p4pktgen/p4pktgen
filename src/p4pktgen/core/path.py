import time

from p4pktgen.config import Config
from p4pktgen.core.test_cases import TestPathResult


class Path(object):
    def __init__(self, id, expected_path, parser_path, control_path, is_complete):
        self.id = id
        self.expected_path = expected_path
        self.parser_path = parser_path
        self.control_path = control_path
        self.is_complete = is_complete

    def __str__(self):
        return "%d Exp path (len %d+%d=%d) complete_path %s: %s" % (
            self.id, len(self.parser_path), len(self.control_path),
            len(self.parser_path) + len(self.control_path),
            self.is_complete, self.expected_path
        )


class PathSolution(object):
    def __init__(self, path, result, constraints, context, sym_packet, model):
        self.path = path
        self.result = result
        self.constraints = constraints
        self.context = context
        self.sym_packet = sym_packet
        self.model = model


class PathModel(object):
    def __init__(self, path, result, path_solver):
        self.path = path
        self.result = result
        self.path_solver = path_solver

    def solutions(self):
        extract_vl_variation = Config().get_extract_vl_variation()
        current_result = self.result
        while current_result != TestPathResult.NO_PACKET_FOUND:
            assert current_result == self.result

            # Choose values for randomization variables.
            random_constraints = []
            fix_random = self.path.is_complete
            if fix_random:
                self.path_solver.push()
                random_constraints = self.path_solver.fix_random_constraints()

            try:
                path_solution = PathSolution(
                    self.path, self.result,
                    self.path_solver.constraints + [random_constraints],
                    self.path_solver.current_context(),
                    self.path_solver.sym_packet,
                    self.path_solver.solver.model(),
                )
                yield path_solution
            finally:
                # Clear the constraints on the values of the randomization
                # variables.
                if fix_random:
                    self.path_solver.pop()

            if not self.path_solver.constrain_last_extract_vl_lengths(extract_vl_variation):
                # Special case: unbounded numbers of test cases are only
                # safe when we're building up constraints on VL-extraction
                # lengths, or else we'll loop forever.
                if not Config().get_max_test_cases_per_path():
                    break

            current_result = self.path_solver.solve_path()
