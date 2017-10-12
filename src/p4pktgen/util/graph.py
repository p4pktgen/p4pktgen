import logging
import copy


class Graph:
    def __init__(self):
        self.graph = {}

    def add_edge(self, v_from, v_to, edge):
        if v_from not in self.graph:
            self.graph[v_from] = []
        self.graph[v_from].append((edge, v_to))

    def get_neighbors(self, v):
        return self.graph[v]

    def __repr__(self):
        return self.graph.__repr__()

    def generate_all_paths(self, v_start, v_end, callback=None):
        path_so_far = []
        all_paths = []
        # num_paths is a 1-element list just to make it
        # straightforward in Python 2 to modify it in a sub-def.
        num_paths = [0]

        # XXX: does not work with cycles, inefficient in general
        def generate_all_paths_(node):
            if node == v_end:
                logging.debug("generate_all_paths: PATH len %2d %s"
                              "" % (len(path_so_far), path_so_far))
                if callback is None:
                    all_paths.append(copy.copy(path_so_far))
                else:
                    # Ignore return value in this case -- we will
                    # never go deeper in this case no matter what the
                    # return value might be.
                    callback(copy.copy(path_so_far), True)
                num_paths[0] += 1
                if num_paths[0] % 1000 == 0:
                    logging.info("generated %d complete paths so far..." %
                                 (num_paths[0]))
                return

            for t in self.get_neighbors(node):
                transition_name = t[0]
                neighbor = t[1]
                path_so_far.append((node, transition_name) + t[2:])
                go_deeper = True
                if callback is not None:
                    # The recursive generate_all_paths_() call below
                    # will call the callback() method with second
                    # argument True, if neighbor == v_end.  In this
                    # special case, it is redundant to call callback()
                    # with the same path_so_far and second argument
                    # False here.  Avoid doing that.
                    if neighbor != v_end:
                        go_deeper = callback(copy.copy(path_so_far), False)
                logging.debug("generate_all_paths: %2d %s node %s to %s"
                              " go_deeper %s"
                              "" % (len(path_so_far), path_so_far, node,
                                    neighbor, go_deeper))
                if go_deeper:
                    generate_all_paths_(neighbor)
                path_so_far.pop()

        go_deeper = True
        if callback is not None:
            go_deeper = callback([], False)
        if go_deeper:
            generate_all_paths_(v_start)
        return all_paths

    def count_all_paths(self, v_start):
        """Quickly count the number of paths in a directed acyclic graph (DAG)
        starting from node self.init_table_name, leading to the "None" node,
        without enumerating them all. This can be done in linear time in the
        number of edges in the DAG, even if the number of paths is
        exponentially large."""

        num_paths_to_end = {}

        # XXX: does not work with cycles
        def count_all_paths_(node):
            if node is None:
                return 1
            if node in num_paths_to_end:
                return num_paths_to_end[node]
            count = 0
            for t in self.get_neighbors(node):
                transition_name = t[0]
                neighbor = t[1]
                tmp = count_all_paths_(neighbor)
                logging.debug(
                    "  %d ways to end through transition %s -> %s -> %s" %
                    (tmp, node, transition_name, neighbor))
                count += tmp
            logging.debug("%d ways to end starting from node %s" % (count,
                                                                    node))
            num_paths_to_end[node] = count
            return count

        return count_all_paths_(v_start)
