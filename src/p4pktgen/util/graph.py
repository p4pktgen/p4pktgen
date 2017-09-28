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

    def generate_all_paths(self, v_start, v_end):
        path_so_far = []
        all_paths = []

        # XXX: does not work with cycles, inefficient in general
        def generate_all_paths_(node):
            if node == v_end:
                logging.debug("generate_all_paths: PATH len %2d %s"
                              "" % (len(path_so_far), path_so_far))
                all_paths.append(copy.copy(path_so_far))
                if len(all_paths) % 1000 == 0:
                    logging.info("generated %d paths so far..." %
                                 (len(all_paths)))
                return

            for t in self.get_neighbors(node):
                transition_name = t[0]
                neighbor = t[1]
                path_so_far.append((node, transition_name) + t[2:])
                logging.debug("generate_all_paths: %2d %s node %s to %s"
                              "" % (len(path_so_far), path_so_far, node,
                                    neighbor))
                generate_all_paths_(neighbor)
                path_so_far.pop()

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
