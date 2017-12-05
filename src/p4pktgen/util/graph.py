import logging
import copy

class Edge(object):
    def __init__(self, src, dst):
        self.src = src
        self.dst = dst

    def __repr__(self):
        return '{} -> {}'.format(self.src, self.dst)

class Graph:
    def __init__(self):
        self.graph = {}

    def add_edge(self, src, dst, edge):
        if src not in self.graph:
            self.graph[src] = []
        self.graph[src].append(edge)

    def get_neighbors(self, v):
        return self.graph[v]

    def __repr__(self):
        return self.graph.__repr__()

    def generate_all_paths(self, v_start, v_end, callback=None,
                           neighbor_order_callback=None):
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

            neighbors = self.get_neighbors(node)
            if neighbor_order_callback is not None:
                custom_order = neighbor_order_callback(node, neighbors)
                # TBD: Consider checking that the two sets of
                # neighbors are identical, rather than this less
                # sophisticated check.
                assert len(custom_order) == len(neighbors)
                neighbors = custom_order
            for t in neighbors:
                transition_name = t
                neighbor = t.dst
                path_so_far.append((node, transition_name))
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
        num_edges = [0]

        # XXX: does not work with cycles
        def count_all_paths_(node):
            if node is None:
                return 1
            if node in num_paths_to_end:
                return num_paths_to_end[node]
            num_edges[0] += len(self.get_neighbors(node))
            count = 0
            for t in self.get_neighbors(node):
                transition_name = t
                neighbor = t.dst
                tmp = count_all_paths_(neighbor)
                logging.debug(
                    "  %d ways to end through transition %s -> %s -> %s" %
                    (tmp, node, transition_name, neighbor))
                count += tmp
            logging.debug("%d ways to end starting from node %s" % (count,
                                                                    node))
            num_paths_to_end[node] = count
            return count

        num_paths = count_all_paths_(v_start)
        # + 1 because "None" node at end is not included in dict
        # num_paths_to_end
        num_nodes = len(num_paths_to_end) + 1
        return num_paths, num_nodes, num_edges[0]
