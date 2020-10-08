import logging
import collections
import copy

from enum import Enum

VisitResult = Enum('VisitResult', 'CONTINUE BACKTRACK ABORT')


class Edge(object):
    def __init__(self, src, dst):
        self.src = src
        self.dst = dst

    def __repr__(self):
        return '{} -> {}'.format(self.src, self.dst)


class GraphVisitor(object):
    def preprocess_edges(self, path, edges):
        raise NotImplementedError()

    def visit(self, path, is_complete_path):
        raise NotImplementedError()

    def backtrack(self):
        raise NotImplementedError()


class Graph:
    """A Graph is a graph of nodes and directed edges.  The nodes can be
    any immutable hashable Python data type, e.g. numbers, strings,
    tuples, frozenset, etc.  The edges can be any data type, mutable
    or immutable.

    Call method add_node to add a node to the graph, or add_edge to
    add an edge.  add_edge also adds the source and destination nodes,
    if they have not been added before.
    """

    def __init__(self):
        self.graph = {}
        self.in_edges = {}

    def num_edges(self):
        count = 0
        for _, edges in self.graph.items():
            count += len(edges)
        return count

    # XXX: This might not be the correct way to override __deepcopy__
    # in Python. I am coding up something that works for this class
    # Graph's use case, and not worrying about the finer details.
    def __deepcopy__(self, memo_dict):
        ret = Graph()
        ret.graph = copy.deepcopy(self.graph)
        ret.in_edges = copy.deepcopy(self.in_edges)
        return ret

    def add_node(self, v):
        if v not in self.graph:
            self.graph[v] = []
        if v not in self.in_edges:
            self.in_edges[v] = []

    def add_edge(self, src, dst, edge):
        assert isinstance(edge, Edge)
        assert edge.src == src
        assert edge.dst == dst
        self.add_node(src)
        self.add_node(dst)
        self.graph[src].append(edge)
        self.in_edges[dst].append(edge)

    def get_nodes(self):
        """Return a list of nodes in the graph."""
        return list(self.graph.keys())

    def get_neighbors(self, v):
        """Given a node v, return a list of edges directed out of v."""
        return self.graph[v]

    def get_in_edges(self, v):
        """Given a node v, return a list of edges directed into v."""
        return self.in_edges[v]

    def __repr__(self):
        return self.graph.__repr__()

    def get_sources_and_sinks(self):
        """Return a list of all 'source' nodes, which are those that have
        no edges directed into them, and a list of all 'sink' nodes,
        which are those that have no edges directed out of them."""
        sources = []
        sinks = []
        for v in self.get_nodes():
            if len(self.get_neighbors(v)) == 0:
                sinks.append(v)
            if len(self.get_in_edges(v)) == 0:
                sources.append(v)
        return sources, sinks

    def topological_sort(self):
        """Return a tuple of 2 elements.  The first element is a Boolean
        value, True if the graph contains at least one cycle, False if
        it is acyclic.

        If the graph is acyclic, the second element of the tuple is a
        list of all nodes in the graph sorted in a topological order.
        A sequence of nodes is in a topological order for a directed
        acyclic graph if for every directed edge (v, w) (from v to w)
        in the graph, v appears earlier than w in the sequence.

        If the graph contains a cycle, then the second element of the
        returned tuple is a list of nodes in one cycle of the graph.
        """

        in_degree = {}
        in_degree_0_nodes = []
        num_nodes = 0
        for u in self.get_nodes():
            num_nodes += 1
            in_degree[u] = len(self.get_in_edges(u))
            if in_degree[u] == 0:
                in_degree_0_nodes.append(u)

        # Start with any node that in-degree 0 in the original graph.
        # Every time a node u is added to the current topological
        # order, pretend like we are deleting each edge out of u by
        # decrementing the in-degree of v for every edge (u, v) out of
        # u.

        # If we ever come to a time when there are remaining nodes,
        # but none of them have in-degree 0, then there must be a
        # cycle among some subset of those nodes (perhaps all of them,
        # perhaps a proper subset of them).  Note: Some of those
        # remaining nodes might not be on _any_ cycle.  For example,
        # in the graph below, all have in-degree >= 1, but only c1,
        # c2, and c3 are in a cycle.  c4 and c5 are in no cycles.
        #
        #    c5 <--- c1 ---> c2 ----> c4
        #            ^       |
        #            |       |
        #            |       |
        #            c3 <----+

        topo_order = []
        cycle_exists = False
        while len(topo_order) < num_nodes:
            if len(in_degree_0_nodes) == 0:
                cycle_exists = True
                break
            u = in_degree_0_nodes.pop()
            topo_order.append(u)
            for e in self.get_neighbors(u):
                v = e.dst
                in_degree[v] -= 1
                assert in_degree[v] >= 0
                if in_degree[v] == 0:
                    in_degree_0_nodes.append(v)
        assert (cycle_exists or len(in_degree_0_nodes) == 0)

        if not cycle_exists:
            # Double-check that topo_order is consistent with all
            # edges of the graph.
            topo_order_idx = {}
            for idx in range(len(topo_order)):
                topo_order_idx[topo_order[idx]] = idx
            for u in self.get_nodes():
                u_idx = topo_order_idx[u]
                for e in self.get_neighbors(u):
                    v = e.dst
                    assert u_idx < topo_order_idx[v]

            return (cycle_exists, topo_order)

        # TBD: Implement the cycle-finding part of this method.
        assert False

    def depth_first_search(self, v, backwards=False):
        """Perform a depth-first search in the graph starting at node v.  By
        default, only traverse edges in the 'forward' direction, from
        e.src to e.dst.  If the optional keyword arg backwards is
        True, only traverse edges in the 'backward' direction, from
        e.dst to e.src.

        Return a dict that contains a key for every node visited, with
        a corresponding value equal to the parent of that node in the
        depth-first search tree.  This dict's keys will be fewer than
        all nodes in the graph, if not all are reachable from v along
        the specified direction of edges.

        Also return a list of nodes that are sinks if backwards is
        False, where a sink node has out-degree 0.  If backwards is
        True, this list of nodes are sources, where a source node has
        in-degree 0.  Again, these nodes are a subset of those
        reachable from v along edges in the specified direction.
        """

        sources_or_sinks = []
        visited = set()
        dfs_tree_parent = {}

        def do_dfs(u, parent):
            if u in dfs_tree_parent:
                return
            dfs_tree_parent[u] = parent
            if backwards:
                edges = self.get_in_edges(u)
            else:
                edges = self.get_neighbors(u)
            if len(edges) == 0:
                sources_or_sinks.append(u)
            for e in edges:
                if backwards:
                    do_dfs(e.src, u)
                else:
                    do_dfs(e.dst, u)

        do_dfs(v, v)
        return dfs_tree_parent, sources_or_sinks

    def reverse_one_edge(self, src_node, dst_node):
        # Find one edge from src_node to dst_node, if there is one.
        fwd_e = None
        fwd_idx = 0
        for e in self.get_neighbors(src_node):
            if e.dst == dst_node:
                fwd_e = e
                break
            fwd_idx += 1
        bkwd_e = None
        bkwd_idx = 0
        for e in self.get_in_edges(dst_node):
            if e.src == src_node:
                bkwd_e = e
                break
            bkwd_idx += 1
        assert fwd_e is not None
        assert bkwd_e is not None
        del self.graph[src_node][fwd_idx]
        del self.in_edges[dst_node][bkwd_idx]
        # Add an edge in the opposite direction
        new_e = Edge(dst_node, src_node)
        self.add_edge(new_e.src, new_e.dst, new_e)

    def lowest_common_ancestor(self, v):
        """In a DAG with a single source node, return the 'lowest common
        ancestor' node for all edges into node v.

        If all edges into v are from the same node u (whether there is
        one such edge, or multiple parallel edges), then u is the
        lowest common ancestor.  If there are multiple nodes with
        edges from them to v, then the lowest common ancestor node is
        the one that is on all paths from the source to v, closest to
        v.
        """

        # First check for some easy special cases, since they will be
        # reasonably common in typical control flow graphs, and they
        # are very quick to check for and return the correct answer.
        from_node_set = set()
        for e in self.get_in_edges(v):
            from_node_set.add(e.src)
        if len(from_node_set) == 0:
            return v
        if len(from_node_set) == 1:
            return from_node_set.pop()

        # Now do the general case.  Start by doing a depth-first
        # search along edges in the backwards direction from v to the
        # source(s).
        dfs_tree, sources = self.depth_first_search(v, backwards=True)
        # This method is only intended to work for graphs with a
        # unique source node, i.e. a node with in-degree 0, reachable
        # along the reverse of edges from v.
        assert len(sources) == 1
        source = sources[0]

        # Create a graph that is like the subgraph of nodes in the
        # collection 'dfs_tree.keys()', except with edges the opposite
        # direction from 'self', and with every node x except v and
        # the source node replaced with a pair of nodes x1 and x2,
        # with an edge from x1 to x2, and all edges into x go into x1,
        # and all edges out of x go out of x2.

        flow_graph_1 = Graph()
        new_node_1 = {}
        new_node_2 = {}
        for u in dfs_tree.keys():
            if u == v or u == source:
                new_node_1[u] = u
                new_node_2[u] = u
            else:
                new_node_1[u] = (u, 1)
                new_node_2[u] = (u, 2)
                e = Edge(new_node_1[u], new_node_2[u])
                e.orig_node = u
                flow_graph_1.add_edge(e.src, e.dst, e)
        for u in dfs_tree.keys():
            edges = self.get_in_edges(u)
            for orig_e in edges:
                orig_src = orig_e.src
                if orig_src not in dfs_tree:
                    continue
                new_e = Edge(new_node_2[u], new_node_1[orig_src])
                flow_graph_1.add_edge(new_e.src, new_e.dst, new_e)

        # Consider all edges in flow_graph_1 to have capacity 1.

        # If the maximum flow from v to source has capacity more than
        # 1, then there are at least 2 node-disjoint paths from v to
        # source, so the least common ancestor is source.

        # If the maximum flow from v to source has capacity exactly 1,
        # then because we have already handled the cases of v having
        # no in-edges, or all in-edges from the same node, earlier
        # above, we know that source and v are different nodes, and
        # there must be another node other than those 2 in the graph
        # that is an 'articulation point', i.e. removing it would
        # result in no remaining paths from v to source in
        # flow_graph_1.

        aug_path_tree_1, _ = flow_graph_1.depth_first_search(v)
        # We should always have found an augmenting path from v to
        # source, given how flow_graph_1 was constructed.
        #        logging.debug("aug_path_tree_1 contents:")
        #        for tmp in aug_path_tree_1:
        #            logging.debug("    %s -> %s", tmp, aug_path_tree_1[tmp])
        assert source in aug_path_tree_1
        # Copy flow_graph_1 to flow_graph_2, then modify flow_graph_2
        # to make it the 'residual flow graph' of flow_graph_1, after
        # sending flow 1 along the augmenting path found from v to
        # source.  This requires reversing the direction of one edge
        # between each pair of vertices on the augmenting path found
        # from v to source.
        flow_graph_2 = copy.deepcopy(flow_graph_1)
        aug_path_lst = [source]
        cur_node = source
        parent_node = aug_path_tree_1[cur_node]
        while True:
            aug_path_lst.append(cur_node)
            # Find any edge from parent_node to cur_node and reverse
            # its direction, by removing the original and adding a new
            # one in the opposite direction.  If there is more than
            # one such edge, only reverse one of them, since each has
            # capacity 1, and the augmenting path only had flow 1.
            flow_graph_2.reverse_one_edge(parent_node, cur_node)
            if parent_node == v:
                break
            cur_node = parent_node
            parent_node = aug_path_tree_1[cur_node]

        # Make the augmenting path list of nodes be in the direction
        # from v to source.
        aug_path_lst.reverse()

        # See if we can find a second augmenting path from v to source
        # in flow_graph_2.
        aug_path_tree_2, _ = flow_graph_2.depth_first_search(v)
        if source in aug_path_tree_2:
            # If so, then source is the lowest common ancestor for v.
            return source

        # If not, find a min cut for the max flow represented by the
        # magnitude 1 flow found as aug_path_tree_1, by seeing which
        # edges cross from the set of nodes reachable from v in
        # aug_path_tree_2, to the set of nodes _not_ reachable from v
        # in aug_path_tree_2.
        min_cut_edges = []
        for reachable_node in aug_path_tree_2:
            for e in flow_graph_1.get_neighbors(reachable_node):
                if e.dst not in aug_path_tree_2:
                    min_cut_edges.append(e)

#        logging.debug("Min cut edges")
#        for e in min_cut_edges:
#            logging.debug("    %s -> %s", e.src, e.dst)
# There should be only one edge in the min cut, and it should
# be from a node of the form (x, 1) to (x, 2), for some node x
# in the original graph.  That x is the lowest common ancestor
# for v.
        assert len(min_cut_edges) == 1
        e = min_cut_edges[0]
        assert isinstance(e.src, tuple)
        assert e.src[1] == 1
        assert isinstance(e.dst, tuple)
        assert e.dst[1] == 2
        assert e.src[0] == e.dst[0]
        return e.src[0]

    def visit_all_paths(self, v_start, v_end, graph_visitor):
        assert v_start is not None, \
            "Empty control graphs must be handled specially."
        queue = [[
            n
        ] for n in graph_visitor.preprocess_edges([], self.get_neighbors(v_start))]
        last_len = 0
        while len(queue) > 0:
            current_path = queue.pop()
            last_node = current_path[-1].dst
            is_full_path = (last_node == v_end)

            # Backtrack to common ancestor edge of last path.  Assumes that such
            # an edge exists, and the current path is that ancestor, plus
            # exactly one additional edge.
            for i in range(last_len - len(current_path) + 1):
                graph_visitor.backtrack()
            last_len = len(current_path)

            visit_result, path_data = graph_visitor.visit(current_path, is_full_path)
            if path_data is not None:
                # There can be no path to yield if it is unsatisfiable, or no
                # state has been created to return (e.g. quick_solve).
                yield path_data

            if visit_result == VisitResult.CONTINUE and not is_full_path:
                for e in graph_visitor.preprocess_edges(current_path,
                        self.get_neighbors(last_node)):
                    queue.append(current_path + [e])
            elif visit_result == VisitResult.ABORT:
                break

        for i in range(last_len):
            graph_visitor.backtrack()

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
