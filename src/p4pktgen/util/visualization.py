import logging

from graphviz import Digraph

from p4pktgen.hlir.transition import TransitionType, BoolTransition


def break_into_lines(s, max_len=40):
    """Break s into lines, only at locations where there is whitespace in
    s, at most `max_len` characters long.  Allow longer lines in
    the returned string if there is no whitespace"""
    words = s.split()
    out_lines = []
    cur_line = ""
    for word in words:
        if (len(cur_line) + 1 + len(word)) > max_len:
            if len(cur_line) == 0:
                out_lines.append(word)
            else:
                out_lines.append(cur_line)
                cur_line = word
        else:
            if len(cur_line) > 0:
                cur_line += " "
            cur_line += word
    if len(cur_line) > 0:
        out_lines.append(cur_line)
    return '\n'.join(out_lines)


def generate_graphviz_graph(pipeline, graph, lcas=None):
    dot = Digraph(comment=pipeline.name)
    if lcas is None:
        lcas = {}
    for node in graph.graph:
        if node in lcas:
            lca_str = str(lcas[node])
            if node is None:
                node_str = "null"
            else:
                node_str = str(node)
            # By creating these edges with constraint "false",
            # GraphViz will lay out the graph the same as if these
            # edges did not exist, and then add these edges.  Without
            # doing this, the node placement with these extra edges
            # can be significantly different than without these edges,
            # and make the control flow more difficult to see, as it
            # isn't always top-to-bottom any longer.
            dot.edge(
                node_str,
                lca_str,
                color="orange",
                style="dashed",
                constraint="false")
        if node is None:
            continue
        assert node in pipeline.conditionals or node in pipeline.tables
        neighbors = graph.get_neighbors(node)
        node_label_str = None
        node_color = None
        if node in pipeline.conditionals:
            node_str = node
            shape = 'oval'
            if len(neighbors) > 0:
                assert isinstance(neighbors[0], BoolTransition)
                # True/False branch of the edge
                assert isinstance(neighbors[0].val, bool)
                si = neighbors[0].source_info
                # Quick and dirty check for whether the condition uses
                # a valid bit, but only for P4_16 programs, and only
                # if the entire condition is in the source_fragment,
                # which requires that the condition all be placed in
                # one line in the actual P4_16 source file.
                if (si is not None) and ('isValid' in si.source_fragment):
                    node_color = "red"
                node_label_str = ("%s (line %d)\n%s"
                                  "" % (node_str,
                                        -1 if si is None else si.line,
                                        "" if si is None else
                                        break_into_lines(si.source_fragment)))
        else:
            node_str = node
            shape = 'box'
        if node_label_str is None:
            node_label_str = node_str
        if node_color is None:
            node_color = "black"
        dot.node(node_str, node_label_str, shape=shape, color=node_color)
        for t in neighbors:
            transition = t
            neighbor = t.dst
            edge_label_str = ""
            edge_color = "black"
            edge_style = "solid"
            if node in pipeline.conditionals:
                if neighbor is None:
                    neighbor_str = "null"
                else:
                    neighbor_str = str(neighbor)
                assert isinstance(transition.val, bool)
                edge_label_str = str(transition.val)
                edge_style = "dashed"
            else:
                # Check for whether an action uses any add_header or
                # remove_header primitive actions.  These correspond
                # to the same named primitives in P4_14 programs, or
                # to setValid() or setInvalid() method calls in P4_16 programs.
                assert (transition.transition_type ==
                        TransitionType.ACTION_TRANSITION
                        or transition.transition_type ==
                        TransitionType.CONST_ACTION_TRANSITION)

                primitive_ops = [p.op for p in transition.action.primitives]
                change_hdr_valid = (("add_header" in primitive_ops)
                                    or ("remove_header" in primitive_ops))
                if change_hdr_valid:
                    edge_color = "green"
                    add_header_count = 0
                    remove_header_count = 0
                    for op in primitive_ops:
                        if op == "add_header":
                            add_header_count += 1
                        elif op == "remove_header":
                            remove_header_count += 1
                    edge_label_str = ""
                    if add_header_count > 0:
                        edge_label_str += "+%d" % (add_header_count)
                    if remove_header_count > 0:
                        edge_label_str += "-%d" % (remove_header_count)

                if neighbor is None:
                    neighbor_str = "null"
                else:
                    neighbor_str = str(neighbor)
            assert isinstance(neighbor_str, str)
            dot.edge(
                node_str,
                neighbor_str,
                edge_label_str,
                color=edge_color,
                style=edge_style)
    fname = '{}_dot.gv'.format(pipeline.name)
    dot.render(fname, view=False)
    logging.info("Wrote files %s and %s.pdf", fname, fname)
