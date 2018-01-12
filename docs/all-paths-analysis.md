# Finding lowest common ancestors in a DAG


## Definitions and basic properties

Definition: In a directed graph, call a node with in-degree 0 a
'source' node.  Similarly, call a node with out-degree 0 a 'sink'
node.

Given: a DAG (directed acyclic graph) with exactly one source node S
(call it S for 'start'), and exactly one sink node E (call it E for
'end').

True or false? Every node is reachable via a directed path from S.

Seems obvious.  Start from a node N and go backwards along any path
you care to.  Every node has in-degree at least 1, except for S, so it
is always possible to keep going backwards along edges until you reach
S.  You will never fall into any cycles because the graph is acyclic.

That proves also that backwards from all nodes, every path eventually
leads to S.

Proved:

* Every node is reachable via a forward directed path starting at S.
* For every node N, every backwards path eventually leads to S.


By a similar argument, but following paths in the forward direction
along edges we can argue that:

* Every node is reachable via a backward directed path starting at E.
* For every node N, every forward path eventually leads to E.


## Definition of a lowest common ancestor

Definition: Among all paths backwards from N, call a node V a 'common
ancestor' if V is on _every_ path backwards from N.

Note: For a general DAG, there might not be any common ancestor nodes
other than N itself on every path, because there might be multiple
nodes with in-degree 0 reachable via backward paths from N.  If so, no
other common ancestor nodes for N may exist.

Small example DAG that does not satisfy the constraints of having a
start and end node as defined above:

    A  --\
          -->  N
          -->
    B  --/

Proof that in a single-source DAG, every node N has a unique lowest
common ancestor LCA(N):

Consider a node N not equal to S.  Enumerate all paths from S to N.
All contain at least the nodes S and N, of course, so they are both
candidates for being the lowest common ancestor, if there is one.

Suppose there are two distinct nodes V1 and V2 that are in all S-to-N
paths.

If there were some paths with V1 earlier than V2, and others with V2
earlier than V1, then there would be a cycle in the graph.  Since the
graph is acyclic, this is impossible.

Thus all such paths either have V1 earlier than V2, or V2 earlier than
V1.

Without loss of generality, assume V1 is earlier than V2 in all such
paths.

Then V1 is not the lowest common ancestor.  V2 might be.

Consider the set A of all nodes that are in all S-to-N paths.  The set
A includes at least S and N.

For every pair of distinct nodes in A, they can be pairwise compared
as earlier or later, like V1 and V2 above.

Sort the elements of A in this order.  In this sorted order, S must be
first and N must be last.  Pick the last node just before N.  That is
what we call the lowest common ancestor.  The lowest common ancestor
might be S.


## Algorithm for finding a lowest common ancestor

What is an efficient algorithm, given a single-source DAG and a node
N, for finding the lowest common ancestor LCA(N)?

There is a fairly simple linear time algorithm based upon depth-first
search to find all "articulation points" in the graph, where an
articulation point is a node such that removing it leaves the graph
with more connected components than there were in the original graph.

On-line references for this algorithm:

    https://www.geeksforgeeks.org/articulation-points-or-cut-vertices-in-a-graph/
    https://courses.cs.washington.edu/courses/cse421/04su/slides/artic.pdf

If one cares about the direction of the edges (which I do not yet know
if the direction is significant for this purpose), you can use maximum
flow algorithms to find a maximum flow from S to E, in a modified
graph where every original node N is replaced with two nodes N1 and N2
with an edge from N1 to N2, all original edges into N go into N1, and
all original edges out of N come out of N2.  Do this substitution for
all nodes _except_ S and E.

The reason for these substitutions is to allow at most a flow of 1 to
pass through any node from the original graph.  This constraint is
enforced by the creation of a capacity 1 edge from N1 to N2.

In this modified graph, if the maximum flow from S to E has magnitude
2 or more, then there are that many node-disjoint paths from S to E in
the original graph, and the lowest common ancestor of E must be S.

If the maximum flow from S to E has magnitude 1, then there are one or
more nodes that appear on all paths from S to E.  The one closest to E
can be found by finding all nodes reachable from E along paths in the
"residual graph" constructed from the original graph and the max flow
found.  That set of nodes form one set in a minimum cut of the graph,
with the rest of the nodes being in the other set.  There should be
only 1 edge that goes across this cut, and that edge should be of the
form (N1, N2) for some node N in the original graph.  That node N is
the lowest common ancestor for E.

On-line reference for proof that finding all nodes reachable in a
flow's residual graph forms one 'side' of a cut:

    http://www.cs.princeton.edu/courses/archive/spr04/cos226/lectures/maxflow.4up.pdf

More efficient algorithms exist, if one wishes to do lowest common
ancestors for many pairs of nodes in a graph:

    https://en.wikipedia.org/wiki/Lowest_common_ancestor
    http://www.herts.ac.uk/dag-pre-processing-downloadable-code/adaptive-pre-processing-of-dag

It isn't clear to me that solving this faster than linear time per
node will produce much noticeable speedup for the kinds of problems
that we want to solve inside `p4pktgen`.

I have implemented this augmenting path method in class Graph as
method `lowest_common_ancestor`.  Calculating `lowest_common_ancestor`
for every node in the ingress control flow graph for file
`examples/switch-p416-nohdrstacks.json` takes a bit less than 0.4
seconds on my 2015 MacBook Pro, which seems like a reasonably low
amount of time for such a graph, and not worth a lot of development
time to make it faster.
