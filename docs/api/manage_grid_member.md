### Available grid membership operations:

- *reject*: Explicitly deny the node that is attempting to join the grid. The node will remain in the list of nodes that have been rejected unless a subsequent request uses the delete operation on the node.
- *add*: Accepts the new grid member into this grid and allow it to participate in the grid synchronization process. For newly setup nodes, this will cause the remainder of the node setup to begin, which can take up to an hour to complete on some systems.
- *delete*: Deletes the grid member. If the node was previously accepted into the grid it will be removed from the grid and removed from the grid member list. The SOC grid list will continue to show the node until the SOC process (or the manager node itself) is restarted.
- *test*: Ingests preselected test data into the node. This should only be executed on sensor nodes, such as standalone nodes, forward nodes, etc.
- *restart*: Restarts the operating system on the given node. Note that restarting the manager node will take SOC offline for several minutes. Restarting all grid nodes concurrently can result in missed network data.
