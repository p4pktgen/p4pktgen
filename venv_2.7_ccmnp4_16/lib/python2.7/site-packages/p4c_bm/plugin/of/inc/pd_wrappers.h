#ifndef _PD_WRAPPERS_H_
#define _PD_WRAPPERS_H_

#include <Judy.h>

void
openflow_init (Pvoid_t *adds, Pvoid_t *mods, Pvoid_t *defs,
               Pvoid_t *dels, Pvoid_t *read_bytes_hit,
               Pvoid_t *read_bytes_missed, Pvoid_t *read_packets_hit,
               Pvoid_t *read_packets_missed, Pvoid_t *per_flow_stats_bytes,
               Pvoid_t *per_flow_stats_packets);

uint8_t
num_openflow_tables ();

#endif /* _PD_WRAPPERS_ */
