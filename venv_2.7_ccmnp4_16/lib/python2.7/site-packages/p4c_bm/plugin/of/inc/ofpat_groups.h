#ifndef _OFPAT_GROUPS_H_
#define _OFPAT_GROUPS_H_

#include <loci/loci.h>
#include <p4ofagent/openflow-spec1.3.0.h>

/* Allocates a mc/lag group and installs flows in the ofpat pipeline
 * @param group_id Group id given by controller
 * @param buckets Action buckets given by controller
 * @param type Type of group (select, all, etc)
 */
void
ofpat_group_alloc (uint32_t group_id, of_list_bucket_t *buckets,
                   enum ofp_group_type type);

/* Adds a group to the ingress group table
 * @param group_id Group id given by controller 
 * @param type Type of group (select, all, etc)
 */
p4_pd_status_t
ofpat_group_create (uint32_t group_id, enum ofp_group_type type);

/* Deletes a group.
 * @param group_id Group id given by controller
 * @param type Type of group (select, all, etc)
 */
p4_pd_status_t
ofpat_group_delete (uint32_t group_id, enum ofp_group_type type);

#endif /* _OFPAT_GROUPS_H_ */
