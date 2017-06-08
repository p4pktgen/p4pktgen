#ifndef _OFPAT_STATE_H_
#define _OFPAT_STATE_H_

/*
 * State management of ofpat.c
 */

#include <bm/pdfixed/pd_pre.h>
#include <pd/pd.h>
#include <plugin/of/inc/ofpat_pipeline.h>
#include <p4ofagent/openflow-spec1.3.0.h>

/************************************************************
 * All accessors return void, 1 on failure, or 0 on success *
 ************************************************************/

/* Deletes the pipeline indexed by key.
 * @param key Indexes the pipeline
 */
void
ofpat_state_pipeline_delete (ofpat_pipeline_key_t *key);

/* Stores an entry handle (flow id) in the pipeline.
 * @param key The key for this pipeline
 * @param type One of OFPAT
 * @param eh The entry handle to store
 */
void
ofpat_state_pipeline_store_eh (ofpat_pipeline_key_t *key,
                               enum ofp_action_type type,
                               p4_pd_entry_hdl_t eh);

/* Get the entry handle in the pipeline indexed by key.
 * @param key The key for this pipeline
 * @param type One of OFPAT
 * @param eh [out] The entry handle to get 
 */
int
ofpat_state_pipeline_get_eh (ofpat_pipeline_key_t *key,
                             enum ofp_action_type type,
                             p4_pd_entry_hdl_t *eh);

/* Get the next entry handle after that indexed by type
 * in the pipeline indexed by key.
 * @param key The key for this pipeline
 * @param type [in, out] One of OFPAT
 * @param eh [out] The entry handle to store
 */
int
ofpat_state_pipeline_get_next_eh (ofpat_pipeline_key_t *key, 
                                  enum ofp_action_type *type,
                                  p4_pd_entry_hdl_t *eh);

/* Get the next entry handle after that indexed by type in the
 * pipeline indexed by key.
 * @param key The key for this pipeline
 * @param type [in, out] One of OFPAT
 * @param eh [out] The entry handle to store
 */
int
ofpat_state_pipeline_get_first_eh (ofpat_pipeline_key_t *key,
                                   enum ofp_action_type *type,
                                   p4_pd_entry_hdl_t *eh);

/**********
 * GROUPS *
 **********/

/* Associates a group-table entry handle with a group id.
 * @param group_id The group id given by the controller
 * @param eh The entry handle to store
 */
void
ofpat_state_group_store_eh (ofpat_pipeline_key_t *key, p4_pd_entry_hdl_t eh);

/* Gets the group-table entry handle associated with a group id.
 * @param group_id The group id given by the controller
 * @param eh [out] The entry hdl to get
 */
int
ofpat_state_group_get_eh (ofpat_pipeline_key_t *key, p4_pd_entry_hdl_t *eh);

/* Associates multicast information with a group id.
 * @param group_id The group id given by the controller
 * @param mgid Multicast group id
 * @param l1 L1 node handle
 */
void
ofpat_state_group_store_mc (uint32_t group_id, p4_pd_entry_hdl_t mgid, 
                            p4_pd_entry_hdl_t l1);

/* Gets multicast information associated with group id.
 * @param group_id The group id given by the controller
 * @param mgid [out] Multicast group id
 * @param l1 [out] L1 node handle
 */
int
ofpat_state_group_get_mc (uint32_t group_id, p4_pd_entry_hdl_t *mgid,
                          p4_pd_entry_hdl_t *l1);

/* Associates LAG handle with group id.
 * @param group_id The group id given by the controller
 * @param lag The LAG group handle
 */
void
ofpat_state_group_store_lag (uint32_t group_id, p4_pd_grp_hdl_t lag);

/* Gets LAG lag associated with group id.
 * @param group_id The group id given by the controller
 * @param lag [out] The LAG group handle
 */
int
ofpat_state_group_get_lag (uint32_t group_id, p4_pd_grp_hdl_t *lag);

/* Sets member egress ports */
void
ofpat_state_group_set_ports (uint32_t group_id, uint8_t *ports);

/* Gets member egress ports */
int
ofpat_state_group_get_ports (uint32_t group_id, uint8_t **ports);

/* Deletes member egress ports entry and frees port list. */
int
ofpat_state_group_delete_ports (uint32_t group_id);

#endif /* OFPAT_STATE_H_ */
