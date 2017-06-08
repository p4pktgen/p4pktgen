#ifndef _OFPAT_PIPELINE_H_
#define _OFPAT_PIPELINE_H_

/*
 * Ofpat pipeline datatypes and API 
 */

#include <bm/pdfixed/pd_common.h>

#include <p4ofagent/openflow-spec1.3.0.h>

#include <Judy.h>

/* Indexes pipeline in pipeline state */
typedef struct ofpat_pipeline_key {
    uint64_t *index;
    uint32_t *group_id;
    uint16_t *egr_port;
} ofpat_pipeline_key_t;

/* Fill in pipeline key */
void
ofpat_pipeline_key_new (uint64_t *index, uint32_t *group_id,
                        uint16_t *egr_port, ofpat_pipeline_key_t *key);

/* Generic match struct for pipeline entries */
typedef struct ofpat_pipeline_match {
    uint32_t index;
    uint32_t index_mask;
    uint32_t group_id;
    uint32_t group_id_mask;
    uint16_t egr_port;
    uint16_t egr_port_mask;
} ofpat_match_t;

/* Fill in match struct */
void
ofpat_match_get (ofpat_match_t *ms, ofpat_pipeline_key_t *key);

/* Returns pointer to action arg val indexed by t
 * @param aargs Datastructure holding action arg vals
 * @param t The action type 
 */
void*
ofpat_action_get (Pvoid_t *aargs, enum ofp_action_type t);

/* Adds an OFPAT pipeline
 * @param bmap Bitmap of actions to add
 * @param key Used to index pipeline
 * @param aargs OFPAT arguments, indexed by OFPAT enum vals
 */
p4_pd_status_t
ofpat_pipeline_add (uint32_t bmap, ofpat_pipeline_key_t *key,
                    Pvoid_t *aargs);

/* Modifies an OFPAT pipeline
 * @param bmap Bitmap of actions to add
 * @param key Used to index pipeline
 * @param aargs OFPAT arguments, indexed by OFPAT enum vals
 */
p4_pd_status_t
ofpat_pipeline_mod (uint32_t bmap, ofpat_pipeline_key_t *key,
                    Pvoid_t *aargs);

/* Sets default entries to nop */
p4_pd_status_t
ofpat_pipeline_set_default_nop ();

/* Deletes an OFPAT pipeline.
 * @param key Used to get the pipeline
 */
p4_pd_status_t
ofpat_pipeline_del (ofpat_pipeline_key_t *key);

#endif /* _OFPAT_PIPELINE_H_ */
