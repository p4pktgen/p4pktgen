/*
 * Ofpat group logic
 */

#include "ofpat_state.h"

#include <plugin/of/inc/ofpat_groups.h>
#include <plugin/of/inc/ofpat_pipeline.h>

#include <pd/pd.h>
#include <bm/pdfixed/pd_pre.h>

#include <p4ofagent/p4ofagent.h>
#include <p4ofagent/parse.h>

#define MAX_GROUP_SIZE 32
#define PORT_MAP_LENGTH ((PRE_PORTS_MAX + 7)/8)

void
ofpat_group_alloc (uint32_t group_id, of_list_bucket_t *buckets,
                   enum ofp_group_type type) {
    uint32_t bucket_sig;
    ofpat_pipeline_key_t key;
    
    Pvoid_t aargs;
    PWord_t pv;

    of_bucket_t elt;
    of_list_action_t *actions;
    int rv;
    
    uint8_t *port_map;
    uint8_t *lag_map;
    port_map = P4OFAGENT_MALLOC (PORT_MAP_LENGTH);
    lag_map = P4OFAGENT_MALLOC (PORT_MAP_LENGTH);
    memset (port_map, 0, PORT_MAP_LENGTH);
    memset (lag_map, 0, PORT_MAP_LENGTH);

    p4_pd_entry_hdl_t mgrp;
    p4_pd_entry_hdl_t node_hdl;

    OF_LIST_BUCKET_ITER(buckets, &elt, rv) {
        bucket_sig = 0;
        aargs = (Pvoid_t) NULL;
        actions = of_bucket_actions_get (&elt);
        parse_actions (actions, &aargs, &bucket_sig);

        JLG (pv, aargs, OFPAT_OUTPUT);

        *(uint64_t *) port_map |= ((uint64_t) 1 << *(uint32_t *) *pv);

        memset (&key, 0, sizeof (key)); 
        ofpat_pipeline_key_new (NULL, &group_id, (uint16_t *) *pv, &key);
        ofpat_pipeline_add (bucket_sig, &key, &aargs);
    }

    p4_pd_mc_mgrp_create (P4_PRE_SESSION, P4_DEVICE_ID, group_id, &mgrp);
    p4_pd_mc_node_create (P4_PRE_SESSION, P4_DEVICE_ID, group_id,
                    port_map, lag_map, &node_hdl);
    p4_pd_mc_associate_node (P4_PRE_SESSION, P4_DEVICE_ID, mgrp, node_hdl, 0, 0);

    ofpat_state_group_store_mc (group_id, mgrp, node_hdl);
    ofpat_state_group_set_ports (group_id, port_map);
}

p4_pd_status_t
ofpat_group_create (uint32_t group_id, enum ofp_group_type type) {
    p4_pd_entry_hdl_t eh;
    p4_pd_status_t status = 0;
    ofpat_pipeline_key_t key;

    ofpat_pipeline_key_new (NULL, &group_id, NULL, &key);

    ${pd_prefix}ofpat_group_ingress_match_spec_t ms;
    ${pd_prefix}ofpat_group_ingress_mc_action_spec_t as;

    p4_pd_entry_hdl_t hdl;
    p4_pd_entry_hdl_t node;

    ms.openflow_metadata_group_id = group_id;

    if (ofpat_state_group_get_mc (group_id, &hdl, &node)) {
        return 1;
    }

    as.action_mcindex = hdl;

    status |= ${pd_prefix}ofpat_group_ingress_table_add_with_ofpat_group_ingress_mc
        (P4_PD_SESSION, P4_SINGLE_DEVICE, &ms, &as, &eh);


    ofpat_state_group_store_eh (&key, eh);

    return status;
}

p4_pd_status_t
ofpat_group_delete (uint32_t group_id, enum ofp_group_type type) {
    p4_pd_status_t status = 0;
    uint8_t *port_map;

    p4_pd_entry_hdl_t mgrp;
    p4_pd_entry_hdl_t node;

    if (ofpat_state_group_get_mc (group_id, &mgrp, &node)) {
        return 1;
    }

    if (ofpat_state_group_get_ports (group_id, &port_map)) {
        P4_LOG ("Could not get group ports");
        return 1;
    }

    p4_pd_mc_mgrp_destroy (P4_PRE_SESSION, P4_DEVICE_ID, mgrp);
    p4_pd_mc_node_destroy (P4_PRE_SESSION, P4_DEVICE_ID, node);

    ofpat_pipeline_key_t key;
    uint16_t i, j, egr_port;
    for (i = 0, j = 0; (j * 8 + i) < PORT_MAP_LENGTH; i = !((i + 1) % 8) ? j++, 0 : i + 1) {
        if (*(port_map + j) & (1 << i)) {
            egr_port = j * 8 + i;
            ofpat_pipeline_key_new (NULL, &group_id, &egr_port, &key);
            status |= ofpat_pipeline_del (&key);
            ofpat_state_pipeline_delete (&key);
        }
    }

    free ((void *)port_map);

    return status;
}
