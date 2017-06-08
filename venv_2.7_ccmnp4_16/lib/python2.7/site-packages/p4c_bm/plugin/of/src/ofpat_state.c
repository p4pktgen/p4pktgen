/*
 * State management for ofpat.c
 */

#include <Judy.h>
#include "ofpat_state.h"
#include <p4ofagent/p4ofagent.h>


/********************
 * Index for egress pipeline *
 ********************/

typedef struct __attribute__((__packed__)) ofpat_state_pipeline_hash_key {
    uint64_t index;
    uint32_t group_id;
    uint16_t egr_port;
    uint64_t type;
} ofpat_state_pipeline_hash_key_t;

static void
ofpat_state_pipeline_hash_key_new (ofpat_pipeline_key_t *key, uint64_t type,
                                   ofpat_state_pipeline_hash_key_t *hkey) {
    if (key->index != NULL) {
        hkey->index    = *key->index;
        hkey->group_id = -1;
        hkey->egr_port = -1;
    } else {
        hkey->group_id = *key->group_id;
        hkey->egr_port = *key->egr_port;
        hkey->index    = -1;
    }

    hkey->type = type;
}

/**********************************
 * Operations on pipelines *
 **********************************/

#define MAX_ACTION_VAL OFPAT_PUSH_PBB

static Pvoid_t pipelines = (Pvoid_t) NULL;

void
ofpat_state_pipeline_delete (ofpat_pipeline_key_t *key) {
    int rc;

    ofpat_state_pipeline_hash_key_t hkey;
    ofpat_state_pipeline_hash_key_new (key, 0, &hkey);

    for (; hkey.type <= MAX_ACTION_VAL; hkey.type++) {
        JHSD (rc, pipelines, &hkey, sizeof (hkey));
    }
}

void
ofpat_state_pipeline_store_eh (ofpat_pipeline_key_t *key,
                               enum ofp_action_type type,
                               p4_pd_entry_hdl_t eh) {
    PWord_t pv;

    ofpat_state_pipeline_hash_key_t hkey;
    ofpat_state_pipeline_hash_key_new (key, type, &hkey);
    JHSI (pv, pipelines, &hkey, sizeof (hkey));
    *pv = eh;
}

int
ofpat_state_pipeline_get_eh (ofpat_pipeline_key_t *key,
                             enum ofp_action_type type,
                             p4_pd_entry_hdl_t *eh) {
    PWord_t pv;

    ofpat_state_pipeline_hash_key_t hkey;
    ofpat_state_pipeline_hash_key_new (key, type, &hkey);
    JHSG (pv, pipelines, &hkey, sizeof (hkey));
    if (pv == NULL) {
        P4_LOG ("ofpat_state_pipeline_get: key not present");
        return 1;
    }
    *eh = (p4_pd_entry_hdl_t) *pv;
    return 0;
}

int
ofpat_state_pipeline_get_next_eh (ofpat_pipeline_key_t *key,
                                  enum ofp_action_type *type,
                                  p4_pd_entry_hdl_t *eh) {
    PWord_t pv = NULL;

    ofpat_state_pipeline_hash_key_t hkey;
    ofpat_state_pipeline_hash_key_new (key, *type + 1, &hkey);
    while (hkey.type <= MAX_ACTION_VAL) {
        JHSG (pv, pipelines, &hkey, sizeof (hkey));
        if (pv) {
            break;
        }
        hkey.type++;
    }

    if (hkey.type > MAX_ACTION_VAL) {
        return 1;
    } else {
        *type = hkey.type;
    }
    
    *eh = (p4_pd_entry_hdl_t) *pv;
    return 0;
}

int
ofpat_state_pipeline_get_first_eh (ofpat_pipeline_key_t *key,
                                   enum ofp_action_type *type,
                                   p4_pd_entry_hdl_t *eh) {
    return ofpat_state_pipeline_get_next_eh (key, type, eh);
}

/****************************
 * operations on group_id_* *
 ****************************/

static Pvoid_t group_id_eh        = (Pvoid_t) NULL;
static Pvoid_t group_id_egress_eh = (Pvoid_t) NULL;
static Pvoid_t group_id_hdl       = (Pvoid_t) NULL;
static Pvoid_t ports              = (Pvoid_t) NULL;

void
ofpat_state_group_store_eh (ofpat_pipeline_key_t *key, p4_pd_entry_hdl_t eh) {
    PWord_t pv;

    if (!key->egr_port) {
        JLI (pv, group_id_eh, *key->group_id);
        *pv = eh;
    } else {
        ofpat_state_pipeline_hash_key_t hash_key;
        ofpat_state_pipeline_hash_key_new (key, -1, &hash_key);
        JHSI (pv, group_id_egress_eh, &hash_key, sizeof (ofpat_state_pipeline_hash_key_t));
        *pv = eh;
    }
}

int
ofpat_state_group_get_eh (ofpat_pipeline_key_t *key, p4_pd_entry_hdl_t *eh) {
    PWord_t pv;
    int rc;

    if (!key->egr_port) {
        if (!(J1T (rc, group_id_eh, *key->group_id))) {
            P4_LOG ("Invalid group id");
            return 1;
        }

        JLG (pv, group_id_eh, *key->group_id);
        *eh = (p4_pd_entry_hdl_t) *pv;
    } else {
        ofpat_state_pipeline_hash_key_t hash_key;
        ofpat_state_pipeline_hash_key_new (key, -1, &hash_key);
        JHSG (pv, group_id_egress_eh, &hash_key, sizeof (ofpat_state_pipeline_hash_key_t));
        if (!pv) {
            P4_LOG ("Invalid group id");
            return 1;
        } 

        *eh = (p4_pd_entry_hdl_t) *pv;
    }
    return 0;
}

void
ofpat_state_group_store_mc (uint32_t group_id, p4_pd_entry_hdl_t mgid,
                            p4_pd_entry_hdl_t node) {
    PWord_t pv;
    JLI (pv, group_id_hdl, group_id);
    *pv = ((uint64_t) node << 31) + mgid;
}

int
ofpat_state_group_get_mc (uint32_t group_id, p4_pd_entry_hdl_t *mgid,
                          p4_pd_entry_hdl_t *node) {
    PWord_t pv;
    int rc;

    if (!(J1T (rc, group_id_hdl, group_id))) {
        P4_LOG ("Invalid group id");
        return 1;
    }

    JLG (pv, group_id_hdl, group_id);
    *mgid = (p4_pd_entry_hdl_t) *pv;
    *node = (p4_pd_entry_hdl_t) (*pv >> 31);
    return 0;
}

void
ofpat_state_group_store_lag (uint32_t group_id, p4_pd_grp_hdl_t lag) {
    PWord_t pv;
    JLI (pv, group_id_hdl, group_id);
    *pv = lag;
}

int
ofpat_state_group_get_lag (uint32_t group_id, p4_pd_grp_hdl_t *lag) {
    PWord_t pv;
    int rc;

    if (!(J1T (rc, group_id_hdl, group_id))) {
        P4_LOG ("Invalid group id");
        return 1;
    }

    JLG (pv, group_id_hdl, group_id);
    *lag = (p4_pd_grp_hdl_t) *pv;
    return 0;
}

void
ofpat_state_group_set_ports (uint32_t group_id, uint8_t *port_map) {
    PWord_t pv;
    JLI (pv, ports, group_id);
    *pv = (uint64_t) port_map;
}

int
ofpat_state_group_get_ports (uint32_t group_id, uint8_t **port_map) {
    PWord_t pv;
    int rc;

    if (!(J1T (rc, ports, group_id))) {
        P4_LOG ("Invalid group id");
        return 1;
    }

    JLG (pv, ports, group_id);
    *port_map = (uint8_t *) *pv;
    return 0;
}

int
ofpat_state_group_delete_ports (uint32_t group_id) {
    uint8_t *port_map;
    if (ofpat_state_group_get_ports (group_id, &port_map)) {
        P4_LOG ("Cannot delete group lag ports");
        return 1;
    }

    int rc;
    JLD (rc, ports, group_id);
    return 0;
}
