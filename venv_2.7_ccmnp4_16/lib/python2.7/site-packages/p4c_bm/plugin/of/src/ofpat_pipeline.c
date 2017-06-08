/*
 * OFPAT pipeline and group handling
 */

#include "ofpat_state.h"

#include <plugin/of/inc/ofpat_pipeline.h>

#include <p4ofagent/p4ofagent.h>


static int rc;
static PWord_t pv;

/********
 * Keys *
 ********/

void
ofpat_pipeline_key_new (uint64_t *index, uint32_t *group_id,
                        uint16_t *egr_port, ofpat_pipeline_key_t *key) {
    key->index = index;
    key->group_id = group_id;
    key->egr_port = egr_port;
}

/*****************************
 * pipeline match and action *
 *****************************/

void
ofpat_match_get (ofpat_match_t *ms, ofpat_pipeline_key_t *key) {
    if (key->group_id && key->egr_port) {
        ms->group_id = *key->group_id;
        ms->egr_port = *key->egr_port;
        ms->group_id_mask = -1;
        ms->egr_port_mask = -1;
        ms->index_mask = 0;
    } else {
        ms->index = *(uint32_t *) key->index;
        ms->index_mask = -1;
        ms->group_id_mask = 0;
        ms->egr_port_mask = 0;
    }
}

void*
ofpat_action_get (Pvoid_t *aargs, enum ofp_action_type t) {
    if (!(J1T (rc, *aargs, t))) {
        P4_LOG ("No arg for ofp_action_type");
        return NULL;
    } else {
        JLG (pv, *aargs, t);
        return (void *) *pv;
    }
}

/****************************************
 * special match for ofpat_group_egress *
 ****************************************/

typedef struct ofpat_group_egress_match_ {
    uint32_t group_id;
    uint16_t egr_port;
} ofpat_group_egress_match_spec_t_;

/*************
 * Pipelines *
 *************/

//:: from p4c_bm.of import *
//:: 
//:: def is_ofpat_table(table_name):
//::   return table_name[:6] == "ofpat_"
//:: #enddef
//:: 
//:: def action_arg_assign(param, get_c_type):
//::   name, width = param[0]
//::   if width > 4:
//::     return "memcpy (as." + name + ", (uint8_t *) *pv, " + width + ");"
//::   else:
//::     return "as." + name + " = *(" + get_c_type(width) + "*) *pv;"
//::   #endif
//:: #enddef
//::
//:: ofpat_helper_tables = ["ofpat_group_egress", "ofpat_group_ingress"]
//:: args_list = "(P4_PD_SESSION, P4_SINGLE_DEVICE, &ms, &as, &eh)"
p4_pd_status_t
ofpat_pipeline_add (uint32_t bmap, ofpat_pipeline_key_t *key, Pvoid_t *aargs) {
    p4_pd_entry_hdl_t eh;
    p4_pd_status_t status = 0;
    int priority = (key->group_id) ? 3 : 1;

    if (key->group_id) {
        ${pd_prefix}ofpat_group_egress_match_spec_t ms;
        ${pd_prefix}ofpat_group_egress_update_action_spec_t as;

       // ms.openflow_metadata_group_id = *key->group_id;
       // ms.standard_metadata_egress_port = *key->egr_port;
       // as.action_bmap = bmap;

        ((ofpat_group_egress_match_spec_t_ *) &ms)->group_id = *key->group_id;
        ((ofpat_group_egress_match_spec_t_ *) &ms)->egr_port = *key->egr_port;
        as.action_bmap = bmap;

        status = ${pd_prefix}ofpat_group_egress_table_add_with_ofpat_group_egress_update
            ${args_list};

        if (status) {
            return status;
        } else {
            ofpat_state_group_store_eh (key, eh); 
        }
    }

//:: for table_name, table in tables.items():
//::   if not is_ofpat_table(table_name) or table_name in ofpat_helper_tables:
//::     continue
//::   #endif
    if (bmap & (1 << ${of_action_vals[table_name]})${" && !key->group_id" if table_name == "ofpat_output" else ""}) {
        ${pd_prefix}${table_name}_match_spec_t ms;
        ofpat_match_get ((ofpat_match_t *) &ms, key);

//::   if table_name == "ofpat_set_field":
        Pvoid_t field_vals;
        Word_t field_type = 0;
        
        JLG (pv, *aargs, OFPAT_SET_FIELD);
        field_vals = (Pvoid_t) *pv;
        
        JLF (pv, field_vals, field_type);
        
        while (pv) {
            switch (field_type) {
//::   for action_name, action in table.actions.items():
//::     if action_name == "nop":
//::       continue
//::     #endif
//::     field_type = of_set_fields[action_name]
                case ${field_type}:
                {
                    ${pd_prefix}${action_name}_action_spec_t as;
//::     aparams = gen_action_params(action.runtime_data)
//::     args_list = "(P4_PD_SESSION, P4_SINGLE_DEVICE, &ms, priority, &as, &eh)"
                    ${action_arg_assign(aparams, get_c_type)}

                    status |= ${pd_prefix}${table_name}_table_add_with_${action_name}
                        ${args_list};
                    if (status) {
                        return status;
                    } else {
                        ofpat_state_pipeline_store_eh (key, ${of_action_vals[table_name]}, eh);
                    }
                }
                    break;
//::   #endfor
            default:
                P4_LOG ("Bad match field type for set field");
            }

            JLN (pv, field_vals, field_type);
        }
//::   else:
//::     for action_name, action in table.actions.items():
//::       if action_name == "nop":
//::         continue
//::       #endif
//::       aparams = gen_action_params(action.runtime_data)
//::       if aparams:
//::         name, width = aparams[0]
        ${pd_prefix}${table_name}_action_spec_t as;
        as.${name} =
            *(${get_c_type (width)} *) (ofpat_action_get (aargs, ${of_action_vals[table_name]}));
//::       #endif
//::       args_list = ["P4_PD_SESSION", "P4_SINGLE_DEVICE", "&ms", "priority",
//::                    "&as, &eh" if aparams else "&eh"]
        status |= ${pd_prefix}${table_name}_table_add_with_${action_name}
            (${(", ").join(args_list)});

        if (status) {
            return status;
        } else {
            ofpat_state_pipeline_store_eh (key, ${of_action_vals[table_name]}, eh);
        }
//::     #endfor
//::   #endif

    }

//:: #endfor
    return status;
}

p4_pd_status_t
ofpat_pipeline_mod (uint32_t bmap, ofpat_pipeline_key_t *key, Pvoid_t *aargs) {
    p4_pd_entry_hdl_t eh;
    p4_pd_status_t status = 0;

    if (key->group_id) {
        ${pd_prefix}ofpat_group_egress_update_action_spec_t as;

        as.action_bmap = bmap;

        if (ofpat_state_group_get_eh (key, &eh)) {
            return 1;
        }

        status = ${pd_prefix}ofpat_group_egress_table_modify_with_ofpat_group_egress_update
            (P4_PD_SESSION, P4_DEVICE_ID, eh, &as);

        if (status) {
            return status;
        }
    }

//:: for table_name, table in tables.items():
//::   if not is_ofpat_table(table_name) or table_name in ofpat_helper_tables:
//::     continue
//::   #endif
    if (bmap & (1 << ${of_action_vals[table_name]})) {
//::   if table_name == "ofpat_set_field":
//::     args_list = "(P4_PD_SESSION, P4_DEVICE_ID, eh, &as)"
        Pvoid_t field_vals;
        Word_t field_type = 0;
        
        JLG (pv, *aargs, OFPAT_SET_FIELD);
        field_vals = (Pvoid_t) *pv;
        
        JLF (pv, field_vals, field_type);
        
        while (pv) {
            switch (field_type) {
//::   for action_name, action in table.actions.items():
//::     if action_name == "nop":
//::       continue
//::     #endif
//::     field_type = of_set_fields[action_name]
                case ${field_type}:
                {
                    ${pd_prefix}${action_name}_action_spec_t as;
//::     aparams = gen_action_params(action.runtime_data)
                    ${action_arg_assign(aparams, get_c_type)}

                    if (ofpat_state_pipeline_get_eh (key, ${of_action_vals[table_name]}, &eh)) {
                        return 1;
                    }

                    status |= ${pd_prefix}${table_name}_table_modify_with_${action_name}
                        ${args_list};
                }
                    break;
//::   #endfor
            default:
                P4_LOG ("Bad match field type for set field");
            }

            JLN (pv, field_vals, field_type);
        }
//::   else:
//::     for action_name, action in table.actions.items():
//::       if action_name == "nop":
//::         continue
//::       #endif
//::       aparams = gen_action_params(action.runtime_data)
//::       if aparams:
//::         name, width = aparams[0]
        ${pd_prefix}${table_name}_action_spec_t as;
        as.${name} =
            *(${get_c_type (width)} *) (ofpat_action_get (aargs, ${of_action_vals[table_name]}));

//::       #endif
//::       args_list = ["P4_PD_SESSION", "P4_DEVICE_ID","eh, &as" if aparams else "eh"]
        if (ofpat_state_pipeline_get_eh (key, ${of_action_vals[table_name]}, &eh)) {
            return 1;
        }

        status |= ${pd_prefix}${table_name}_table_modify_with_${action_name}
            (${(", ").join(args_list)});

//::     #endfor
//::   #endif
        if (status) {
            return status;
        }
    }

//:: #endfor

    return status;
}

p4_pd_status_t
ofpat_pipeline_set_default_nop () {
    p4_pd_status_t status = 0;
    p4_pd_entry_hdl_t eh;

    status = ${pd_prefix}ofpat_group_egress_set_default_action_nop
        (P4_PD_SESSION, P4_SINGLE_DEVICE, &eh);

    if (status) {
        return status;
    }

    return status;
}

p4_pd_status_t
ofpat_pipeline_del (ofpat_pipeline_key_t *key) {
    p4_pd_entry_hdl_t eh;
    p4_pd_status_t status = 0;

    if (key->group_id) {
        if (ofpat_state_group_get_eh (key, &eh)) {
            return 1;
        }

        status = ${pd_prefix}ofpat_group_egress_table_delete
            (P4_PD_SESSION, P4_DEVICE_ID, eh);

        if (status) {
            return status;
        }
    }

    enum ofp_action_type type = -1;

    int invalid =
        ofpat_state_pipeline_get_first_eh (key, &type, &eh);

    while (!invalid) {
        switch (type) {
//:: args_list = "(P4_PD_SESSION, P4_DEVICE_ID, eh)"
//:: for table_name, table in tables.items():
//::   if not is_ofpat_table(table_name) or table_name in ofpat_helper_tables:
//::     continue
//::   #endif
//::   atype = of_action_vals[table_name]
//::   if atype == "OFPAT_SET_NW_TTL" or atype == "OFPAT_DEC_NW_TTL":
//::     continue
//::   else:
            case ${atype}:
                status |=
                    ${pd_prefix}${table_name}_table_delete
                        ${args_list};
                if (status) {
                    return status;
                }
                break;
//::   #endif
//:: #endfor
//:: if "ofpat_set_nw_ttl_ipv4" in tables:
            case OFPAT_SET_NW_TTL:
                ${pd_prefix}ofpat_set_nw_ttl_ipv4_table_delete
                    ${args_list};
                ${pd_prefix}ofpat_set_nw_ttl_ipv6_table_delete
                    ${args_list};
                break;
            case OFPAT_DEC_NW_TTL:
                ${pd_prefix}ofpat_dec_nw_ttl_ipv4_table_delete
                    ${args_list};
                ${pd_prefix}ofpat_dec_nw_ttl_ipv6_table_delete
                    ${args_list};
                break;
//:: #endif
            default:
                P4_LOG ("delete of unsupported table");
        }
        invalid =
            ofpat_state_pipeline_get_next_eh (key, &type, &eh); 
    }

    return status;
}
