//:: import sys
//:: import os
//:: from p4c_bm.of import *
//::
//:: map_mod = __import__(openflow_mapping_mod)
//::
#include <plugin/of/inc/pd_wrappers.h>
#include <plugin/of/inc/ofpat_pipeline.h>

#include <pd/pd.h>
#include <bm/pdfixed/pd_pre.h>

#include <p4ofagent/p4ofagent.h>
#include <p4ofagent/callbacks.h>
#include <p4ofagent/openflow-spec1.3.0.h>
#include <indigo/of_state_manager.h>

uint16_t
bit_mask_to_prefix (uint8_t *pv, int width) {
    uint16_t i;
    for (i = width * 8 - 1; i >= 0 && (*(pv + i / 8) & (1 << (i % 8))); i -= 1);
    return width * 8 - 1 - i;
}

/* ADD WRAPPERS */

//:: for table_name, table in tables.items():
//::   if table.act_prof or table_name not in map_mod.openflow_tables:
//::     continue
//::   #endif
//::   match_params = gen_match_params(table.key)
//::   of_match_params = map_mod.openflow_tables[table_name].match_fields
//::   args_list = ["sess_hdl", "dev_tgt"]
//::   name = "_".join([table_name, "add"])
//::   pd_name = pd_prefix + table_name + "_table_add_with_"
p4_pd_status_t
${name}
(
    of_match_t *match_fields,
    Pvoid_t *action_args,
    uint32_t sig,
    uint64_t flow_id,
    p4_pd_entry_hdl_t *entry_hdl,
    uint16_t *priority,
    uint32_t *ttl,
    p4_pd_sess_hdl_t sess_hdl,
    p4_pd_dev_target_t dev_tgt,
    uint8_t *signal
) {
//::   if match_params:
    ${pd_prefix + table_name + "_match_spec_t match_spec"};
    memset (&match_spec, 0, sizeof(match_spec));
//::     args_list.append("&match_spec")
//::   #endif
//::   if table.match_type == MatchType.TERNARY:
//::     args_list.append("*priority")
//::   #endif
//::   args_list.append("&action_spec")
    ${pd_prefix + "openflow_apply_action_spec_t action_spec"};
    memset(&action_spec, 0, sizeof(action_spec));
//::   if table.support_timeout:
//::     args_list.append("*ttl")
//::   #endif
//::   args_list += ["entry_hdl"]

    PWord_t pv;
    int rc;

//::   for fn, w in match_params:
//::     c_fn = get_c_name(fn)
//::     if c_fn in map_mod.openflow_tables[table_name].match_fields:
//::       val  = of_match_vals[map_mod.openflow_tables[table_name].match_fields[c_fn].field]
//::       mask = of_match_masks[map_mod.openflow_tables[table_name].match_fields[c_fn].field]
//::       fn_match_type = map_mod.openflow_tables[table_name].match_fields[c_fn].match_type
//::       if fn_match_type == "ternary":
//::         if w > 4:
    memcpy (match_spec.${c_fn + "_mask"}, ${mask}, ${w});
//::         else:
    match_spec.${c_fn + "_mask"} = ${mask};
//::         #endif
    if (${mask}) {
//::         if w > 4:
        memcpy (match_spec.${c_fn}, &${val}, ${w});
//::         else:
        match_spec.${c_fn} = ${val};
//::         #endif
    }
//::       elif fn_match_type == "lpm":
//::         if w > 4:
    memcpy (match_spec.${c_fn}, ${val}, ${w});
//::         else:
    match_spec.${c_fn} = ${val};
//::         #endif
    match_spec.${c_fn + "_prefix_length"} = bit_mask_to_prefix ((uint8_t *) &${mask}, ${w});
//::       else:
//::         if w > 4:
    memcpy (match_spec.${c_fn}, ${val}, ${w});
//::         else:
    match_spec.${c_fn} = ${val};
//::         #endif
//::       #endif
//::     #endif
//::   #endfor

//::   for fn, t, w in table.key:
//::     c_fn = get_c_name(fn)
//::     if c_fn not in of_match_params and t == MatchType.TERNARY:
//::       if w > 4:
    match_spec.${c_fn + "_mask"} = { [0 ... ${w - 1}] = 0 };
//::       else:
    match_spec.${c_fn + "_mask"} = 0;
//::       #endif
//::     #endif
//::   #endfor
    action_spec.action_bmap = sig;

    if ((J1T (rc, *action_args, OFPAT_GROUP))) {
        JLG (pv, *action_args, OFPAT_GROUP);
        action_spec.action_group_id = *(uint32_t *) *pv;
    } else {
        action_spec.action_index = (uint32_t) flow_id;
    }

    if ((J1T (rc, *action_args, OFPAT_OUTPUT))) {
        JLG (pv, *action_args, OFPAT_OUTPUT);
        if (*(uint32_t *) *pv == OFPP_CONTROLLER) {
            ${pd_prefix + "openflow_miss_action_spec_t miss_spec"};
            memset(&miss_spec, 0, sizeof(miss_spec));
            miss_spec.action_table_id = ${map_mod.openflow_tables[table_name].id};
            miss_spec.action_reason = OFPR_ACTION;
            *signal = 1;

            return ${pd_name}${"openflow_miss"}
                (${(", ").join(["&miss_spec" if i == "&action_spec" else i for i in args_list])});
        } else if (*(uint32_t *) *pv == OFPP_NORMAL) {
            return 0;
        }
    }

    return ${pd_name}${"openflow_apply"}
        (${(", ").join(args_list)});
}

//:: #endfor

/* MODIFY WRAPPERS */

//:: for table_name, table in tables.items():
//::   if table.act_prof or table_name not in map_mod.openflow_tables:
//::     continue
//::   #endif
//::   args_list = ["sess_hdl", "dev_id", "entry_hdl"]
//::   name = "_".join([table_name, "mod"])
//::   pd_name = pd_prefix + table_name + "_table_modify_with_"
p4_pd_status_t
${name}
(
    Pvoid_t *action_args,
    uint32_t sig,
    uint64_t flow_id,
    p4_pd_entry_hdl_t entry_hdl,
    p4_pd_sess_hdl_t sess_hdl,
    uint8_t dev_id,
    uint8_t *signal
) {
//::       args_list += ["&action_spec"]
    ${pd_prefix + "openflow_apply_action_spec_t action_spec"};
    memset(&action_spec, 0, sizeof(action_spec));

    PWord_t pv;
    int rc;

    action_spec.action_bmap = sig;

    if ((J1T (rc, *action_args, OFPAT_GROUP))) {
        JLG (pv, *action_args, OFPAT_GROUP);
        action_spec.action_group_id = *(uint32_t *) *pv;
    } else {
        action_spec.action_index = (uint32_t) flow_id;
    }

    if ((J1T (rc, *action_args, OFPAT_OUTPUT))) {
        JLG (pv, *action_args, OFPAT_OUTPUT);
        if (*(uint32_t *) *pv == OFPP_CONTROLLER) {
            ${pd_prefix + "openflow_miss_action_spec_t miss_spec"};
            memset(&miss_spec, 0, sizeof(miss_spec));
            miss_spec.action_table_id = ${map_mod.openflow_tables[table_name].id};
            miss_spec.action_reason = OFPR_ACTION;
            *signal = 1;

            return ${pd_name}${"openflow_miss"}
                (${(", ").join(["&miss_spec" if i == "&action_spec" else i for i in args_list])});
        } else if (*(uint32_t *) *pv == OFPP_NORMAL) {
            return 0;
        }
    }

    return ${pd_name}${"openflow_apply"}
        (${(", ").join(args_list)});
}

//::   #endfor

/* SET_DEFAULT WRAPPERS */

//:: for table_name, table in tables.items():
//::   if table.act_prof or table_name not in map_mod.openflow_tables:
//::     continue
//::   #endif
//::   args_list = ["sess_hdl", "dev_tgt"]
//::   name = "_".join([table_name, "set_default"])
//::   pd_name = pd_prefix + table_name + "_set_default_action_"
p4_pd_status_t
${name}
(
    Pvoid_t *action_args,
    uint32_t sig,
    uint64_t flow_id,
    p4_pd_entry_hdl_t *entry_hdl,
    p4_pd_sess_hdl_t sess_hdl,
    p4_pd_dev_target_t dev_tgt,
    uint8_t *signal
) {
//::       args_list.append("&action_spec")
    ${pd_prefix + "openflow_apply_action_spec_t action_spec"};
    memset(&action_spec, 0, sizeof(action_spec));
//::       args_list += ["entry_hdl"]

    PWord_t pv;
    int rc;

    action_spec.action_bmap = sig;

    if ((J1T (rc, *action_args, OFPAT_GROUP))) {
        JLG (pv, *action_args, OFPAT_GROUP);
        action_spec.action_group_id = (uint32_t) *pv;
    } else {
        action_spec.action_index = (uint32_t) flow_id;
    }

    if ((J1T (rc, *action_args, OFPAT_OUTPUT))) {
        JLG (pv, *action_args, OFPAT_OUTPUT);
        if (*(uint32_t *) *pv == OFPP_CONTROLLER) {
            ${pd_prefix + "openflow_miss_action_spec_t miss_spec"};
            memset(&miss_spec, 0, sizeof(miss_spec));
            miss_spec.action_table_id = ${map_mod.openflow_tables[table_name].id};
            miss_spec.action_reason = OFPR_ACTION;
            *signal = 1;

            return ${pd_name}${"openflow_miss"}
                (${(", ").join(["&miss_spec" if i == "&action_spec" else i for i in args_list])});
        } else if (*(uint32_t *) *pv == OFPP_NORMAL) {
            return 0;
        }
    }

    return ${pd_name}${"openflow_apply"}
        (${(", ").join(args_list)});
}

//:: #endfor
/* Initial settings for openflow module */ 

p4_pd_status_t
openflow_module_init () {
    uint8_t device = 0; // FIXME:
    uint16_t dev_pip_id = 0; // FIXME:
    p4_pd_status_t status = 0;
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = dev_pip_id;

#define PRE_PORT_MAP_ARRAY_SIZE ((PRE_PORTS_MAX + 7)/8)

    static uint8_t port_list[PRE_PORT_MAP_ARRAY_SIZE];
    static uint8_t lag_map[PRE_PORT_MAP_ARRAY_SIZE];

    memset (port_list, 0xff, PRE_PORT_MAP_ARRAY_SIZE);
    memset (lag_map, 0, PRE_PORT_MAP_ARRAY_SIZE);

    // unset cpu port
    *(port_list + 64 / 8) ^= (1 << (64 % 8));

    p4_pd_entry_hdl_t mgrp_hdl;
    p4_pd_entry_hdl_t node_hdl;

    p4_pd_mc_mgrp_create (P4_PRE_SESSION, 0, 20, &mgrp_hdl);
    p4_pd_mc_node_create (P4_PRE_SESSION, P4_DEVICE_ID, 0, port_list, lag_map, &node_hdl);
    p4_pd_mc_associate_node (P4_PRE_SESSION, P4_DEVICE_ID, mgrp_hdl, node_hdl, 0, 0);

    AGENT_ETHERNET_FLOOD_MC_HDL = mgrp_hdl;

    // set pipeline defaults
    status |= ofpat_pipeline_set_default_nop ();

    return status;
}

void
openflow_init (Pvoid_t *adds, Pvoid_t *mods, Pvoid_t *defs,
               Pvoid_t *dels, Pvoid_t *read_bytes_hit,
               Pvoid_t *read_bytes_missed, Pvoid_t *read_packets_hit,
               Pvoid_t *read_packets_missed, Pvoid_t *per_flow_stats_bytes,
               Pvoid_t *per_flow_stats_packets) {
    PWord_t pv;
    indigo_core_table_ops_t *ops;

    openflow_module_init ();

//:: for table_name in map_mod.openflow_tables:
//::   table_id = map_mod.openflow_tables[table_name].id
    // ${table_name} state mods
    JLI (pv, *adds, ${table_id});
    *pv = (uint64_t) &${table_name + "_add"};
    JLI (pv, *mods, ${table_id});
    *pv = (uint64_t) &${table_name + "_mod"};
    JLI (pv, *defs, ${table_id});
    *pv = (uint64_t) &${table_name + "_set_default"};

    ops = malloc (sizeof (indigo_core_table_ops_t));

    ops->entry_create = &flow_create;
    ops->entry_modify = &flow_modify;
    ops->entry_delete = &flow_delete;
    ops->table_stats_get = &table_stats_get;

    indigo_core_table_register (${table_id}, "${table_name}", ops,
                                (void *) (uint64_t) ${table_id});

    // ${table_name} deletion
    JLI (pv, *dels, ${table_id});
    *pv = (uint64_t) &${pd_prefix + table_name + "_table_delete"};

//:: #endfor
    // per flow counters
//:: for counter_name, counter in counter_arrays.items():
//::   if counter.is_direct and counter.table in map_mod.openflow_tables:
//::     name = "p4_pd_" + p4_prefix + "_counter_read_" + counter
//    JLI (pv, *per_flow_stats_${type_}, ${map_mod.openflow_tables[binding[1]].id});
//    *pv = (uint64_t) &${name};

//::   #endif
//:: #endfor

    // Group table
    indigo_core_group_table_ops_t *group_ops;
    group_ops = malloc (sizeof (indigo_core_group_table_ops_t));
    group_ops->entry_create = &group_create;
    group_ops->entry_modify = &group_modify;
    group_ops->entry_delete = &group_delete;
    group_ops->entry_stats_get = &group_stats;

    indigo_core_group_table_register
        (${len(map_mod.openflow_tables)}, "${pd_prefix + "group"}", group_ops,
         (void *) (uint64_t) ${len(map_mod.openflow_tables)});
}

uint8_t
num_openflow_tables () {
    return ${len(map_mod.openflow_tables)};
}
