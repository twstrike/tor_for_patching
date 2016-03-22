/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#include "entrynodes.h"

#ifndef TOR_GUARD_STATE_H
#define TOR_GUARD_STATE_H
typedef enum {
    STATE_INVALID = 0,
    STATE_PRIMARY_GUARDS,
    STATE_TRY_UTOPIC,
    STATE_TRY_DYSTOPIC
} guard_selection_state_t;

typedef struct {
    guard_selection_state_t state;
    guard_selection_state_t previous_state;

    int num_primary_guards;

    //They are lists of node_t because they havent been chosen as guards
    smartlist_t *remaining_utopic_guards;
    smartlist_t *remaining_dystopic_guards;

    //They should be lists of entry_guard_t because they have been used as
    //guards
    smartlist_t *primary_guards;
    smartlist_t *used_guards;

    //XXX Explain the idea of this
    smartlist_t *primary_guards_log;

} guard_selection_t;

const node_t *
choose_random_entry_prop259(cpath_build_state_t *state, int for_directory,
                         dirinfo_type_t dirinfo_type, int *n_options_out);

void
entry_guards_update_profiles(const or_options_t *options);

smartlist_t* get_all_dystopic_guards(void);

void guard_selection_register_connect_status(const entry_guard_t *guard,
                                             int succeeded);

#ifdef PROP259_PRIVATE

guard_selection_t*
algo_choose_entry_guard_start(
        smartlist_t *used_guards,
        const smartlist_t *sampled_utopic_guards,
        const smartlist_t *sampled_dystopic_guards,
        smartlist_t *exclude_nodes,
        int n_primary_guards,
        int dir);

MOCK_DECL(entry_guard_t *,
algo_choose_entry_guard_next,(guard_selection_t *guard_selection,
                              const or_options_t *options, time_t now));
void
guard_selection_free(guard_selection_t *guard_selection);

STATIC void
transition_to(guard_selection_t *algo, guard_selection_state_t state);

void
algo_on_new_consensus(guard_selection_t *guard_selection);

STATIC entry_guard_t*
next_primary_guard(guard_selection_t *guard_selection);

STATIC const node_t*
next_node_by_bandwidth(smartlist_t *nodes);

STATIC entry_guard_t*
next_by_bandwidth(smartlist_t *guards);

STATIC void
fill_in_primary_guards(guard_selection_t *guard_selection);

STATIC void
fill_in_node_sampled_set(smartlist_t *sample, const smartlist_t *set,
                         const int size);

STATIC void
fill_in_remaining_utopic(guard_selection_t *guard_selection,
                         const smartlist_t *sampled_utopic);

STATIC void
fill_in_remaining_dystopic(guard_selection_t *guard_selection,
                           const smartlist_t *sampled_dystopic);

STATIC smartlist_t*
nonbad_guards(smartlist_t *guards);

STATIC void
choose_entry_guard_algo_end(guard_selection_t *guard_selection,
                            const entry_guard_t *guard);

#endif

#endif

