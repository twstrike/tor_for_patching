/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

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

    smartlist_t *guards;
    smartlist_t *utopic_guards;
    smartlist_t *dystopic_guards;

    //should be changed by the algo
    smartlist_t *remaining_utopic_guards;
    smartlist_t *remaining_dystopic_guards;
    smartlist_t *primary_guards;

    smartlist_t *primary_guards_log;

    // Context
    smartlist_t *used_guards;
} guard_selection_t;

#endif

MOCK_DECL(entry_guard_t *,algo_choose_entry_guard_next,(guard_selection_t *));

#ifdef PROP259_PRIVATE

guard_selection_t* algo_choose_entry_guard_start(
        smartlist_t *used_guards,
        smartlist_t *sampled_utopic_guards,
        smartlist_t *sampled_dystopic_guards,
        smartlist_t *exclude_nodes,
        int n_primary_guards,
        int dir);

STATIC void transition_to(guard_selection_t *algo, guard_selection_state_t state);
void algo_on_new_consensus(guard_selection_t *guard_selection);
entry_guard_t *next_primary_guard(guard_selection_t *guard_selection);

STATIC entry_guard_t* next_by_bandwidth(smartlist_t *guards);
#endif

