/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_GUARD_STATE_H
#define TOR_GUARD_STATE_H

typedef struct {
    unsigned int state;
    unsigned int previous_state;

    smartlist_t *guards;
    smartlist_t *utopic_guards;
    smartlist_t *dystopic_guards;

    //should be changed by the algo
    smartlist_t *remaining_utopic_guards;
    smartlist_t *remaining_dystopic_guards;
    smartlist_t *primary_guards;

	// Context
	smartlist_t *used_guards;
} guard_selection_t;

#endif

MOCK_DECL(entry_guard_t *,algo_choose_entry_guard_next,(guard_selection_t *));

#ifdef PROP259_PRIVATE
const unsigned int STATE_INVALID = 0;
const unsigned int STATE_PRIMARY_GUARDS = 1;
const unsigned int STATE_TRY_UTOPIC = 2;
const unsigned int STATE_TRY_DYSTOPIC = 3;

guard_selection_t* algo_choose_entry_guard_start(
        smartlist_t *used_guards,
        smartlist_t *sampled_utopic_guards,
        smartlist_t *sampled_dystopic_guards,
        smartlist_t *exclude_nodes,
        int n_primary_guards,
        int dir);

void transition_to(guard_selection_t *algo, const unsigned int state);

STATIC entry_guard_t* next_by_bandwidth(smartlist_t *guards);
#endif
