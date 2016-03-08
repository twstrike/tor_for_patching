/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_GUARD_STATE_H
#define TOR_GUARD_STATE_H

typedef struct {
 unsigned int state;
} guard_state_t;

#endif

MOCK_DECL(const node_t *,algo_choose_entry_guard_next,(guard_state_t *state));
#ifdef PROP259_PRIVATE
const unsigned int STATE_PRIMARY_GUARDS = 0;
const unsigned int STATE_TRY_UTOPIC = 1;
const unsigned int STATE_TRY_DYSTOPIC = 2;

guard_state_t *algo_choose_entry_guard_start(
        smartlist_t *used_guards,
        smartlist_t *sampled_utopic_guards,
        smartlist_t *sampled_dystopic_guards,
        smartlist_t *exclude_nodes,
        int n_primary_guards,
        int dir);
guard_state_t *transfer_to(guard_state_t *guard_state,const unsigned int new_state);
MOCK_DECL(int, check_treshould,(guard_state_t *state));
#endif
