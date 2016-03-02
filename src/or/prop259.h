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

MOCK_DECL(const node_t *,get_next_entry_guard,(guard_state_t *state));
#ifdef PROP259_PRIVATE
const unsigned int STATE_PRIMARY_GUARDS = 0;
const unsigned int STATE_TRY_UTOPIC = 1;
const unsigned int STATE_TRY_DYSTOPIC = 2;

guard_state_t *init_guard_state(void);
guard_state_t *transfer_to(guard_state_t *guard_state,const unsigned int new_state);
MOCK_DECL(int, reach_treshould,(guard_state_t *state));
#endif
