/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_GUARD_STATE_H
#define TOR_GUARD_STATE_H

typedef struct {
 char *state;
} guard_state_t;

#endif

#ifdef PROP259_PRIVATE
const node_t *get_next_entry_guard(guard_state_t *state);

#endif
guard_state_t *init_guard_state(void);
