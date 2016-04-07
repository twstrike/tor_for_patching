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
} guard_selection_state_t;

typedef struct {
    guard_selection_state_t state;
    guard_selection_state_t previous_state;

    int for_directory;
    int num_primary_guards;
    time_t last_success;

    //They are lists of node_t because they havent been chosen as guards
    smartlist_t *remaining_utopic_guards;

    //They should be lists of entry_guard_t because they have been used as
    //guards
    smartlist_t *primary_guards;
    smartlist_t *used_guards;
} guard_selection_t;

void
entry_guard_selection_init(void);

const node_t *
choose_random_entry_prop259(cpath_build_state_t *state, int for_directory,
                         dirinfo_type_t dirinfo_type, int *n_options_out);

void
entry_guards_update_profiles(const or_options_t *options);

int
guard_selection_register_connect_status(const entry_guard_t *guard,
                                        int succeeded, time_t now);

int
choose_entry_guard_algo_should_continue(guard_selection_t *guard_selection,
          int succeeded, time_t now, int internet_likely_down_interval);

int
guard_selection_parse_state(const or_state_t *state, int set, char **msg);

void
guard_selection_update_state(or_state_t *state, const or_options_t *options);

entry_guard_t*
guard_get_by_digest(const char *digest, const smartlist_t *guards);

entry_guard_t *
used_guard_get_by_digest(const char *digest);

void
log_guards(int severity, const smartlist_t *guards);

#ifdef PROP259_PRIVATE

STATIC guard_selection_t*
choose_entry_guard_algo_start(
        smartlist_t *used_guards,
        const smartlist_t *sampled_utopic_guards,
        routerset_t *exclude_nodes,
        int n_primary_guards,
        int dir);

MOCK_DECL(STATIC int,
is_bad,(const entry_guard_t *guard));

STATIC entry_guard_t *
choose_entry_guard_algo_next(guard_selection_t *guard_selection,
                              const or_options_t *options, time_t now);
STATIC void
guard_selection_free(guard_selection_t *guard_selection);

STATIC void
transition_to(guard_selection_t *algo, guard_selection_state_t state);

STATIC void
choose_entry_guard_algo_new_consensus(guard_selection_t *guard_selection);

STATIC entry_guard_t*
next_primary_guard(guard_selection_t *guard_selection);

STATIC const node_t*
next_node_by_bandwidth(smartlist_t *nodes);

STATIC void
fill_in_primary_guards(guard_selection_t *guard_selection);

STATIC void
fill_in_sampled_guard_set(smartlist_t *sample, const smartlist_t *set,
                          const int size);

STATIC void
fill_in_remaining_utopic(guard_selection_t *guard_selection,
                         const smartlist_t *sampled_utopic);

STATIC smartlist_t*
nonbad_guards(smartlist_t *guards);

STATIC void
choose_entry_guard_algo_end(guard_selection_t *guard_selection,
                            const entry_guard_t *guard);

STATIC int
used_guards_parse_state(const or_state_t *state, smartlist_t *used_guards,
                        char **msg);

STATIC int
entry_guards_parse_state_backward(const or_state_t *state,
                                  smartlist_t *entry_guards, char **msg);

STATIC void
used_guards_update_state(or_state_t *state, smartlist_t *used_guards);

#endif

#endif

