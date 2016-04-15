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
    STATE_TRY_REMAINING,
} guard_selection_state_t;

typedef struct {
    smartlist_t *list;
} guardlist_t;

typedef struct {
    guard_selection_state_t state;
    guard_selection_state_t previous_state;

    int for_directory;
    int num_primary_guards;
    time_t last_success;

    //The minimum size of the sampled set after filtering.
    int min_filtered_sample_size;
    //Fraction of GUARDS used as an upper bound when expanding SAMPLED_GUARDS.
    int max_sample_size_threshold;

    //List of entry_guard_t
    smartlist_t *remaining_guards;

    //They should be lists of entry_guard_t because they have been used as
    //guards
    smartlist_t *primary_guards;
    guardlist_t *used_guards;
} guard_selection_t;

guardlist_t* guardlist_new(void);

void
guardlist_add(guardlist_t *gl, entry_guard_t *e);

int
guardlist_len(const guardlist_t *gl);

void guardlist_free(guardlist_t*);

#define GUARDLIST_FOREACH(a, b, c, d) \
    SMARTLIST_FOREACH(a->list, b, c, d)

#define GUARDLIST_FOREACH_BEGIN(a, b, c) \
    SMARTLIST_FOREACH_BEGIN(a->list, b, c)

#define GUARDLIST_FOREACH_END(a) SMARTLIST_FOREACH_END(a)

const node_t *
choose_random_entry_prop259(cpath_build_state_t *state, int for_directory,
                         dirinfo_type_t dirinfo_type, int *n_options_out);

void
entry_guards_update_profiles(const or_options_t *options, const time_t now);

int
guard_selection_register_connect_status(const char *digest, int succeeded,
                                        int mark_relay_status, time_t now);

int
update_entry_guards_connection_status(entry_guard_t *entry,
                                      const int succeeded, const time_t now);

int
choose_entry_guard_algo_should_continue(guard_selection_t *guard_selection,
          int succeeded, time_t now, int internet_likely_down_interval);

int
guard_selection_parse_used_guards_state(const or_state_t *state, int set,
                                        char **msg);

int
guard_selection_parse_sampled_guards_state(const or_state_t *state, int set,
                                           char **msg);

void
guard_selection_update_state(or_state_t *state, const or_options_t *options);

entry_guard_t*
guard_get_by_digest(const char *digest, const smartlist_t *guards);

entry_guard_t *
used_guard_get_by_digest(const char *digest);

int
remove_dead_guards(time_t now, smartlist_t* guards);

int
remove_obsolete_guards(time_t now, smartlist_t* guards);

void
add_an_entry_bridge(node_t *node);

int
known_entry_bridge(void);

void
log_guards(int severity, const smartlist_t *guards);

void
guard_selection_fill_in_from_entrynodes(const or_options_t *options);

#ifdef PROP259_PRIVATE

STATIC guard_selection_t *
entry_guard_selection_init(void);

STATIC guard_selection_t*
choose_entry_guard_algo_start(
        guardlist_t *used_guards,
        const guardlist_t *sampled_utopic_guards,
        int n_primary_guards,
        int dir);

MOCK_DECL(STATIC int,
is_bad,(const entry_guard_t *guard));

MOCK_DECL(STATIC int,
is_live,(const entry_guard_t *guard));

MOCK_DECL(STATIC entry_guard_t*, each_remaining_by_bandwidth,
	  (smartlist_t *guards, int for_directory));

STATIC entry_guard_t *
choose_entry_guard_algo_next(guard_selection_t *guard_selection,
                              const or_options_t *options, time_t now);

STATIC smartlist_t *
filter_set(const guardlist_t *guards, smartlist_t *all_guards,
	   int min_filtered_sample_size, int max_sample_size_threshold);

STATIC void
guard_selection_free(guard_selection_t *guard_selection);

STATIC void
transition_to(guard_selection_t *algo, guard_selection_state_t state);

STATIC entry_guard_t*
next_primary_guard(guard_selection_t *guard_selection);

STATIC const node_t*
next_node_by_bandwidth(smartlist_t *nodes);

STATIC void
fill_in_primary_guards(guard_selection_t *guard_selection);

STATIC void
fill_in_sampled_guard_set(guardlist_t *sample, const smartlist_t *set,
                          const int size);

STATIC void
fill_in_remaining_guards(guard_selection_t *guard_selection,
                         const guardlist_t *sampled_utopic);

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
used_guards_update_state(or_state_t *state, guardlist_t *used_guards);

#endif

#endif

