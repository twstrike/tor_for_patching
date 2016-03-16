/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define PROP259_PRIVATE

#include "or.h"
#include "circpathbias.h"
#include "circuitbuild.h"
#include "circuitstats.h"
#include "config.h"
#include "confparse.h"
#include "connection.h"
#include "connection_or.h"
#include "control.h"
#include "directory.h"
#include "entrynodes.h"
#include "prop259.h"
#include "main.h"
#include "microdesc.h"
#include "networkstatus.h"
#include "nodelist.h"
#include "policies.h"
#include "router.h"
#include "routerlist.h"
#include "routerparse.h"
#include "routerset.h"
#include "transports.h"
#include "statefile.h"

static int
is_live(entry_guard_t *guard)
{
    //XXX using entry_is_live() would introduce the current progressive retry
    //behavior. I suspect we should evaluate using this at some point.

    if (guard->can_retry)
        return 1;

    if (guard->unreachable_since == 0)
        return 1;

    return 0;
}

//XXX review whether bad_since is appropriate to know if a guard is listed
//in the latest consensus. entry_guard_set_status suggests an unlisted guard
//is a guard which we fail to find a node with node_get_by_id(entry->identity)
static int
is_bad(entry_guard_t *guard)
{
    return (guard->bad_since != 0);
}

static void
mark_for_retry(const smartlist_t *guards)
{
    SMARTLIST_FOREACH_BEGIN(guards, entry_guard_t *, e) {
        e->can_retry = 1;
    } SMARTLIST_FOREACH_END(e);
}

static void
mark_remaining_used_for_retry(guard_selection_t *guard_selection)
{
    SMARTLIST_FOREACH_BEGIN(guard_selection->used_guards, entry_guard_t *, e) {
        if (smartlist_contains(guard_selection->primary_guards, e)) {
            continue;
        }

        e->can_retry = 1;
    } SMARTLIST_FOREACH_END(e);
}

static void
transition_to_previous_state_or_try_utopic(guard_selection_t *guard_selection)
{
    if (guard_selection->previous_state != 0) {
        transition_to(guard_selection, guard_selection->previous_state);
    } else {
        mark_remaining_used_for_retry(guard_selection);
        transition_to(guard_selection, STATE_TRY_UTOPIC);
    }
}

static entry_guard_t*
state_PRIMARY_GUARDS_next(guard_selection_t *guard_selection)
{
    smartlist_t *guards = guard_selection->primary_guards;
    SMARTLIST_FOREACH_BEGIN(guards, entry_guard_t *, e) {
        if (is_live(e))
            return e;
    } SMARTLIST_FOREACH_END(e);

    transition_to_previous_state_or_try_utopic(guard_selection);
    return NULL;
}

//XXX review if this is the right way of doing this
static const node_t*
guard_to_node(const entry_guard_t *guard)
{
    return node_get_by_id(guard->identity);
}

//XXX review if this is the right way of doing this
static entry_guard_t*
node_to_guard(const node_t *node)
{
    return entry_guard_get_by_id_digest(node->identity);
}

STATIC void
transition_to(guard_selection_t *guard_selection,
              guard_selection_state_t state)
{
    guard_selection->state = state;
}

static void
transition_to_and_save_state(guard_selection_t *guard_selection,
                             guard_selection_state_t state)
{
    guard_selection->previous_state = guard_selection->state;
    transition_to(guard_selection, state);
}

STATIC entry_guard_t*
next_by_bandwidth(smartlist_t *guards)
{
    entry_guard_t *guard = NULL;
    smartlist_t *nodes = smartlist_new();

    //Bandwidth is an information on the node descriptors. We need to convert
    //guards to nodes.
    SMARTLIST_FOREACH_BEGIN(guards, entry_guard_t *, e) {
        const node_t *node = guard_to_node(e);
        if (node)
            smartlist_add(nodes, (void *)node);
    } SMARTLIST_FOREACH_END(e);

    const node_t *node = node_sl_choose_by_bandwidth(nodes, WEIGHT_FOR_GUARD);
    if (node) {
        guard = node_to_guard(node);
        tor_assert(guard);
        smartlist_remove(guards, guard);
    }

    smartlist_free(nodes);
    return guard;
}

static entry_guard_t*
each_used_guard_not_in_primary_guards(guard_selection_t *guard_selection)
{
    SMARTLIST_FOREACH_BEGIN(guard_selection->used_guards, entry_guard_t *, e) {
        if (smartlist_contains(guard_selection->primary_guards, e)) {
            continue;
        }

        if (is_live(e) && !is_bad(e)) {
            return e;
        }
    } SMARTLIST_FOREACH_END(e);

    return NULL;
}

static entry_guard_t*
each_remaining_by_bandwidth(guard_selection_t* guard_selection,
                            int require_dystopic)
{
    entry_guard_t *guard = NULL;
    smartlist_t *guards = NULL;
    smartlist_t *remaining = smartlist_new();

    if (require_dystopic == 1) {
        guards = guard_selection->remaining_dystopic_guards;
    } else {
        guards = guard_selection->remaining_utopic_guards;
    }

    smartlist_add_all(remaining, guards);
    while (smartlist_len(remaining) > 0) {
        entry_guard_t *g = next_by_bandwidth(remaining);
        if (!g) {
            break;
        }

        if (is_live(g)) {
            guard = g;
            break;
        }

        smartlist_remove(guards, g);
    }

    tor_free(remaining);
    return guard;
}

static entry_guard_t*
each_remaining_utopic_by_bandwidth(guard_selection_t* guard_selection)
{
    return each_remaining_by_bandwidth(guard_selection, 0);
}

static entry_guard_t*
each_remaining_dystopic_by_bandwidth(guard_selection_t* guard_selection)
{
    return each_remaining_by_bandwidth(guard_selection, 1);
}

static entry_guard_t*
state_TRY_UTOPIC_next(guard_selection_t *guard_selection)
{
    entry_guard_t *guard = each_used_guard_not_in_primary_guards(
        guard_selection);

    if (guard) {
        return guard;
    }

    guard = each_remaining_utopic_by_bandwidth(guard_selection);
    if (guard) {
        return guard;
    }

    transition_to(guard_selection, STATE_TRY_DYSTOPIC);

    return NULL;
}

static entry_guard_t*
state_TRY_DYSTOPIC_next(guard_selection_t *guard_selection)
{
    entry_guard_t *guard = each_remaining_dystopic_by_bandwidth(
        guard_selection);

    if (guard) {
        return guard;
    }

    transition_to(guard_selection, STATE_PRIMARY_GUARDS);

    return NULL;
}

static int
has_any_been_tried_before(const smartlist_t *guards, time_t time)
{
    SMARTLIST_FOREACH_BEGIN(guards, entry_guard_t *, e) {
        //XXX review if unreachable since is the right property
        if (e->unreachable_since != 0 && e->unreachable_since <= time) {
            return 1;
        }

    } SMARTLIST_FOREACH_END(e);

    return 0;
}

static void
check_primary_guards_retry_interval(guard_selection_t *guard_selection,
                                    const or_options_t *options, time_t now)
{
    const smartlist_t *guards = guard_selection->primary_guards;
    time_t primary_retry_time = now - options->PrimaryGuardsRetryInterval * 60;

    if (has_any_been_tried_before(guards, primary_retry_time)) {
        mark_for_retry(guards);
        transition_to_and_save_state(guard_selection, STATE_PRIMARY_GUARDS);
    }
}

MOCK_IMPL(entry_guard_t *,
algo_choose_entry_guard_next,(guard_selection_t *guard_selection,
                              const or_options_t *options, time_t now))
{
    check_primary_guards_retry_interval(guard_selection, options, now);

    switch (guard_selection->state) {
    case STATE_INVALID:
        tor_assert(NULL); //XXX how to panic?
        return NULL;
    case STATE_PRIMARY_GUARDS:
        return state_PRIMARY_GUARDS_next(guard_selection);
    case STATE_TRY_UTOPIC:
        return state_TRY_UTOPIC_next(guard_selection);
    case STATE_TRY_DYSTOPIC:
        return state_TRY_DYSTOPIC_next(guard_selection);
    }

    return NULL;
}

STATIC void
fill_in_primary_guards(guard_selection_t *guard_selection, int num_guards)
{
    smartlist_t *primary = guard_selection->primary_guards;
    while (smartlist_len(primary) < num_guards) {
        entry_guard_t *guard = next_primary_guard(guard_selection);
        if (guard && !is_bad(guard))
            smartlist_add(primary, guard);
    }
}

void
guard_selection_free(guard_selection_t *guard_selection)
{
    smartlist_free(guard_selection->primary_guards);
    smartlist_free(guard_selection->remaining_utopic_guards);
    smartlist_free(guard_selection->remaining_dystopic_guards);
}

guard_selection_t*
algo_choose_entry_guard_start(
    smartlist_t *used_guards,
    smartlist_t *sampled_utopic,
    smartlist_t *sampled_dystopic,
    smartlist_t *exclude_nodes,
    int n_primary_guards,
    int dir)
{
    guard_selection_t *guard_selection = tor_malloc_zero(
        sizeof(guard_selection_t));
    guard_selection->state = STATE_PRIMARY_GUARDS;
    guard_selection->used_guards = used_guards;
    guard_selection->primary_guards = smartlist_new();
    guard_selection->remaining_utopic_guards = smartlist_new();
    guard_selection->remaining_dystopic_guards = smartlist_new();

    fill_in_primary_guards(guard_selection, n_primary_guards);

    //XXX fill remaining sets from sampled

    (void) sampled_utopic;
    (void) sampled_dystopic;
    (void) exclude_nodes;

    //XXX make sure is directory is used appropriately
    (void) dir;

    return guard_selection;
}

void
algo_on_new_consensus(guard_selection_t *guard_selection, int num_guards)
{
    if (guard_selection->primary_guards_log == NULL) {
        guard_selection->primary_guards_log = smartlist_new();
        smartlist_add_all(guard_selection->primary_guards_log,
            guard_selection->primary_guards);
    }

    smartlist_t *guards_log = guard_selection->primary_guards_log;
    guard_selection->primary_guards = smartlist_new();
    smartlist_t *guards = guard_selection->primary_guards;
    SMARTLIST_FOREACH_BEGIN(guards_log, entry_guard_t *, e) {
        if (!e->bad_since && smartlist_len(guards) < num_guards) {
            smartlist_add(guards, e);
        }
    } SMARTLIST_FOREACH_END(e);

    //XXX review this log
    //This is fill_in_primary_guards() with a "log".
    while (smartlist_len(guard_selection->primary_guards) < num_guards) {
        entry_guard_t *guard = next_primary_guard(guard_selection);
        if (guard != NULL) {
            smartlist_add(guards, guard);
            if (!smartlist_contains(guards_log, guard)) {
                smartlist_add(guards_log, guard);
            }
        } else {
            break;
        }
    }
}

STATIC entry_guard_t*
next_primary_guard(guard_selection_t *guard_selection)
{
    const smartlist_t *used = guard_selection->used_guards;
    const smartlist_t *primary = guard_selection->primary_guards;

    SMARTLIST_FOREACH_BEGIN(used, entry_guard_t *, e) {
        if (!smartlist_contains(primary, e) && !is_bad(e))
            return e;
    } SMARTLIST_FOREACH_END(e);

    smartlist_t *remaining = smartlist_new();
    smartlist_add_all(remaining, guard_selection->remaining_utopic_guards);
    smartlist_subtract(remaining, used);
    smartlist_subtract(remaining, primary);

    entry_guard_t *guard = next_by_bandwidth(remaining);

    tor_free(remaining);
    return guard;
}

