/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define PROP259_PRIVATE

#include "prop259.h"
#include "nodelist.h"
#include "routerlist.h"
#include "config.h"
#include "circuitbuild.h"

//XXX Find the appropriate place for this global state

/** Entry guard selection algorithm **/
static guard_selection_t *entry_guard_selection = NULL;

/** Related to guard selection algorithm. **/
//XXX Add proper documentation
static smartlist_t *used_guards = NULL;
static smartlist_t *sampled_utopic_guards = NULL;
static smartlist_t *sampled_dystopic_guards = NULL;

static int
is_dystopic_port(uint16_t port)
{
    if (port == 80)
        return 1;

    if (port == 443)
        return 1;

    return 0;
}

static int
is_dystopic(node_t *node)
{
    if (!node->ri && !node->rs && !node->md) {
        return 0;
    }

    //XXX there might be false positive if we dont support IPV6
    //but the guard on listen to a dystopic port in IPV6

    if (node->ri) {
        if (is_dystopic_port(node->ri->or_port))
            return 1;

        if (is_dystopic_port(node->ri->ipv6_orport))
            return 1;
    } else if (node->rs) {
        if (is_dystopic_port(node->rs->or_port))
            return 1;

        if (is_dystopic_port(node->rs->ipv6_orport))
            return 1;
    } else if (node->md) {
        if (is_dystopic_port(node->md->ipv6_orport))
            return 1;
    }

    return 0;
}

smartlist_t*
get_all_dystopic_guards(void)
{
    smartlist_t *dystopic = smartlist_new();
    smartlist_t *all = get_all_guards(0);

    SMARTLIST_FOREACH_BEGIN(all, node_t *, node) {
        if (is_dystopic(node))
            smartlist_add(dystopic, node);
    } SMARTLIST_FOREACH_END(node);

    smartlist_free(all);
    return dystopic;
}

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

static int
should_try(entry_guard_t* guard)
{
    if (guard->can_retry)
        return 1;

    if (is_live(guard) && !is_bad(guard))
        return 1;

    return 0;
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
        if (should_try(e))
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
        if (is_bad(e))
            continue;

        const node_t *node = guard_to_node(e);
        if (node)
            smartlist_add(nodes, (void *)node);
    } SMARTLIST_FOREACH_END(e);

    //XXX should not happen, but happens due the node -> guard translation
    if (smartlist_len(nodes) == 0)
        return NULL;

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

        if (should_try(e))
            return e;
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

        if (should_try(g)) {
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
    //XXX choose_good_entry_server() ignores:
    // - routers in the same family as the exit node
    // - routers in the same family of the guards you have chosen
    //Our proposal does not care.

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
fill_in_remaining_utopic(guard_selection_t *guard_selection,
                         const smartlist_t *sampled_utopic)
{
    guard_selection->remaining_utopic_guards = smartlist_new();

    SMARTLIST_FOREACH_BEGIN(sampled_utopic, node_t *, node) {
        if (!smartlist_contains(guard_selection->used_guards, node)) {
            smartlist_add(guard_selection->remaining_utopic_guards, node);
        }
    } SMARTLIST_FOREACH_END(node);
}

STATIC void
fill_in_remaining_dystopic(guard_selection_t *guard_selection,
                           const smartlist_t *sampled_dystopic)
{
    guard_selection->remaining_dystopic_guards = smartlist_new();

    SMARTLIST_FOREACH_BEGIN(sampled_dystopic, node_t *, node) {
        if (!smartlist_contains(guard_selection->used_guards, node)) {
            smartlist_add(guard_selection->remaining_dystopic_guards, node);
        }
    } SMARTLIST_FOREACH_END(node);
}

STATIC void
fill_in_primary_guards(guard_selection_t *guard_selection)
{
    guard_selection->primary_guards = smartlist_new();

    int num_guards = guard_selection->num_primary_guards;
    smartlist_t *primary = guard_selection->primary_guards;
    while (smartlist_len(primary) < num_guards) {
        entry_guard_t *guard = next_primary_guard(guard_selection);
        if (!guard)
            break;

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
    const smartlist_t *sampled_utopic,
    const smartlist_t *sampled_dystopic,
    smartlist_t *exclude_nodes,
    int n_primary_guards,
    int dir)
{
    //XXX fill remaining sets from sampled
    (void) exclude_nodes;

    //XXX make sure is directory is used appropriately
    (void) dir;

    guard_selection_t *guard_selection = tor_malloc_zero(
        sizeof(guard_selection_t));
    guard_selection->state = STATE_PRIMARY_GUARDS;
    guard_selection->used_guards = used_guards;
    guard_selection->num_primary_guards = n_primary_guards;

    fill_in_remaining_utopic(guard_selection, sampled_utopic);
    fill_in_remaining_dystopic(guard_selection, sampled_dystopic);
    fill_in_primary_guards(guard_selection);

    return guard_selection;
}

void
algo_on_new_consensus(guard_selection_t *guard_selection)
{
    int num_guards = guard_selection->num_primary_guards;
    if (guard_selection->primary_guards_log == NULL) {
        guard_selection->primary_guards_log = smartlist_new();
        smartlist_add_all(guard_selection->primary_guards_log,
            guard_selection->primary_guards);
    }

    smartlist_t *guards_log = guard_selection->primary_guards_log;
    guard_selection->primary_guards = smartlist_new();
    smartlist_t *guards = guard_selection->primary_guards;
    SMARTLIST_FOREACH_BEGIN(guards_log, entry_guard_t *, e) {
        if (!is_bad(e) && smartlist_len(guards) < num_guards) {
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

static void
init_entry_guard_selection(const or_options_t *options, int for_directory)
{
    const int num_needed = decide_num_guards(options, for_directory);

    //XXX How to load this from the state file
    if (!used_guards)
        used_guards = smartlist_new();

    //XXX support excluded nodes.
    //options->ExcludeNodes is a routerset_t, not a list of guards.
    //XXX Look at entry_guards_set_from_config to see how it filters out
    //ExcludeNodes
    entry_guard_selection = algo_choose_entry_guard_start(
        used_guards, sampled_utopic_guards, sampled_dystopic_guards,
        NULL, //XXX should be options->ExcludeNodes,
        num_needed, for_directory);
}

const node_t *
choose_random_entry_prop259(cpath_build_state_t *state, int for_directory,
    dirinfo_type_t dirinfo_type, int *n_options_out)
{
    log_info(LD_CIRC, "Using proposal 259 to choose entry guards.");

    const or_options_t *options = get_options();
    const node_t *node = NULL;
    const entry_guard_t* guard = NULL;
    time_t now = time(NULL);

    //XXX we ignore this information while selecting a guard
    const node_t *chosen_exit =
        state ? build_state_get_exit_node(state) : NULL;
    int need_uptime = state ? state->need_uptime : 0;
    int need_capacity = state ? state->need_capacity : 0;
    (void) chosen_exit;
    (void) dirinfo_type;
    (void) need_uptime;
    (void) need_capacity;

    if (n_options_out)
        *n_options_out = 0;

    //XXX see entry_guards_set_from_config(options);

    if (entry_guard_selection)
        guard_selection_free(entry_guard_selection);

    init_entry_guard_selection(options, for_directory);

  retry:
    guard = algo_choose_entry_guard_next(entry_guard_selection, options, now);
    if (guard)
        node = guard_to_node(guard);

    if (!node)
        goto retry;

    //XXX check entry_guards_changed();

    //XXX What is n_options_out in our case?
    if (n_options_out)
        *n_options_out = 1;

    return node;
}

STATIC void
fill_in_node_sampled_set(smartlist_t *sample, const smartlist_t *set,
                         const int size)
{
    smartlist_t *remaining = smartlist_new();

    smartlist_add_all(remaining, set);
    while (smartlist_len(sample) < size && smartlist_len(remaining) > 0) {
        //this is next by bandwidth with a set of nodes
        const node_t *node = node_sl_choose_by_bandwidth(remaining,
            WEIGHT_FOR_GUARD);

        if (!node)
            break;

        smartlist_remove(remaining, node);
        smartlist_add(sample, (void*) node);
    }
    smartlist_free(remaining);
}

static void
fill_in_sampled_sets(const smartlist_t *utopic_nodes,
                     const smartlist_t *dystopic_nodes)
{
    //XXX Extract a configuration from this
    const double sample_set_threshold = 0.02;

    //XXX persist sampled sets in state file

    if (!sampled_utopic_guards)
        sampled_utopic_guards = smartlist_new();

    if (!sampled_dystopic_guards)
        sampled_dystopic_guards = smartlist_new();

    fill_in_node_sampled_set(sampled_utopic_guards, utopic_nodes,
        sample_set_threshold * smartlist_len(utopic_nodes));

    log_info(LD_CIRC, "We sampled %d from %d utopic guards",
        smartlist_len(sampled_utopic_guards), smartlist_len(utopic_nodes));

    fill_in_node_sampled_set(sampled_dystopic_guards, dystopic_nodes,
        sample_set_threshold * smartlist_len(dystopic_nodes));

    log_info(LD_CIRC, "We sampled %d from %d dystopic guards",
        smartlist_len(sampled_dystopic_guards), smartlist_len(dystopic_nodes));
}

void
entry_guards_update_profiles(const or_options_t *options)
{
#ifndef USE_PROP_259
    return; //do nothing
#endif

    int for_directory = 0;
    smartlist_t *utopic = get_all_guards(for_directory);
    smartlist_t *dystopic = smartlist_new();

    SMARTLIST_FOREACH_BEGIN(utopic, node_t *, node) {
        if (is_dystopic(node))
            smartlist_add(dystopic, node);
    } SMARTLIST_FOREACH_END(node);

    //XXX The size of the utopic and dystopic sets may change, but we only
    //change the sampled sets when these sizes increase.
    fill_in_sampled_sets(utopic, dystopic);

    smartlist_free(utopic);
    smartlist_free(dystopic);

    if (!entry_guard_selection)
        init_entry_guard_selection(options, 0);

    algo_on_new_consensus(entry_guard_selection);
}

