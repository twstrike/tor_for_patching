/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define PROP259_PRIVATE

//XXX Think about it from a modularity perspective and reduce
//the number of dependencies.
#include "prop259.h"
#include "nodelist.h"
#include "routerlist.h"
#include "config.h"
#include "circuitbuild.h"
#include "networkstatus.h"
#include "policies.h"
#include "router.h"

//XXX Find the appropriate place for this global state

/** Entry guard selection algorithm **/
static const node_t *entry_node = NULL;
static guard_selection_t *entry_guard_selection = NULL;

/** Related to guard selection algorithm. **/
//XXX Add proper documentation
static smartlist_t *used_guards = NULL;
static smartlist_t *sampled_utopic_guards = NULL;
static smartlist_t *sampled_dystopic_guards = NULL;

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
    //From router_choose_random_node()
    int pref_addr = 1;
    if (firewall_is_fascist_or())
        return fascist_firewall_allows_node(node, FIREWALL_OR_CONNECTION,
                                            pref_addr);

    //XXX there might be false positive if we dont support IPV6
    //but the guard only listen to a dystopic port in IPV6

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

static int
is_live(const entry_guard_t *guard)
{
    //XXX using entry_is_live() would introduce the current progressive retry
    //behavior. I suspect we should evaluate using this at some point.
    if (guard->unreachable_since == 0)
        return 1;

    return 0;
}

MOCK_IMPL(STATIC int,
is_bad,(const entry_guard_t *guard))
{
    return (node_get_by_id(guard->identity) == NULL);
}

static int
should_ignore(const entry_guard_t *guard, int for_directory)
{
    // Dont use an entry guard when we need a directory guard
    const node_t* node = guard_to_node(guard);
    if (for_directory && !node_is_dir(node))
       return 1;

    //XXX should ignore the exit node
    // const node_t *chosen_exit =
    //state?build_state_get_exit_node(state) : NULL;
    //if (guard_to_node(guard) == chosen)
    //  return 1;

    //XXX this is how need_uptime and need_capacity fits
    //if (!node_is_unreliable(node, need_uptime, need_capacity, 0))
    //{
    //  return 0;
    //}

    return 0;
}

static int
should_try(const entry_guard_t* guard)
{
    if (guard->can_retry)
        return 1;

    return (is_live(guard) && !is_bad(guard));
}

static int
is_eligible(const entry_guard_t* guard, int for_directory)
{
    return should_try(guard) &&
        !should_ignore(guard, for_directory);
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
    log_warn(LD_CIRC, "Will retry remaining used guards.");

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
        log_warn(LD_CIRC, "Going back to previous state");
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
        if (is_eligible(e, guard_selection->for_directory))
            return e;
    } SMARTLIST_FOREACH_END(e);

    log_warn(LD_CIRC, "No PRIMARY_GUARDS is live.");

    transition_to_previous_state_or_try_utopic(guard_selection);
    return NULL;
}

STATIC void
transition_to(guard_selection_t *guard_selection,
              guard_selection_state_t state)
{
    switch (state) {
    case STATE_INVALID:
        log_warn(LD_CIRC, "Transitioned to INVALID_STATE.");
        return;
    case STATE_PRIMARY_GUARDS:
        log_warn(LD_CIRC, "Transitioned to STATE_PRIMARY_GUARDS.");
    case STATE_TRY_UTOPIC:
        log_warn(LD_CIRC, "Transitioned to STATE_TRY_UTOPIC.");
    case STATE_TRY_DYSTOPIC:
        log_warn(LD_CIRC, "Transitioned to STATE_TRY_DYSTOPIC.");
    }

    guard_selection->state = state;
}

static void
transition_to_and_save_state(guard_selection_t *guard_selection,
                             guard_selection_state_t state)
{
    guard_selection->previous_state = guard_selection->state;
    transition_to(guard_selection, state);
}

STATIC const node_t*
next_node_by_bandwidth(smartlist_t *nodes)
{
    const node_t *node = node_sl_choose_by_bandwidth(nodes, WEIGHT_FOR_GUARD);
    if (node)
        smartlist_remove(nodes, node); //otherwise it may return duplicates

    return node;
}

static entry_guard_t*
each_used_guard_not_in_primary_guards(guard_selection_t *guard_selection)
{
    SMARTLIST_FOREACH_BEGIN(guard_selection->used_guards, entry_guard_t *, e) {
        if (smartlist_contains(guard_selection->primary_guards, e)) {
            continue;
        }

        if (is_eligible(e, guard_selection->for_directory))
            return e;
    } SMARTLIST_FOREACH_END(e);

    return NULL;
}

static entry_guard_t*
each_remaining_by_bandwidth(smartlist_t *nodes, int for_directory)
{
    entry_guard_t *guard = NULL;
    smartlist_t *remaining = smartlist_new();

    smartlist_add_all(remaining, nodes);
    while (smartlist_len(remaining) > 0) {
        const node_t *node = next_node_by_bandwidth(remaining);
        if (!node) {
            break;
        }

        //XXX avoid the global entry_guards but still create a entry_guard_t
        add_an_entry_guard(node, 0, 0, 0, for_directory);
        entry_guard_t *g = node_to_guard(node);
        tor_assert(g);

        if (!is_live(g))
            smartlist_remove(nodes, node);

        if (!is_eligible(g, for_directory))
            continue;

        guard = g;
        break;
    }

    tor_free(remaining);
    return guard;
}

static entry_guard_t*
each_remaining_utopic_by_bandwidth(guard_selection_t* guard_selection)
{
    return each_remaining_by_bandwidth(
                   guard_selection->remaining_utopic_guards,
                   guard_selection->for_directory);
}

static entry_guard_t*
each_remaining_dystopic_by_bandwidth(guard_selection_t* guard_selection)
{
    return each_remaining_by_bandwidth(
                   guard_selection->remaining_dystopic_guards,
                   guard_selection->for_directory);
}

static entry_guard_t*
state_TRY_UTOPIC_next(guard_selection_t *guard_selection)
{
    log_warn(LD_CIRC, "Will try USED_GUARDS not in PRIMARY_GUARDS.");

    entry_guard_t *guard = each_used_guard_not_in_primary_guards(
        guard_selection);

    if (guard) {
        return guard;
    }

    log_warn(LD_CIRC, "Will try REMAINING_UTOPIC_GUARDS.");

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
    log_warn(LD_CIRC, "Will try REMAINING_DYSTOPIC_GUARDS.");

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
        if (e->unreachable_since && e->unreachable_since <= time) {
            return 1;
        }

    } SMARTLIST_FOREACH_END(e);

    return 0;
}

//XXX Add tests
static void
check_primary_guards_retry_interval(guard_selection_t *guard_selection,
                                    const or_options_t *options, time_t now)
{
    int retry_interval = options->PrimaryGuardsRetryInterval ?
        options->PrimaryGuardsRetryInterval : 3;
    time_t primary_retry_time = now - retry_interval * 60;

    const smartlist_t *guards = guard_selection->primary_guards;
    if (has_any_been_tried_before(guards, primary_retry_time)) {
        log_warn(LD_CIRC, "Some PRIMARY_GUARDS have been tried more than %d "
            "minutes ago. Will retry PRIMARY_GUARDS.", retry_interval);

        mark_for_retry(guards);
        transition_to_and_save_state(guard_selection, STATE_PRIMARY_GUARDS);
    }
}

STATIC entry_guard_t *
choose_entry_guard_algo_next(guard_selection_t *guard_selection,
                              const or_options_t *options, time_t now)
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

STATIC void
guard_selection_free(guard_selection_t *guard_selection)
{
    smartlist_free(guard_selection->primary_guards);
    smartlist_free(guard_selection->remaining_utopic_guards);
    smartlist_free(guard_selection->remaining_dystopic_guards);
}

STATIC guard_selection_t*
choose_entry_guard_algo_start(
    smartlist_t *used_guards,
    const smartlist_t *sampled_utopic,
    const smartlist_t *sampled_dystopic,
    smartlist_t *exclude_nodes,
    int n_primary_guards,
    int for_directory)
{
    //XXX fill remaining sets from sampled
    (void) exclude_nodes;

    guard_selection_t *guard_selection = tor_malloc_zero(
        sizeof(guard_selection_t));
    guard_selection->for_directory = for_directory;
    guard_selection->state = STATE_PRIMARY_GUARDS;
    guard_selection->used_guards = used_guards;
    guard_selection->num_primary_guards = n_primary_guards;

    fill_in_remaining_utopic(guard_selection, sampled_utopic);
    fill_in_remaining_dystopic(guard_selection, sampled_dystopic);
    fill_in_primary_guards(guard_selection);

    return guard_selection;
}

STATIC void
choose_entry_guard_algo_new_consensus(guard_selection_t *guard_selection)
{
    int num_guards = guard_selection->num_primary_guards;
    smartlist_t *guards = guard_selection->primary_guards;

    while (smartlist_len(nonbad_guards(guards)) < num_guards) {
        entry_guard_t *guard = next_primary_guard(guard_selection);
        if (guard != NULL) {
            if (!smartlist_contains(guards, guard)) {
                smartlist_add(guards, guard);
            }
        } else {
            break;
        }
    }
}

STATIC smartlist_t*
nonbad_guards(smartlist_t *guards)
{
    smartlist_t *nonbad_guards = smartlist_new();
    SMARTLIST_FOREACH_BEGIN(guards, entry_guard_t *, e) {
        if (!is_bad(e))
            smartlist_add(nonbad_guards, e);
    } SMARTLIST_FOREACH_END(e);

    return nonbad_guards;
}

static void
add_nodes_to(smartlist_t *nodes, const smartlist_t *guards)
{
    SMARTLIST_FOREACH_BEGIN(guards, entry_guard_t *, e) {
        const node_t *node = guard_to_node(e);
        if (node && !smartlist_contains(nodes, node))
            smartlist_add(nodes, (node_t*) node);
    } SMARTLIST_FOREACH_END(e);
}

static void
remaining_guards_for_next_primary(guard_selection_t *guard_selection,
          smartlist_t *dest)
{
    smartlist_t *except = smartlist_new();
    add_nodes_to(except, guard_selection->used_guards);
    add_nodes_to(except, guard_selection->primary_guards);

    smartlist_add_all(dest, guard_selection->remaining_utopic_guards);
    smartlist_subtract(dest, except);
    smartlist_free(except);
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

    //Need to normalize, otherwise subtract wont work
    smartlist_t *remaining = smartlist_new();
    remaining_guards_for_next_primary(guard_selection, remaining);
    const node_t *node = next_node_by_bandwidth(remaining);
    tor_free(remaining);

    if (!node)
      return NULL;

    smartlist_remove(guard_selection->remaining_utopic_guards, node);
    add_an_entry_guard(node, 0, 0, 0, guard_selection->for_directory);
    return node_to_guard(node);
}

STATIC void
fill_in_node_sampled_set(smartlist_t *sample, const smartlist_t *set,
                         const int size)
{
    smartlist_t *remaining = smartlist_new();

    smartlist_add_all(remaining, set);
    while (smartlist_len(sample) < size && smartlist_len(remaining) > 0) {
        const node_t *node = next_node_by_bandwidth(remaining);
        if (!node)
            break;

        //XXX should we crete the entry_guard at this moment?
        //add_an_entry_guard(node, 0, 0, 0, for_directory);

        smartlist_add(sample, (node_t*) node);
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

    log_warn(LD_CIRC, "We sampled %d from %d utopic guards",
        smartlist_len(sampled_utopic_guards), smartlist_len(utopic_nodes));

    fill_in_node_sampled_set(sampled_dystopic_guards, dystopic_nodes,
        sample_set_threshold * smartlist_len(dystopic_nodes));

    log_warn(LD_CIRC, "We sampled %d from %d dystopic guards",
        smartlist_len(sampled_dystopic_guards), smartlist_len(dystopic_nodes));
}

STATIC void
choose_entry_guard_algo_end(guard_selection_t *guard_selection,
                            const entry_guard_t *guard)
{
    log_warn(LD_CIRC, "Finishing guard selection algorithm");

    //XXX Save used_guards to state file instead of global variable
    if (!smartlist_contains(guard_selection->used_guards, guard))
        smartlist_add(guard_selection->used_guards, (entry_guard_t*) guard);

    guard_selection_free(guard_selection);
}

//These functions adapt our proposal to current tor code

// PUBLIC INTERFACE ----------------------------------------

int
choose_entry_guard_algo_should_continue(guard_selection_t *guard_selection,
					int succeeded, time_t now, int internet_likely_down_interval)
{
    if (!succeeded) {
        log_warn(LD_CIRC, "Did not succeeded.");
        return 1;
    }

    int should_continue = 0;
    time_t last_success = guard_selection->last_success;
    if (last_success &&
        now - last_success > internet_likely_down_interval * 60) {
        log_warn(LD_CIRC, "Discarding circuit after %d minutes without "
            "success. The network may have been down and now is up again,"
            "so we retry the used guards.", internet_likely_down_interval);

        mark_for_retry(guard_selection->used_guards);
        transition_to(guard_selection, STATE_PRIMARY_GUARDS);
        should_continue = 1;
    }

    guard_selection->last_success = now;
    return should_continue;
}

void
entry_guard_selection_init(void)
{
#ifndef USE_PROP_259
    return; //do nothing
#endif

    if (!router_have_minimum_dir_info()) {
        log_warn(LD_CIRC, "Cant initialize without a consensus.");
        return;
    }

    const or_options_t *options = get_options();
    const int for_directory = 0; //XXX how to get this at this moment?
    const int num_needed = decide_num_guards(options, for_directory);

    //XXX load this from the state file
    //It also feels wrong to have it here, but the algo crashes if it is NULL
    if (!used_guards)
        used_guards = smartlist_new();

    //XXX support excluded nodes.
    //options->ExcludeNodes is a routerset_t, not a list of guards.
    //XXX Look at entry_guards_set_from_config to see how it filters out
    //ExcludeNodes
    entry_guard_selection = choose_entry_guard_algo_start(
        used_guards, sampled_utopic_guards, sampled_dystopic_guards,
        NULL, //XXX should be options->ExcludeNodes,
        num_needed, for_directory);
}

const node_t *
choose_random_entry_prop259(cpath_build_state_t *state, int for_directory,
    dirinfo_type_t dirinfo_type, int *n_options_out)
{
    //XXX This might not work. What guarantees we have that the previously
    //chosen guard meets all the constraints we have now. They can have
    //changed between last run and this run.
    // if entry_node exist we will use it, otherwise we will pick one using next_algo
    if (entry_node) {
        log_warn(LD_CIRC, "Reuse %s as entry guard for this circuit.",
            node_describe(entry_node));
        return entry_node;
    }

    //We have received a consensus but not enough to build a circuit
    //same as !router_have_minimum_dir_info()
    if (!entry_guard_selection)
        return NULL;

    //XXX choose_good_entry_server() ignores:
    // - routers in the same family as the exit node
    // - routers in the same family of the guards you have chosen
    //Our proposal does not care.

    log_warn(LD_CIRC, "Using proposal 259 to choose entry guards.");

    const or_options_t *options = get_options();
    const node_t *node = NULL;
    const entry_guard_t* guard = NULL;
    time_t now = time(NULL);

    /* const node_t *chosen_exit = */
    /*     state ? build_state_get_exit_node(state) : NULL; */
    /* int need_uptime = state ? state->need_uptime : 0; */
    /* int need_capacity = state ? state->need_capacity : 0; */
    /* (void) chosen_exit; */
    (void) state;
    (void) dirinfo_type;
    /* (void) need_uptime; */
    /* (void) need_capacity; */

    if (n_options_out)
        *n_options_out = 0;

    //XXX see entry_guards_set_from_config(options);

    const int num_needed = decide_num_guards(options, for_directory);
    entry_guard_selection->for_directory = for_directory;
    entry_guard_selection->num_primary_guards = num_needed;

  retry:
    guard = choose_entry_guard_algo_next(entry_guard_selection, options, now);

    // This only exists because NEXT() can return NULL when transitioning
    // between states
    if (!guard)
        goto retry;

    // Guard is not in the consensus anymore. Not sure if this is possible
    node = guard_to_node(guard);
    tor_assert(node);

    log_warn(LD_CIRC, "Chose %s as entry guard for this circuit.",
        node_describe(node));

    //XXX check entry_guards_changed();

    //XXX What is n_options_out in our case?
    if (n_options_out)
        *n_options_out = 1;

    entry_node = node;

    return node;
}

void
entry_guards_update_profiles(const or_options_t *options)
{
#ifndef USE_PROP_259
    return; //do nothing
#endif

    //XXX remove
    (void) options;

    log_warn(LD_CIRC, "Received a new consensus");

    //We recreate the sample sets without restricting to directory
    //guards, because most of the entry guards will be directory in
    //the near ideal future.
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

    //XXX Is this necessary?
    if (entry_guard_selection)
        choose_entry_guard_algo_new_consensus(entry_guard_selection);
}

int
guard_selection_register_connect_status(const entry_guard_t *guard,
                                        int succeeded, time_t now)
{
    int should_continue = 0;

#ifndef USE_PROP_259
    return should_continue;
#endif

    log_warn(LD_CIRC, "Guard %s has succeeded = %d.",
        node_describe(guard_to_node(guard)), succeeded);

    if (!entry_guard_selection) {
        log_warn(LD_CIRC, "We have no guard_selection algo."
            " Should not continue.");
        return should_continue;
    }

    //XXX add this to options?
    int internet_likely_down_interval = 5;

    should_continue = choose_entry_guard_algo_should_continue(
        entry_guard_selection, succeeded, now, internet_likely_down_interval);

    log_warn(LD_CIRC, "Should continue? %d", should_continue);

    if (!should_continue) {
        choose_entry_guard_algo_end(entry_guard_selection, guard);
        tor_free(entry_guard_selection);
    } else {
        entry_node = NULL;
    }

    return should_continue;
}

