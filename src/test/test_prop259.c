/* Copyright (c) 2014-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"

#define STATEFILE_PRIVATE
#define ENTRYNODES_PRIVATE
#define ROUTERLIST_PRIVATE
#define PROP259_PRIVATE

#include "or.h"
#include "test.h"

#include "config.h"
#include "entrynodes.h"
#include "prop259.h"
#include "nodelist.h"
#include "policies.h"
#include "routerlist.h"
#include "routerparse.h"
#include "routerset.h"
#include "statefile.h"
#include "util.h"

#include "test_helpers.h"

/** Dummy Tor state used in unittests. */
static or_state_t *dummy_state = NULL;
static or_state_t *
get_or_state_replacement(void)
{
    return dummy_state;
}

/* Unittest setup function: Setup a fake network. */
static void *
fake_network_setup(const struct testcase_t *testcase)
{
    (void) testcase;

    /* Setup fake state */
    dummy_state = tor_malloc_zero(sizeof(or_state_t));
    MOCK(get_or_state,
        get_or_state_replacement);

    /* Setup fake routerlist. */
    helper_setup_fake_routerlist();

    /* Return anything but NULL (it's interpreted as test fail) */
    return dummy_state;
}

/* Unittest cleanup function: Cleanup the fake network. */
static int
fake_network_cleanup(const struct testcase_t *testcase, void *ptr)
{
    (void) testcase;
    (void) ptr;

    routerlist_free_all();
    nodelist_free_all();
    entry_guards_free_all();
    or_state_free(dummy_state);

    return 1; /* NOP */
}

static const struct testcase_setup_t fake_network = {
    fake_network_setup, fake_network_cleanup
};

/* TODO:
 * algo_choose_entry_guard_next() test with state machine.
 *
 */

static void
test_STATE_PRIMARY_GUARD_is_initial_state(void *arg)
{
    (void) arg;

    guard_selection_t *guard_selection;
    smartlist_t *sampled_utopic = smartlist_new();
    smartlist_t *sampled_dystopic = smartlist_new();
    smartlist_t *used_guards = smartlist_new();
    smartlist_t *exclude_nodes = smartlist_new();
    int n_primary_guards = 3;
    int dir = 0;

    guard_selection = algo_choose_entry_guard_start(
        used_guards,
        sampled_utopic,
        sampled_dystopic,
        exclude_nodes,
        n_primary_guards,
        dir);

    tt_int_op(guard_selection->state, OP_EQ, STATE_PRIMARY_GUARDS);

  done:
    tor_free(guard_selection);
    tor_free(used_guards);
    tor_free(exclude_nodes);
}

static const node_t*
node_sl_choose_by_bandwidth_mock(const smartlist_t *sl,
    bandwidth_weight_rule_t rule)
{
    (void) rule;

    return smartlist_get(sl, 0);
}

static void
test_next_by_bandwidth_return_each_entry(void *arg)
{
    entry_guard_t* guard = NULL;
    node_t *node = NULL;
    smartlist_t *guards = NULL;
    entry_guard_t *g1, *g2, *g3 = NULL;
    (void) arg;

    MOCK(node_sl_choose_by_bandwidth, node_sl_choose_by_bandwidth_mock);

    // all nodes are guards
    tt_int_op(smartlist_len(get_entry_guards()), OP_EQ, 0);

    smartlist_t *our_nodelist = nodelist_get_list();
    SMARTLIST_FOREACH_BEGIN(our_nodelist, const node_t *, node) {
        const node_t *node_tmp;
        node_tmp = add_an_entry_guard(node, 0, 1, 0, 0);
        tt_assert(node_tmp);
    } SMARTLIST_FOREACH_END(node);

    node = smartlist_get(our_nodelist, 0);
    g1 = entry_guard_get_by_id_digest(node->identity);
    node = smartlist_get(our_nodelist, 1);
    g2 = entry_guard_get_by_id_digest(node->identity);
    g3 = tor_malloc_zero(sizeof(entry_guard_t));

    guards = smartlist_new();
    smartlist_add(guards, g1);
    smartlist_add(guards, g2);
    smartlist_add(guards, g3); // this should be ignored

    guard = next_by_bandwidth(guards);
    tt_ptr_op(guard, OP_EQ, g1);

    guard = next_by_bandwidth(guards);
    tt_ptr_op(guard, OP_EQ, g2);

    guard = next_by_bandwidth(guards);
    tt_ptr_op(guard, OP_EQ, NULL);

  done:
    tor_free(guards);
    tor_free(g3);
    UNMOCK(node_sl_choose_by_bandwidth);
}

static void
test_state_machine_should_use_new_state_as_current_state(void *arg)
{
    (void) arg;

    guard_selection_t *guard_selection;
    smartlist_t *sampled_utopic = smartlist_new();
    smartlist_t *sampled_dystopic = smartlist_new();
    smartlist_t *used_guards = smartlist_new();
    smartlist_t *exclude_nodes = smartlist_new();
    int n_primary_guards = 3;
    int dir = 0;

    guard_selection = algo_choose_entry_guard_start(
        used_guards,
        sampled_utopic,
        sampled_dystopic,
        exclude_nodes,
        n_primary_guards,
        dir);

    tt_int_op(guard_selection->state, OP_EQ, STATE_PRIMARY_GUARDS);
    transition_to(guard_selection, STATE_TRY_UTOPIC);
    tt_int_op(guard_selection->state, OP_EQ, STATE_TRY_UTOPIC);

  done:
    tor_free(guard_selection);
    tor_free(used_guards);
    tor_free(exclude_nodes);
}

static void
test_NEXT_transitions_to_PRIMARY_GUARDS_and_saves_previous_state(void *arg)
{
    guard_selection_t *guard_selection = tor_malloc_zero(
        sizeof(guard_selection_t));
    smartlist_t *primary_guards = smartlist_new();
    smartlist_t *used_guards = smartlist_new();
    smartlist_t *remaining_utopic_guards = smartlist_new();
    smartlist_t *remaining_dystopic_guards = smartlist_new();
    or_options_t *options = tor_malloc_zero(sizeof(or_options_t));

    entry_guard_t *chosen = NULL;
    entry_guard_t *g1 = NULL, *g2 = NULL, *g3 = NULL;
    (void) arg;

    MOCK(node_sl_choose_by_bandwidth, node_sl_choose_by_bandwidth_mock);

    time_t now = 100;
    options->PrimaryGuardsRetryInterval = 3;

    g1 = tor_malloc_zero(sizeof(entry_guard_t));
    g2 = tor_malloc_zero(sizeof(entry_guard_t));
    g3 = tor_malloc_zero(sizeof(entry_guard_t));

    smartlist_add(primary_guards, g1);
    smartlist_add(used_guards, g1);
    smartlist_add(used_guards, g3); //used not in primary

    g1->unreachable_since = now - 3*60;
    g2->unreachable_since = now - 10;

    guard_selection->state = STATE_TRY_UTOPIC;
    guard_selection->used_guards = used_guards;
    guard_selection->primary_guards = primary_guards;
    guard_selection->remaining_utopic_guards = remaining_utopic_guards;
    guard_selection->remaining_dystopic_guards = remaining_dystopic_guards;

    chosen = algo_choose_entry_guard_next(guard_selection, options, now-1);
    tt_ptr_op(chosen, OP_EQ, g3);
    tt_int_op(guard_selection->state, OP_EQ, STATE_TRY_UTOPIC);

    chosen = algo_choose_entry_guard_next(guard_selection, options, now);
    tt_int_op(guard_selection->state, OP_EQ, STATE_PRIMARY_GUARDS);

  done:
    UNMOCK(node_sl_choose_by_bandwidth);
    tor_free(g1);
    tor_free(g2);
    tor_free(g3);
    tor_free(guard_selection);
    tor_free(primary_guards);
    tor_free(used_guards);
    tor_free(remaining_utopic_guards);
    tor_free(remaining_dystopic_guards);
    tor_free(options);
}

static void
test_PRIMARY_GUARDS_returns_PRIMARY_GUARDS_in_order(void *arg)
{
    entry_guard_t *entry1 = NULL, *entry2 = NULL;
    or_options_t *options = tor_malloc_zero(sizeof(or_options_t));
    (void) arg;

    guard_selection_t *guard_selection;
    smartlist_t *sampled_utopic = smartlist_new();
    smartlist_t *sampled_dystopic = smartlist_new();
    smartlist_t *used_guards = smartlist_new();
    smartlist_t *exclude_nodes = smartlist_new();
    int n_primary_guards = 3;
    int dir = 0;
    entry_guard_t *chosen = NULL;

    guard_selection = algo_choose_entry_guard_start(
        used_guards,
        sampled_utopic,
        sampled_dystopic,
        exclude_nodes,
        n_primary_guards,
        dir);

    entry1 = tor_malloc_zero(sizeof(entry_guard_t));
    entry2 = tor_malloc_zero(sizeof(entry_guard_t));
    smartlist_add(guard_selection->primary_guards, entry1);
    smartlist_add(guard_selection->primary_guards, entry2);

    chosen = algo_choose_entry_guard_next(guard_selection, options, 0);
    tt_ptr_op(entry1, OP_EQ, chosen);
    chosen = algo_choose_entry_guard_next(guard_selection, options, 0);
    tt_ptr_op(entry1, OP_EQ, chosen);

    entry1->unreachable_since = 1;
    chosen = algo_choose_entry_guard_next(guard_selection, options, 0);
    tt_ptr_op(entry2, OP_EQ, chosen);

    entry1->unreachable_since = 0;
    chosen = algo_choose_entry_guard_next(guard_selection, options, 0);

  done:
    tor_free(entry1);
    tor_free(entry2);
    tor_free(guard_selection);
    tor_free(used_guards);
    tor_free(exclude_nodes);
    tor_free(options);
}

static void
test_PRIMARY_GUARDS_transitions_to_TRY_UTOPIC_when_theres_not_previous_state(
                                                                    void *arg)
{
    or_options_t *options = tor_malloc_zero(sizeof(or_options_t));
    (void) arg;

    guard_selection_t *guard_selection;
    smartlist_t *sampled_utopic = smartlist_new();
    smartlist_t *sampled_dystopic = smartlist_new();
    smartlist_t *used_guards = smartlist_new();
    smartlist_t *exclude_nodes = smartlist_new();
    int n_primary_guards = 3;
    int dir = 0;

    guard_selection = algo_choose_entry_guard_start(
        used_guards,
        sampled_utopic,
        sampled_dystopic,
        exclude_nodes,
        n_primary_guards,
        dir);

    tt_int_op(guard_selection->state, OP_EQ, STATE_PRIMARY_GUARDS);
    algo_choose_entry_guard_next(guard_selection, options, 0);
    tt_int_op(guard_selection->state, OP_EQ, STATE_TRY_UTOPIC);

  done:
    tor_free(guard_selection);
    tor_free(options);
}

static void
test_PRIMARY_GUARDS_transitions_to_previous_state_when_theres_one(void *arg)
{
    or_options_t *options = tor_malloc_zero(sizeof(or_options_t));
    (void) arg;

    guard_selection_t *guard_selection;
    smartlist_t *sampled_utopic = smartlist_new();
    smartlist_t *sampled_dystopic = smartlist_new();
    smartlist_t *used_guards = smartlist_new();
    smartlist_t *exclude_nodes = smartlist_new();
    int n_primary_guards = 3;
    int dir = 0;

    guard_selection = algo_choose_entry_guard_start(
        used_guards,
        sampled_utopic,
        sampled_dystopic,
        exclude_nodes,
        n_primary_guards,
        dir);

    tt_int_op(guard_selection->state, OP_EQ, STATE_PRIMARY_GUARDS);
    guard_selection->previous_state = STATE_TRY_DYSTOPIC;
    algo_choose_entry_guard_next(guard_selection, options, 0);
    tt_int_op(guard_selection->state, OP_EQ, STATE_TRY_DYSTOPIC);

  done:
    tor_free(guard_selection);
    tor_free(options);
}

static void
test_TRY_UTOPIC_returns_each_USED_GUARDS_not_in_PRIMARY_GUARDS(void *arg)
{
    entry_guard_t* guard = NULL;
    smartlist_t *used_guards = NULL;
    smartlist_t *primary_guards = NULL;
    entry_guard_t *g1 = NULL, *g2 = NULL, *g3 = NULL;
    or_options_t *options = tor_malloc_zero(sizeof(or_options_t));
    (void) arg;

    g1 = tor_malloc_zero(sizeof(entry_guard_t));
    g2 = tor_malloc_zero(sizeof(entry_guard_t));
    g3 = tor_malloc_zero(sizeof(entry_guard_t));

    primary_guards = smartlist_new();
    smartlist_add(primary_guards, g1);

    used_guards = smartlist_new();
    smartlist_add(used_guards, g1);
    smartlist_add(used_guards, g2);
    smartlist_add(used_guards, g3);

    guard_selection_t *guard_selection = tor_malloc_zero(
        sizeof(guard_selection_t));
    guard_selection->state = STATE_TRY_UTOPIC;
    guard_selection->used_guards = used_guards;
    guard_selection->primary_guards = primary_guards;

    guard = algo_choose_entry_guard_next(guard_selection, options, 0);
    tt_ptr_op(guard, OP_EQ, g2);

    g2->unreachable_since = 1;
    guard = algo_choose_entry_guard_next(guard_selection, options, 0);
    tt_ptr_op(guard, OP_EQ, g3);

    //XXX this seems to be unrealistic
    g2->unreachable_since = 0;
    guard = algo_choose_entry_guard_next(guard_selection, options, 0);
    tt_ptr_op(guard, OP_EQ, g2);

  done:
    tor_free(g1);
    tor_free(g2);
    tor_free(g3);
    tor_free(guard_selection);
    tor_free(used_guards);
    tor_free(primary_guards);
    tor_free(options);
}

static void
test_TRY_UTOPIC_returns_each_REMAINING_UTOPIC_by_bandwidth_weights(void *arg)
{
    entry_guard_t* guard = NULL;
    smartlist_t *our_nodelist = NULL;
    node_t *node = NULL;
    guard_selection_t *guard_selection = NULL;
    smartlist_t *primary_guards = NULL;
    smartlist_t *used_guards = NULL;
    smartlist_t *remaining_utopic_guards = NULL;
    entry_guard_t *g1, *g2, *g3, *g4 = NULL;
    or_options_t *options = tor_malloc_zero(sizeof(or_options_t));
    (void) arg;

    MOCK(node_sl_choose_by_bandwidth, node_sl_choose_by_bandwidth_mock);

    tt_int_op(smartlist_len(get_entry_guards()), OP_EQ, 0);

    our_nodelist = nodelist_get_list();
    SMARTLIST_FOREACH_BEGIN(our_nodelist, const node_t *, node) {
        const node_t *node_tmp;
        node_tmp = add_an_entry_guard(node, 0, 1, 0, 0);
        tt_assert(node_tmp);
    } SMARTLIST_FOREACH_END(node);

    node = smartlist_get(our_nodelist, 0);
    g1 = entry_guard_get_by_id_digest(node->identity);
    node = smartlist_get(our_nodelist, 1);
    g2 = entry_guard_get_by_id_digest(node->identity);
    node = smartlist_get(our_nodelist, 2);
    g3 = entry_guard_get_by_id_digest(node->identity);
    g4 = tor_malloc_zero(sizeof(entry_guard_t));

    primary_guards = smartlist_new();
    smartlist_add(primary_guards, g1);

    used_guards = smartlist_new();
    smartlist_add(used_guards, g1);

    remaining_utopic_guards = smartlist_new();
    smartlist_add(remaining_utopic_guards, g2);
    smartlist_add(remaining_utopic_guards, g3);
    smartlist_add(remaining_utopic_guards, g4); // this should be ignored

    guard_selection = tor_malloc_zero(sizeof(guard_selection_t));
    guard_selection->state = STATE_TRY_UTOPIC;
    guard_selection->used_guards = used_guards;
    guard_selection->primary_guards = primary_guards;
    guard_selection->remaining_utopic_guards = remaining_utopic_guards;

    guard = algo_choose_entry_guard_next(guard_selection, options, 0);
    tt_ptr_op(guard, OP_EQ, g2);

    g2->unreachable_since = 1;
    guard = algo_choose_entry_guard_next(guard_selection, options, 0);
    tt_ptr_op(guard, OP_EQ, g3);
    tt_assert(!smartlist_contains(guard_selection->remaining_utopic_guards,
        g2));

    g3->unreachable_since = 1;
    guard = algo_choose_entry_guard_next(guard_selection, options, 0);
    tt_ptr_op(guard, OP_EQ, NULL);
    tt_assert(!smartlist_contains(guard_selection->remaining_utopic_guards,
        g3));

  done:
    UNMOCK(node_sl_choose_by_bandwidth);
    tor_free(g4);
    tor_free(guard_selection);
    tor_free(primary_guards);
    tor_free(used_guards);
    tor_free(remaining_utopic_guards);
    tor_free(options);
}

static void
test_TRY_UTOPIC_transitions_to_TRY_DYSTOPIC(void *arg)
{
    entry_guard_t* guard = NULL;
    guard_selection_t *guard_selection = NULL;
    smartlist_t *primary_guards = NULL;
    smartlist_t *used_guards = NULL;
    smartlist_t *remaining_utopic_guards = NULL;
    or_options_t *options = tor_malloc_zero(sizeof(or_options_t));
    (void) arg;

    primary_guards = smartlist_new();
    used_guards = smartlist_new();
    remaining_utopic_guards = smartlist_new();

    guard_selection = tor_malloc_zero(sizeof(guard_selection_t));
    guard_selection->state = STATE_TRY_UTOPIC;
    guard_selection->used_guards = used_guards;
    guard_selection->primary_guards = primary_guards;
    guard_selection->remaining_utopic_guards = remaining_utopic_guards;

    guard = algo_choose_entry_guard_next(guard_selection, options, 0);
    tt_ptr_op(guard, OP_EQ, NULL);
    tt_int_op(guard_selection->state, OP_EQ, STATE_TRY_DYSTOPIC);

  done:
    tor_free(guard_selection);
    tor_free(primary_guards);
    tor_free(used_guards);
    tor_free(remaining_utopic_guards);
    tor_free(options);
}

static void
test_TRY_DYSTOPIC_returns_each_dystopic_USED_GUARDS_not_in_PRIMARY_GUARDS(
                                                                    void *arg)
{
    entry_guard_t* guard = NULL;
    smartlist_t *used_guards = NULL;
    smartlist_t *primary_guards = NULL;
    smartlist_t *dystopic_guards = NULL;
    entry_guard_t *g1 = NULL, *g2 = NULL, *g3 = NULL, *g4 = NULL;
    or_options_t *options = tor_malloc_zero(sizeof(or_options_t));
    (void) arg;

    g1 = tor_malloc_zero(sizeof(entry_guard_t));
    g2 = tor_malloc_zero(sizeof(entry_guard_t));
    g3 = tor_malloc_zero(sizeof(entry_guard_t));
    g4 = tor_malloc_zero(sizeof(entry_guard_t));

    primary_guards = smartlist_new();
    smartlist_add(primary_guards, g1);

    used_guards = smartlist_new();
    smartlist_add(used_guards, g1);
    smartlist_add(used_guards, g2);
    smartlist_add(used_guards, g3);
    smartlist_add(used_guards, g4);

    dystopic_guards = smartlist_new();
    smartlist_add(dystopic_guards, g3);
    smartlist_add(dystopic_guards, g4);

    guard_selection_t *guard_selection = tor_malloc_zero(
        sizeof(guard_selection_t));
    guard_selection->state = STATE_TRY_DYSTOPIC;
    guard_selection->used_guards = used_guards;
    guard_selection->primary_guards = primary_guards;
    guard_selection->dystopic_guards = dystopic_guards;

    guard = algo_choose_entry_guard_next(guard_selection, options, 0);
    tt_ptr_op(guard, OP_EQ, g3);

    g3->unreachable_since = 1;
    guard = algo_choose_entry_guard_next(guard_selection, options, 0);
    tt_ptr_op(guard, OP_EQ, g4);

    //XXX this seems to be unrealistic
    g3->unreachable_since = 0;
    guard = algo_choose_entry_guard_next(guard_selection, options, 0);
    tt_ptr_op(guard, OP_EQ, g3);

  done:
    tor_free(g1);
    tor_free(g2);
    tor_free(g3);
    tor_free(g4);
    tor_free(guard_selection);
    tor_free(used_guards);
    tor_free(primary_guards);
    tor_free(dystopic_guards);
    tor_free(options);
}

static void
test_TRY_DYSTOPIC_returns_each_REMAINING_DYSTOPIC_guard(void *arg)
{
    guard_selection_t *guard_selection = NULL;
    entry_guard_t* guard = NULL;
    smartlist_t *used_guards = NULL;
    smartlist_t *primary_guards = NULL;
    smartlist_t *dystopic_guards = NULL;
    smartlist_t *remaining_dystopic = NULL;
    entry_guard_t *g1, *g2, *g3, *g4 = NULL;
    node_t *node = NULL;
    or_options_t *options = tor_malloc_zero(sizeof(or_options_t));
    (void) arg;

    MOCK(node_sl_choose_by_bandwidth, node_sl_choose_by_bandwidth_mock);

    // all nodes are guards
    tt_int_op(smartlist_len(get_entry_guards()), OP_EQ, 0);

    smartlist_t *our_nodelist = nodelist_get_list();
    SMARTLIST_FOREACH_BEGIN(our_nodelist, const node_t *, node) {
        const node_t *node_tmp;
        node_tmp = add_an_entry_guard(node, 0, 1, 0, 0);
        tt_assert(node_tmp);
    } SMARTLIST_FOREACH_END(node);

    node = smartlist_get(our_nodelist, 0);
    g1 = entry_guard_get_by_id_digest(node->identity);
    node = smartlist_get(our_nodelist, 1);
    g2 = entry_guard_get_by_id_digest(node->identity);
    node = smartlist_get(our_nodelist, 2);
    g3 = entry_guard_get_by_id_digest(node->identity);
    g4 = tor_malloc_zero(sizeof(entry_guard_t));

    primary_guards = smartlist_new();
    smartlist_add(primary_guards, g1);

    used_guards = smartlist_new();
    smartlist_add(used_guards, g1);

    dystopic_guards = smartlist_new();
    remaining_dystopic = smartlist_new();
    smartlist_add(remaining_dystopic, g2);
    smartlist_add(remaining_dystopic, g3);
    smartlist_add(remaining_dystopic, g4); // this should be ignored

    guard_selection = tor_malloc_zero(sizeof(guard_selection_t));
    guard_selection->state = STATE_TRY_DYSTOPIC;
    guard_selection->used_guards = used_guards;
    guard_selection->primary_guards = primary_guards;
    guard_selection->dystopic_guards = dystopic_guards;
    guard_selection->remaining_dystopic_guards = remaining_dystopic;

    guard = algo_choose_entry_guard_next(guard_selection, options, 0);
    tt_ptr_op(guard, OP_EQ, g2);

    g2->unreachable_since = 1;
    guard = algo_choose_entry_guard_next(guard_selection, options, 0);
    tt_ptr_op(guard, OP_EQ, g3);
    tt_assert(!smartlist_contains(guard_selection->remaining_dystopic_guards,
        g2));

    g3->unreachable_since = 1;
    guard = algo_choose_entry_guard_next(guard_selection, options, 0);
    tt_ptr_op(guard, OP_EQ, NULL);
    tt_assert(!smartlist_contains(guard_selection->remaining_dystopic_guards,
        g3));

  done:
    UNMOCK(node_sl_choose_by_bandwidth);
    tor_free(g4);
    tor_free(guard_selection);
    tor_free(used_guards);
    tor_free(primary_guards);
    tor_free(dystopic_guards);
    tor_free(remaining_dystopic);
    tor_free(options);
}

static void
test_TRY_DYSTOPIC_transitions_to_PRIMARY_GUARDS(void *arg)
{
    guard_selection_t *guard_selection = NULL;
    entry_guard_t* guard = NULL;
    smartlist_t *used_guards = NULL;
    smartlist_t *primary_guards = NULL;
    smartlist_t *dystopic_guards = NULL;
    smartlist_t *remaining_dystopic = NULL;
    or_options_t *options = tor_malloc_zero(sizeof(or_options_t));
    (void) arg;

    primary_guards = smartlist_new();
    used_guards = smartlist_new();
    dystopic_guards = smartlist_new();
    remaining_dystopic = smartlist_new();

    guard_selection = tor_malloc_zero(sizeof(guard_selection_t));
    guard_selection->state = STATE_TRY_DYSTOPIC;
    guard_selection->used_guards = used_guards;
    guard_selection->primary_guards = primary_guards;
    guard_selection->dystopic_guards = dystopic_guards;
    guard_selection->remaining_dystopic_guards = remaining_dystopic;

    guard = algo_choose_entry_guard_next(guard_selection, options, 0);
    tt_ptr_op(guard, OP_EQ, NULL);
    tt_int_op(guard_selection->state, OP_EQ, STATE_PRIMARY_GUARDS);

  done:
    tor_free(guard_selection);
    tor_free(used_guards);
    tor_free(primary_guards);
    tor_free(dystopic_guards);
    tor_free(remaining_dystopic);
    tor_free(options);
}

static void
test_ON_NEW_CONSENSUS(void *arg)
{
    (void) arg;

    guard_selection_t *guard_selection = tor_malloc_zero(
        sizeof(guard_selection_t));
    entry_guard_t *g1, *g2, *g3, *g4, *g5;
    g1 = tor_malloc_zero(sizeof(entry_guard_t));
    g2 = tor_malloc_zero(sizeof(entry_guard_t));
    g3 = tor_malloc_zero(sizeof(entry_guard_t));
    smartlist_t *primary_guards = smartlist_new();
    smartlist_add(primary_guards, g1);
    smartlist_add(primary_guards, g2);
    smartlist_add(primary_guards, g3);
    smartlist_t *used_guards = smartlist_new();
    g4 = tor_malloc_zero(sizeof(entry_guard_t));
    g5 = tor_malloc_zero(sizeof(entry_guard_t));
    smartlist_add(used_guards, g4);
    smartlist_add(used_guards, g5);

    guard_selection->primary_guards = primary_guards;
    guard_selection->used_guards = used_guards;

    g1->bad_since = 1;
    g2->bad_since = 1;

    algo_on_new_consensus(guard_selection);

    tt_int_op(smartlist_len(guard_selection->primary_guards), OP_EQ, 3);
    tt_int_op(smartlist_len(guard_selection->primary_guards_log), OP_EQ, 5);
    tt_ptr_op(smartlist_get(guard_selection->primary_guards,0), OP_EQ, g3);
    tt_ptr_op(smartlist_get(guard_selection->primary_guards,1), OP_EQ, g4);
    tt_ptr_op(smartlist_get(guard_selection->primary_guards,2), OP_EQ, g5);

    g1->bad_since = 0;
    g2->bad_since = 0;

    algo_on_new_consensus(guard_selection);

    tt_int_op(smartlist_len(guard_selection->primary_guards), OP_EQ, 3);
    tt_int_op(smartlist_len(guard_selection->primary_guards_log), OP_EQ, 5);
    tt_ptr_op(smartlist_get(guard_selection->primary_guards,0), OP_EQ, g1);
    tt_ptr_op(smartlist_get(guard_selection->primary_guards,1), OP_EQ, g2);
    tt_ptr_op(smartlist_get(guard_selection->primary_guards,2), OP_EQ, g3);

    g1->bad_since = 1;
    g2->bad_since = 1;

    algo_on_new_consensus(guard_selection);

    tt_int_op(smartlist_len(guard_selection->primary_guards), OP_EQ, 3);
    tt_int_op(smartlist_len(guard_selection->primary_guards_log), OP_EQ, 5);
    tt_ptr_op(smartlist_get(guard_selection->primary_guards,0), OP_EQ, g3);
    tt_ptr_op(smartlist_get(guard_selection->primary_guards,1), OP_EQ, g4);
    tt_ptr_op(smartlist_get(guard_selection->primary_guards,2), OP_EQ, g5);

    g3->bad_since = 1;

    algo_on_new_consensus(guard_selection);

    tt_int_op(smartlist_len(guard_selection->primary_guards), OP_EQ, 2);
    tt_int_op(smartlist_len(guard_selection->primary_guards_log), OP_EQ, 5);
    tt_ptr_op(smartlist_get(guard_selection->primary_guards,0), OP_EQ, g4);
    tt_ptr_op(smartlist_get(guard_selection->primary_guards,1), OP_EQ, g5);
  done:
    tor_free(g1);
    tor_free(g2);
    tor_free(g3);
    tor_free(g4);
    tor_free(g5);
    tor_free(guard_selection);
}

struct testcase_t entrynodes_new_tests[] = {
    { "state_machine_init",
        test_STATE_PRIMARY_GUARD_is_initial_state,
        0, NULL, NULL },
    { "next_by_bandwidth",
        test_next_by_bandwidth_return_each_entry,
        TT_FORK, &fake_network, NULL },
    { "state_machine_transitions_to",
        test_state_machine_should_use_new_state_as_current_state,
        0, NULL, NULL },
    { "NEXT_transitions_to_STATE_PRIMARY_GUARDS_and_saves_previous_state",
        test_NEXT_transitions_to_PRIMARY_GUARDS_and_saves_previous_state,
        0, NULL, NULL },
    { "STATE_PRIMARY_GUARDS_returns_PRIMARY_GUARDS_in_order",
        test_PRIMARY_GUARDS_returns_PRIMARY_GUARDS_in_order,
        0, NULL, NULL },
    { "STATE_PRIMARY_GUARDS_transitions_to_previous_state",
        test_PRIMARY_GUARDS_transitions_to_previous_state_when_theres_one,
        0, NULL, NULL },
    { "STATE_PRIMARY_GUARDS_transitions_to_STATE_TRY_UTOPIC",
  test_PRIMARY_GUARDS_transitions_to_TRY_UTOPIC_when_theres_not_previous_state,
        0, NULL, NULL },
    { "STATE_TRY_UTOPIC_returns_USED_NOT_PRIMARY",
        test_TRY_UTOPIC_returns_each_USED_GUARDS_not_in_PRIMARY_GUARDS,
        0, NULL, NULL },
    { "STATE_TRY_UTOPIC_returns_REMAINING_UTOPIC",
        test_TRY_UTOPIC_returns_each_REMAINING_UTOPIC_by_bandwidth_weights,
        TT_FORK, &fake_network, NULL },
    { "STATE_TRY_UTOPIC_transitions_to_STATE_TRY_DYSTOPIC",
        test_TRY_UTOPIC_transitions_to_TRY_DYSTOPIC,
        0, NULL, NULL },
    { "STATE_TRY_DYSTOPIC_returns_dystopic_USED_NOT_PRIMARY",
     test_TRY_DYSTOPIC_returns_each_dystopic_USED_GUARDS_not_in_PRIMARY_GUARDS,
        0, NULL, NULL },
    { "STATE_TRY_DYSTOPIC_returns_REMAINING_DYSTOPIC",
        test_TRY_DYSTOPIC_returns_each_REMAINING_DYSTOPIC_guard,
        TT_FORK, &fake_network, NULL },
    { "STATE_TRY_DYSTOPIC_transitions_to_STATE_PRIMARY_GUARDS",
        test_TRY_DYSTOPIC_transitions_to_PRIMARY_GUARDS,
        0, NULL, NULL },
    { "ON_NEW_CONSENSUS",
        test_ON_NEW_CONSENSUS,
        0, NULL, NULL },

    END_OF_TESTCASES
};

