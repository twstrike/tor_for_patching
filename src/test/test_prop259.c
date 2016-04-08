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

static const node_t*
node_sl_choose_by_bandwidth_mock(const smartlist_t *sl,
    bandwidth_weight_rule_t rule)
{
    (void) rule;

    return smartlist_get(sl, 0);
}

static int
is_bad_mock(const entry_guard_t *guard)
{
    return guard->bad_since != 0;
}

static int
is_live_mock(const entry_guard_t *guard)
{
    return guard->unreachable_since == 0;
}

/* TODO:
 * choose_entry_guard_algo_next() test with state machine.
 *
 */

static void
test_STATE_PRIMARY_GUARD_is_initial_state(void *arg)
{
    guard_selection_t *guard_selection = NULL;
    guardlist_t *used_guards = guardlist_new();
    guardlist_t *sampled_utopic = guardlist_new();
    routerset_t *exclude_nodes = routerset_new();
    (void) arg;

    int n_primary_guards = 0;
    int dir = 0;

    guard_selection = choose_entry_guard_algo_start(
        used_guards,
        sampled_utopic,
        exclude_nodes,
        n_primary_guards,
        dir);

    tt_int_op(guard_selection->state, OP_EQ, STATE_PRIMARY_GUARDS);

  done:
    routerset_free(exclude_nodes);
    guardlist_free(used_guards);
    guardlist_free(sampled_utopic);
    guard_selection_free(guard_selection);
    tor_free(guard_selection);
}

static void
test_next_primary_guard(void *arg)
{
    guard_selection_t *guard_selection = tor_malloc_zero(
        sizeof(guard_selection_t));
    guardlist_t *used_guards = guardlist_new();
    smartlist_t *primary_guards = smartlist_new();
    smartlist_t *remaining_guards = smartlist_new();

    entry_guard_t *g1 = NULL;
    entry_guard_t *g2 = NULL;
    entry_guard_t *g3 = NULL;
    entry_guard_t *chosen = NULL;
    (void) arg;

    MOCK(node_sl_choose_by_bandwidth, node_sl_choose_by_bandwidth_mock);
    MOCK(is_bad, is_bad_mock);

    tt_int_op(smartlist_len(get_entry_guards()), OP_EQ, 0);

    smartlist_t *our_nodelist = nodelist_get_list();

    g1 = entry_guard_new(smartlist_get(our_nodelist, 0));
    g2 = entry_guard_new(smartlist_get(our_nodelist, 1));
    g2->bad_since = 1;
    g3 = entry_guard_new(smartlist_get(our_nodelist, 2));

    guardlist_add(used_guards, g1);
    guardlist_add(used_guards, g2);
    smartlist_add(remaining_guards, g3);

    guard_selection->used_guards = used_guards;
    guard_selection->primary_guards = primary_guards;
    guard_selection->remaining_guards = remaining_guards;

    /** Gets first used that is not bad **/
    chosen = next_primary_guard(guard_selection);
    tt_ptr_op(chosen, OP_EQ, g1);
    smartlist_add(primary_guards, chosen);

    /** No more used, gets first remaining **/
    chosen = next_primary_guard(guard_selection);
    tt_ptr_op(chosen, OP_EQ, g3);
    smartlist_add(primary_guards, chosen);

  done:
    UNMOCK(node_sl_choose_by_bandwidth);
    UNMOCK(is_bad);
    tor_free(g1);
    tor_free(g2);
    tor_free(g3);
    guardlist_free(used_guards);
    guard_selection_free(guard_selection);
    tor_free(guard_selection);
}

static void
test_fill_in_primary_guards(void *arg)
{
    guard_selection_t *guard_selection = tor_malloc_zero(
        sizeof(guard_selection_t));
    guardlist_t *used_guards = guardlist_new();
    entry_guard_t *g1 = NULL;
    entry_guard_t *g2 = NULL;
    entry_guard_t *g3 = NULL;
    entry_guard_t *g4 = NULL;
    (void) arg;

    MOCK(is_bad, is_bad_mock);

    g1 = tor_malloc_zero(sizeof(entry_guard_t));
    g2 = tor_malloc_zero(sizeof(entry_guard_t));
    g3 = tor_malloc_zero(sizeof(entry_guard_t));
    g4 = tor_malloc_zero(sizeof(entry_guard_t));

    g1->bad_since = 1; //not listed

    guardlist_add(used_guards, g1);
    guardlist_add(used_guards, g2);
    guardlist_add(used_guards, g3);
    guardlist_add(used_guards, g4);

    guard_selection->used_guards = used_guards;
    guard_selection->num_primary_guards = 2;

    fill_in_primary_guards(guard_selection);

    smartlist_t *primary_guards = guard_selection->primary_guards;
    tt_int_op(2, OP_EQ, smartlist_len(primary_guards));
    tt_ptr_op(g2, OP_EQ, smartlist_get(primary_guards, 0));
    tt_ptr_op(g3, OP_EQ, smartlist_get(primary_guards, 1));

  done:
    UNMOCK(is_bad);
    tor_free(g1);
    tor_free(g2);
    tor_free(g3);
    tor_free(g4);
    guardlist_free(used_guards);
    guard_selection_free(guard_selection);
    tor_free(guard_selection);
}

static void
test_fill_in_sampled_set(void *arg)
{
    guardlist_t *sample = guardlist_new();
    smartlist_t *set = smartlist_new();
    (void) arg;

    MOCK(node_sl_choose_by_bandwidth, node_sl_choose_by_bandwidth_mock);

    smartlist_t *our_nodelist = nodelist_get_list();
    smartlist_add(set, smartlist_get(our_nodelist, 0));
    smartlist_add(set, smartlist_get(our_nodelist, 1));
    smartlist_add(set, smartlist_get(our_nodelist, 2));

    fill_in_sampled_guard_set(sample, set, 2);
    tt_int_op(guardlist_len(sample), OP_EQ, 2);

  done:
    UNMOCK(node_sl_choose_by_bandwidth);
    smartlist_free(set);
    guardlist_free(sample);
}

static void
test_fill_in_remaining_utopic(void *arg)
{
    guard_selection_t *guard_selection = tor_malloc_zero(
        sizeof(guard_selection_t));
    guardlist_t *used = guardlist_new();
    guardlist_t *sampled = guardlist_new();
    entry_guard_t *g2 = NULL;
    (void) arg;

    smartlist_t *our_nodelist = nodelist_get_list();
    node_t *node1 = smartlist_get(our_nodelist, 0);
    node_t *node2 = smartlist_get(our_nodelist, 1);
    node_t *node3 = smartlist_get(our_nodelist, 2);

    g2 = entry_guard_new(node2);
    guardlist_add(sampled, entry_guard_new(node1));
    guardlist_add(sampled, g2);
    guardlist_add(sampled, entry_guard_new(node3));
    guardlist_add(used, g2);

    guard_selection->used_guards = used;
    fill_in_remaining_utopic(guard_selection, sampled);

    tt_int_op(smartlist_len(guard_selection->remaining_guards),
        OP_EQ, 2);

    entry_guard_t* guard = smartlist_get(guard_selection->remaining_guards, 0);
    tt_int_op(strcmp_len(guard->identity, node1->identity, DIGEST_LEN),
        OP_EQ, 0);

    guard = smartlist_get(guard_selection->remaining_guards, 1);
    tt_int_op(strcmp_len(guard->identity, node3->identity, DIGEST_LEN),
        OP_EQ, 0);

  done:
    tor_free(g2);
    guardlist_free(used);
    guardlist_free(sampled);
    guard_selection_free(guard_selection);
    tor_free(guard_selection);
}

static void
test_state_machine_should_use_new_state_as_current_state(void *arg)
{
    (void) arg;

    guard_selection_t *guard_selection;
    guardlist_t *sampled_utopic = guardlist_new();
    guardlist_t *used_guards = guardlist_new();
    routerset_t *exclude_nodes = routerset_new();
    int n_primary_guards = 0;
    int dir = 0;

    guard_selection = choose_entry_guard_algo_start(
        used_guards,
        sampled_utopic,
        exclude_nodes,
        n_primary_guards,
        dir);

    tt_int_op(guard_selection->state, OP_EQ, STATE_PRIMARY_GUARDS);
    transition_to(guard_selection, STATE_TRY_UTOPIC);
    tt_int_op(guard_selection->state, OP_EQ, STATE_TRY_UTOPIC);

  done:
    routerset_free(exclude_nodes);
    guardlist_free(sampled_utopic);
    guardlist_free(used_guards);
    guard_selection_free(guard_selection);
    tor_free(guard_selection);
}

static void
test_NEXT_transitions_to_PRIMARY_GUARDS_and_saves_previous_state(void *arg)
{
    guard_selection_t *guard_selection = tor_malloc_zero(
        sizeof(guard_selection_t));
    smartlist_t *primary_guards = smartlist_new();
    guardlist_t *used_guards = guardlist_new();
    smartlist_t *remaining_guards = smartlist_new();
    or_options_t *options = tor_malloc_zero(sizeof(or_options_t));

    entry_guard_t *chosen = NULL;
    entry_guard_t *g1 = NULL, *g2 = NULL, *g3 = NULL;
    (void) arg;

    MOCK(is_live, is_live_mock);
    MOCK(is_bad, is_bad_mock);
    MOCK(node_sl_choose_by_bandwidth, node_sl_choose_by_bandwidth_mock);

    time_t now = 100;
    options->PrimaryGuardsRetryInterval = 3;

    g1 = tor_malloc_zero(sizeof(entry_guard_t));
    g2 = tor_malloc_zero(sizeof(entry_guard_t));
    g3 = tor_malloc_zero(sizeof(entry_guard_t));

    smartlist_add(primary_guards, g1);
    guardlist_add(used_guards, g1);
    guardlist_add(used_guards, g3); //used not in primary

    g1->last_attempted = now - 3*60;
    g2->last_attempted = now - 10;

    guard_selection->state = STATE_TRY_UTOPIC;
    guard_selection->used_guards = used_guards;
    guard_selection->primary_guards = primary_guards;
    guard_selection->remaining_guards = remaining_guards;

    chosen = choose_entry_guard_algo_next(guard_selection, options, now-1);
    tt_ptr_op(chosen, OP_EQ, g3);
    tt_int_op(guard_selection->state, OP_EQ, STATE_TRY_UTOPIC);

    chosen = choose_entry_guard_algo_next(guard_selection, options, now);
    tt_int_op(guard_selection->state, OP_EQ, STATE_PRIMARY_GUARDS);

  done:
    UNMOCK(node_sl_choose_by_bandwidth);
    UNMOCK(is_bad);
    UNMOCK(is_live);
    tor_free(g1);
    tor_free(g2);
    tor_free(g3);
    guardlist_free(used_guards);
    guard_selection_free(guard_selection);
    tor_free(guard_selection);
    tor_free(options);
}

static void
test_PRIMARY_GUARDS_returns_PRIMARY_GUARDS_in_order(void *arg)
{
    guard_selection_t *guard_selection;
    guardlist_t *sampled_utopic = guardlist_new();
    guardlist_t *used_guards = guardlist_new();
    routerset_t *exclude_nodes = routerset_new();
    entry_guard_t *entry1 = NULL, *entry2 = NULL;
    or_options_t *options = tor_malloc_zero(sizeof(or_options_t));
    (void) arg;

    MOCK(is_bad, is_bad_mock);
    MOCK(is_live, is_live_mock);

    int n_primary_guards = 0;
    int dir = 0;

    guard_selection = choose_entry_guard_algo_start(
        used_guards,
        sampled_utopic,
        exclude_nodes,
        n_primary_guards,
        dir);

    entry1 = tor_malloc_zero(sizeof(entry_guard_t));
    entry2 = tor_malloc_zero(sizeof(entry_guard_t));
    smartlist_add(guard_selection->primary_guards, entry1);
    smartlist_add(guard_selection->primary_guards, entry2);

    entry_guard_t *chosen = choose_entry_guard_algo_next(
        guard_selection, options, 0);
    tt_ptr_op(entry1, OP_EQ, chosen);
    chosen = choose_entry_guard_algo_next(guard_selection, options, 0);
    tt_ptr_op(entry1, OP_EQ, chosen);

    entry1->unreachable_since = 1;
    chosen = choose_entry_guard_algo_next(guard_selection, options, 0);
    tt_ptr_op(entry2, OP_EQ, chosen);

    entry1->unreachable_since = 0;
    chosen = choose_entry_guard_algo_next(guard_selection, options, 0);

  done:
    UNMOCK(is_live);
    UNMOCK(is_bad);
    tor_free(entry1);
    tor_free(entry2);
    guardlist_free(used_guards);
    guardlist_free(sampled_utopic);
    routerset_free(exclude_nodes);
    tor_free(options);
    guard_selection_free(guard_selection);
    tor_free(guard_selection);
}

static void
test_PRIMARY_GUARDS_transitions_to_TRY_UTOPIC_when_theres_not_previous_state(
                                                                    void *arg)
{
    or_options_t *options = tor_malloc_zero(sizeof(or_options_t));
    (void) arg;

    guard_selection_t *guard_selection;
    guardlist_t *sampled_utopic = guardlist_new();
    guardlist_t *used_guards = guardlist_new();
    routerset_t *exclude_nodes = routerset_new();
    int n_primary_guards = 0;
    int dir = 0;

    guard_selection = choose_entry_guard_algo_start(
        used_guards,
        sampled_utopic,
        exclude_nodes,
        n_primary_guards,
        dir);

    tt_int_op(guard_selection->state, OP_EQ, STATE_PRIMARY_GUARDS);
    choose_entry_guard_algo_next(guard_selection, options, 0);
    tt_int_op(guard_selection->state, OP_EQ, STATE_TRY_UTOPIC);

  done:
    guardlist_free(used_guards);
    guardlist_free(sampled_utopic);
    guard_selection_free(guard_selection);
    tor_free(guard_selection);
    tor_free(options);
}

static void
test_PRIMARY_GUARDS_transitions_to_previous_state_when_theres_one(void *arg)
{
    or_options_t *options = tor_malloc_zero(sizeof(or_options_t));
    (void) arg;

    guard_selection_t *guard_selection;
    guardlist_t *sampled_utopic = guardlist_new();
    guardlist_t *used_guards = guardlist_new();
    routerset_t *exclude_nodes = routerset_new();
    int n_primary_guards = 0;
    int dir = 0;

    guard_selection = choose_entry_guard_algo_start(
        used_guards,
        sampled_utopic,
        exclude_nodes,
        n_primary_guards,
        dir);

    tt_int_op(guard_selection->state, OP_EQ, STATE_PRIMARY_GUARDS);
    guard_selection->previous_state = STATE_TRY_UTOPIC;
    choose_entry_guard_algo_next(guard_selection, options, 0);
    tt_int_op(guard_selection->state, OP_EQ, STATE_TRY_UTOPIC);

  done:
    guardlist_free(used_guards);
    guardlist_free(sampled_utopic);
    guard_selection_free(guard_selection);
    tor_free(guard_selection);
    tor_free(options);
}

static void
test_TRY_UTOPIC_returns_each_USED_GUARDS_not_in_PRIMARY_GUARDS(void *arg)
{
    entry_guard_t* guard = NULL;
    guardlist_t *used_guards = guardlist_new();
    smartlist_t *primary_guards = NULL;
    entry_guard_t *g1 = NULL, *g2 = NULL, *g3 = NULL;
    or_options_t *options = tor_malloc_zero(sizeof(or_options_t));
    guard_selection_t *guard_selection = NULL;
    (void) arg;

    MOCK(is_bad, is_bad_mock);
    MOCK(is_live, is_live_mock);

    g1 = tor_malloc_zero(sizeof(entry_guard_t));
    g2 = tor_malloc_zero(sizeof(entry_guard_t));
    g3 = tor_malloc_zero(sizeof(entry_guard_t));

    primary_guards = smartlist_new();
    smartlist_add(primary_guards, g1);

    guardlist_add(used_guards, g1);
    guardlist_add(used_guards, g2);
    guardlist_add(used_guards, g3);

    tt_int_op(is_live(g1), OP_EQ, 1);
    tt_int_op(is_live(g2), OP_EQ, 1);
    tt_int_op(is_live(g3), OP_EQ, 1);

    guard_selection = tor_malloc_zero(sizeof(guard_selection_t));
    guard_selection->state = STATE_TRY_UTOPIC;
    guard_selection->used_guards = used_guards;
    guard_selection->primary_guards = primary_guards;

    guard = choose_entry_guard_algo_next(guard_selection, options, 0);
    tt_ptr_op(guard, OP_EQ, g2);

    g2->unreachable_since = 1;
    guard = choose_entry_guard_algo_next(guard_selection, options, 0);
    tt_ptr_op(guard, OP_EQ, g3);

    //XXX this seems to be unrealistic
    g2->unreachable_since = 0;
    guard = choose_entry_guard_algo_next(guard_selection, options, 0);
    tt_ptr_op(guard, OP_EQ, g2);

  done:
    UNMOCK(is_live);
    UNMOCK(is_bad);
    tor_free(g1);
    tor_free(g2);
    tor_free(g3);
    guardlist_free(used_guards);
    guard_selection_free(guard_selection);
    tor_free(guard_selection);
    tor_free(options);
}

static void
test_TRY_UTOPIC_returns_each_REMAINING_UTOPIC_by_bandwidth_weights(void *arg)
{
    guard_selection_t *guard_selection = NULL;
    smartlist_t *primary_guards = smartlist_new();
    guardlist_t *used_guards = guardlist_new();
    smartlist_t *remaining_guards = smartlist_new();
    or_options_t *options = tor_malloc_zero(sizeof(or_options_t));
    entry_guard_t *g1 = NULL;
    entry_guard_t *g2 = NULL;
    entry_guard_t *g3 = NULL;
    (void) arg;

    MOCK(node_sl_choose_by_bandwidth, node_sl_choose_by_bandwidth_mock);
    MOCK(is_live, is_live_mock);

    tt_int_op(smartlist_len(get_entry_guards()), OP_EQ, 0);

    smartlist_t *our_nodelist = nodelist_get_list();
    node_t *n1 = smartlist_get(our_nodelist, 0);
    node_t *n2 = smartlist_get(our_nodelist, 1);
    node_t *n3 = smartlist_get(our_nodelist, 2);

    //entry_guard_get_by_id_digest(node->identity);
    g1 = entry_guard_new(n1);
    smartlist_add(primary_guards, g1);
    guardlist_add(used_guards, g1);

    g2 = entry_guard_new(n2);
    g3 = entry_guard_new(n3);
    smartlist_add(remaining_guards, g2);
    smartlist_add(remaining_guards, g3);

    guard_selection = tor_malloc_zero(sizeof(guard_selection_t));
    guard_selection->state = STATE_TRY_UTOPIC;
    guard_selection->used_guards = used_guards;
    guard_selection->primary_guards = primary_guards;
    guard_selection->remaining_guards = remaining_guards;

    entry_guard_t* chosen = choose_entry_guard_algo_next(
        guard_selection, options, 0);
    tt_ptr_op(chosen, OP_EQ, g2);

    chosen->unreachable_since = 1;
    chosen = choose_entry_guard_algo_next(guard_selection, options, 0);
    tt_ptr_op(chosen, OP_EQ, g3);
    tt_assert(!smartlist_contains(guard_selection->remaining_guards,
        g2));

    chosen->unreachable_since = 1;
    chosen = choose_entry_guard_algo_next(guard_selection, options, 0);
    tt_ptr_op(chosen, OP_EQ, NULL);
    tt_assert(!smartlist_contains(guard_selection->remaining_guards,
        g3));

  done:
    UNMOCK(is_live);
    UNMOCK(node_sl_choose_by_bandwidth);
    tor_free(g1);
    tor_free(g2);
    tor_free(g3);
    guardlist_free(used_guards);
    guard_selection_free(guard_selection);
    tor_free(guard_selection);
    tor_free(options);
    remove_all_entry_guards();
}

static void
test_TRY_UTOPIC_transitions_to_PRIMARY_GUARDS(void *arg)
{
    entry_guard_t* guard = NULL;
    guard_selection_t *guard_selection = NULL;
    smartlist_t *primary_guards = smartlist_new();;
    guardlist_t *used_guards = guardlist_new();
    smartlist_t *remaining_guards = smartlist_new();
    or_options_t *options = tor_malloc_zero(sizeof(or_options_t));
    (void) arg;

    guard_selection = tor_malloc_zero(sizeof(guard_selection_t));
    guard_selection->state = STATE_TRY_UTOPIC;
    guard_selection->used_guards = used_guards;
    guard_selection->primary_guards = primary_guards;
    guard_selection->remaining_guards = remaining_guards;

    guard = choose_entry_guard_algo_next(guard_selection, options, 0);
    tt_ptr_op(guard, OP_EQ, NULL);
    tt_int_op(guard_selection->state, OP_EQ, STATE_PRIMARY_GUARDS);

  done:
    guardlist_free(used_guards);
    guard_selection_free(guard_selection);
    tor_free(guard_selection);
    tor_free(options);
}

static void
test_ON_NEW_CONSENSUS(void *arg)
{
    guard_selection_t *guard_selection = tor_malloc_zero(
        sizeof(guard_selection_t));
    guardlist_t *used_guards = guardlist_new();
    smartlist_t *primary_guards = smartlist_new();
    entry_guard_t *g1, *g2, *g3, *g4, *g5;
    (void) arg;

    MOCK(is_bad, is_bad_mock);

    g1 = tor_malloc_zero(sizeof(entry_guard_t));
    g2 = tor_malloc_zero(sizeof(entry_guard_t));
    g3 = tor_malloc_zero(sizeof(entry_guard_t));
    g4 = tor_malloc_zero(sizeof(entry_guard_t));
    g5 = tor_malloc_zero(sizeof(entry_guard_t));

    g1->bad_since = 0;
    g2->bad_since = 0;
    g3->bad_since = 0;
    g4->bad_since = 1;
    g5->bad_since = 1;

    smartlist_add(primary_guards, g1);
    smartlist_add(primary_guards, g2);
    smartlist_add(primary_guards, g3);
    guardlist_add(used_guards, g1);
    guardlist_add(used_guards, g2);
    guardlist_add(used_guards, g4);
    guardlist_add(used_guards, g5);

    guard_selection->primary_guards = primary_guards;
    guard_selection->used_guards = used_guards;
    guard_selection->num_primary_guards = 3;

    g1->bad_since = 1;
    g2->bad_since = 1;
    g3->bad_since = 0;
    g4->bad_since = 0;
    g5->bad_since = 0;

    choose_entry_guard_algo_new_consensus(guard_selection);

    tt_int_op(smartlist_len(nonbad_guards(guard_selection->primary_guards)),
        OP_EQ, 3);
    tt_ptr_op(smartlist_get(nonbad_guards(guard_selection->primary_guards),0),
        OP_EQ, g3);
    tt_ptr_op(smartlist_get(nonbad_guards(guard_selection->primary_guards),1),
        OP_EQ, g4);
    tt_ptr_op(smartlist_get(nonbad_guards(guard_selection->primary_guards),2),
        OP_EQ, g5);

    g1->bad_since = 0;
    g2->bad_since = 0;
    g3->bad_since = 0;
    g4->bad_since = 0;
    g5->bad_since = 0;

    choose_entry_guard_algo_new_consensus(guard_selection);

    tt_int_op(smartlist_len(nonbad_guards(guard_selection->primary_guards)),
        OP_EQ, 5);
    tt_ptr_op(smartlist_get(nonbad_guards(guard_selection->primary_guards),0),
        OP_EQ, g1);
    tt_ptr_op(smartlist_get(nonbad_guards(guard_selection->primary_guards),1),
        OP_EQ, g2);
    tt_ptr_op(smartlist_get(nonbad_guards(guard_selection->primary_guards),2),
        OP_EQ, g3);

    g1->bad_since = 0;
    g2->bad_since = 1;
    g3->bad_since = 0;
    g4->bad_since = 1;
    g5->bad_since = 0;

    choose_entry_guard_algo_new_consensus(guard_selection);

    tt_int_op(smartlist_len(nonbad_guards(guard_selection->primary_guards)),
        OP_EQ, 3);
    tt_ptr_op(smartlist_get(nonbad_guards(guard_selection->primary_guards),0),
        OP_EQ, g1);
    tt_ptr_op(smartlist_get(nonbad_guards(guard_selection->primary_guards),1),
        OP_EQ, g3);
    tt_ptr_op(smartlist_get(nonbad_guards(guard_selection->primary_guards),2),
        OP_EQ, g5);

  done:
    UNMOCK(is_bad);
    tor_free(g1);
    tor_free(g2);
    tor_free(g3);
    tor_free(g4);
    tor_free(g5);
    guardlist_free(used_guards);
    guard_selection_free(guard_selection);
    tor_free(guard_selection);
}

static void
test_choose_entry_guard_algo_should_continue_when_circuit_fails(void *arg)
{
    guard_selection_t *guard_selection =
        tor_malloc_zero(sizeof(guard_selection_t));
    int succeeded = 0;
    time_t now = time(NULL);
    (void) arg;

    int should_continue = choose_entry_guard_algo_should_continue
        (guard_selection, succeeded, now, 5);

    tt_int_op(should_continue, OP_EQ, 1);

  done:
    guard_selection_free(guard_selection);
    tor_free(guard_selection);
}

static void
test_should_not_continue_when_circuit_succeeds_for_first_time(void *arg)
{
    guard_selection_t *guard_selection =
        tor_malloc_zero(sizeof(guard_selection_t));
    int succeeded = 1;
    time_t now = time(NULL);
    (void) arg;

    int should_continue = choose_entry_guard_algo_should_continue
        (guard_selection, succeeded, now, 5);

    tt_int_op(should_continue, OP_EQ, 0);

  done:
    guard_selection_free(guard_selection);
    tor_free(guard_selection);
}

static void
test_should_continue_when_last_sucess_was_before_likely_down_interval(
    void *arg)
{
    guard_selection_t *guard_selection =
        tor_malloc_zero(sizeof(guard_selection_t));
    int succeeded = 1;
    time_t now = time(NULL);
    (void) arg;

    guard_selection->primary_guards = smartlist_new();
    guard_selection->last_success = now - 61;
    int should_continue = choose_entry_guard_algo_should_continue
        (guard_selection, succeeded, now, 1);

    tt_int_op(should_continue, OP_EQ, 1);

  done:
    guard_selection_free(guard_selection);
    tor_free(guard_selection);
}

static void
test_should_not_continue_when_last_success_was_after_likely_down_interval(
    void *arg)
{
    guard_selection_t *guard_selection =
        tor_malloc_zero(sizeof(guard_selection_t));
    int succeeded = 1;
    time_t now = time(NULL);
    (void) arg;

    guard_selection->used_guards = guardlist_new();
    guard_selection->last_success = now - 60;
    int should_continue = choose_entry_guard_algo_should_continue
        (guard_selection, succeeded, now, 1);

    tt_int_op(should_continue, OP_EQ, 0);

  done:
    guardlist_free(guard_selection->used_guards);
    guard_selection_free(guard_selection);
    tor_free(guard_selection);
}

static void
state_insert_line_helper(config_line_t **next,
                                smartlist_t *lines)
{
  config_line_t *line;
  *next = NULL;

  /* Loop over all the state lines in the smartlist */
  SMARTLIST_FOREACH_BEGIN(lines, const smartlist_t *,state_lines) {
    /* Get key and value for each line */
    const char *state_key = smartlist_get(state_lines, 0);
    const char *state_value = smartlist_get(state_lines, 1);

    *next = line = tor_malloc_zero(sizeof(config_line_t));
    line->key = tor_strdup(state_key);
    tor_asprintf(&line->value, "%s", state_value);
    next = &(line->next);
  } SMARTLIST_FOREACH_END(state_lines);
}

static void
state_lines_free(smartlist_t *lines)
{
  SMARTLIST_FOREACH_BEGIN(lines, smartlist_t *, state_lines) {
    char *state_key = smartlist_get(state_lines, 0);
    char *state_value = smartlist_get(state_lines, 1);

    tor_free(state_key);
    tor_free(state_value);
    smartlist_free(state_lines);
  } SMARTLIST_FOREACH_END(state_lines);

  smartlist_free(lines);
}

static void
test_used_guards_parse_state(void *arg)
{
  or_state_t *state = or_state_new();
  smartlist_t *used_state_lines = smartlist_new();
  smartlist_t *used_guards = smartlist_new();
  char *msg = NULL;
  int retval;

  /* Details of our fake guard node */
  const char *nickname = "hagbard";
  const char *fpr = "B29D536DD1752D542E1FBB3C9CE4449D51298212";
  const char *unlisted_since = "2014-06-08 16:16:50";
  const char *down_since = "2014-06-07 16:16:40";
  const char *tor_version = "0.2.5.3-alpha-dev";
  const char *added_at = get_yesterday_date_str();

  /* Path bias details of the fake guard */
  const double circ_attempts = 9;
  const double circ_successes = 8;
  const double successful_closed = 4;
  const double collapsed = 2;
  const double unusable = 0;
  const double timeouts = 1;

  (void) arg;

  { /* Prepare the state entry */

    /* Prepare the smartlist to hold the key/value of each line */
    smartlist_t *state_line = smartlist_new();
    smartlist_add_asprintf(state_line, "UsedGuard");
    smartlist_add_asprintf(state_line, "%s %s %s", nickname, fpr, "DirCache");
    smartlist_add(used_state_lines, state_line);

    state_line = smartlist_new();
    smartlist_add_asprintf(state_line, "UsedGuardDownSince");
    smartlist_add_asprintf(state_line, "%s", down_since);
    smartlist_add(used_state_lines, state_line);

    state_line = smartlist_new();
    smartlist_add_asprintf(state_line, "UsedGuardUnlistedSince");
    smartlist_add_asprintf(state_line, "%s", unlisted_since);
    smartlist_add(used_state_lines, state_line);

    state_line = smartlist_new();
    smartlist_add_asprintf(state_line, "UsedGuardAddedBy");
    smartlist_add_asprintf(state_line, "%s %s %s", fpr, tor_version, added_at);
    smartlist_add(used_state_lines, state_line);

    state_line = smartlist_new();
    smartlist_add_asprintf(state_line, "USedGuardPathBias");
    smartlist_add_asprintf(state_line, "%f %f %f %f %f %f",
                           circ_attempts, circ_successes, successful_closed,
                           collapsed, unusable, timeouts);
    smartlist_add(used_state_lines, state_line);
  }

  /* Inject our lines in the state */
  state_insert_line_helper(&state->UsedGuards, used_state_lines);

  /* Parse state */
  retval = used_guards_parse_state(state, used_guards, &msg);
  tt_int_op(retval, OP_GE, 0);

  tt_int_op(smartlist_len(used_guards), OP_EQ, 1);

  { /* Test the entry guard structure */
    char hex_digest[1024];
    char str_time[1024];

    const entry_guard_t *e = smartlist_get(used_guards, 0);
    tt_str_op(e->nickname, OP_EQ, nickname); /* Verify nickname */

    base16_encode(hex_digest, sizeof(hex_digest),
                  e->identity, DIGEST_LEN);
    tt_str_op(hex_digest, OP_EQ, fpr); /* Verify fingerprint */

    tt_assert(e->is_dir_cache); /* Verify dirness */

    tt_str_op(e->chosen_by_version, OP_EQ, tor_version); /* Verify version */

    tt_assert(e->bad_since); /* Verify bad_since timestamp */
    format_iso_time(str_time, e->bad_since);
    tt_str_op(str_time, OP_EQ, unlisted_since);

    tt_assert(e->unreachable_since); /* Verify unreachable_since timestamp */
    format_iso_time(str_time, e->unreachable_since);
    tt_str_op(str_time, OP_EQ, down_since);

    /* XXX tt_double_op doesn't support equality. Cast to int for now. */
    tt_int_op((int)e->circ_attempts, OP_EQ, (int)circ_attempts);
    tt_int_op((int)e->circ_successes, OP_EQ, (int)circ_successes);
    tt_int_op((int)e->successful_circuits_closed, OP_EQ,
              (int)successful_closed);
    tt_int_op((int)e->timeouts, OP_EQ, (int)timeouts);
    tt_int_op((int)e->collapsed_circuits, OP_EQ, (int)collapsed);
    tt_int_op((int)e->unusable_circuits, OP_EQ, (int)unusable);

    /* The rest should be unset */
    tt_assert(!e->made_contact);
    tt_assert(!e->can_retry);
    tt_assert(!e->path_bias_noticed);
    tt_assert(!e->path_bias_warned);
    tt_assert(!e->path_bias_extreme);
    tt_assert(!e->path_bias_disabled);
    tt_assert(!e->path_bias_use_noticed);
    tt_assert(!e->path_bias_use_extreme);
    tt_assert(!e->last_attempted);
  }

 done:
  state_lines_free(used_state_lines);
  SMARTLIST_FOREACH(used_guards, entry_guard_t *, e, entry_guard_free(e));
  smartlist_free(used_guards);
  or_state_free(state);
  tor_free(msg);
}

static void
test_used_guards_parse_state_backward_compatible(void *arg)
{
  or_state_t *state = or_state_new();
  smartlist_t *entry_state_lines = smartlist_new();
  smartlist_t *used_guards = smartlist_new();
  char *msg = NULL;
  int retval;

  /* Details of our fake guard node */
  const char *nickname = "hagbard";
  const char *fpr = "B29D536DD1752D542E1FBB3C9CE4449D51298212";
  const char *unlisted_since = "2014-06-08 16:16:50";
  const char *down_since = "2014-06-07 16:16:40";

  (void) arg;

  dummy_state = tor_malloc_zero(sizeof(or_state_t));
  MOCK(get_or_state, get_or_state_replacement);

  { /* Prepare backwards compatible state entry */
    smartlist_t *state_line = smartlist_new();
    smartlist_add_asprintf(state_line, "EntryGuard");
    smartlist_add_asprintf(state_line, "%s %s %s", nickname, fpr, "DirCache");
    smartlist_add(entry_state_lines, state_line);

    state_line = smartlist_new();
    smartlist_add_asprintf(state_line, "EntryGuardDownSince");
    smartlist_add_asprintf(state_line, "%s", down_since);
    smartlist_add(entry_state_lines, state_line);

    state_line = smartlist_new();
    smartlist_add_asprintf(state_line, "EntryGuardUnlistedSince");
    smartlist_add_asprintf(state_line, "%s", unlisted_since);
    smartlist_add(entry_state_lines, state_line);
  }

  /* Inject our lines in the state */
  state_insert_line_helper(&state->EntryGuards, entry_state_lines);

  /* Parse state */
  retval = entry_guards_parse_state_backward(state, used_guards, &msg);
  tt_int_op(retval, OP_GE, 0);

  tt_int_op(smartlist_len(used_guards), OP_EQ, 1);

  { /* Test the entry guard structure */
    char hex_digest[1024];
    char str_time[1024];

    const entry_guard_t *e = smartlist_get(used_guards, 0);
    tt_str_op(e->nickname, OP_EQ, nickname); /* Verify nickname */

    base16_encode(hex_digest, sizeof(hex_digest),
                  e->identity, DIGEST_LEN);
    tt_str_op(hex_digest, OP_EQ, fpr); /* Verify fingerprint */

    tt_assert(e->is_dir_cache); /* Verify dirness */

    tt_assert(e->bad_since); /* Verify bad_since timestamp */
    format_iso_time(str_time, e->bad_since);
    tt_str_op(str_time, OP_EQ, unlisted_since);

    tt_assert(e->unreachable_since); /* Verify unreachable_since timestamp */
    format_iso_time(str_time, e->unreachable_since);
    tt_str_op(str_time, OP_EQ, down_since);

    /* The rest should be unset */
    tt_assert(!e->made_contact);
    tt_assert(!e->chosen_by_version);
    tt_assert(!e->can_retry);
    tt_assert(!e->path_bias_noticed);
    tt_assert(!e->path_bias_warned);
    tt_assert(!e->path_bias_extreme);
    tt_assert(!e->path_bias_disabled);
    tt_assert(!e->path_bias_use_noticed);
    tt_assert(!e->path_bias_use_extreme);
    tt_assert(!e->last_attempted);
  }

 done:
  UNMOCK(get_or_state);
  tor_free(dummy_state);
  state_lines_free(entry_state_lines);
  SMARTLIST_FOREACH(used_guards, entry_guard_t *, e, entry_guard_free(e));
  smartlist_free(used_guards);
  or_state_free(state);
  tor_free(msg);
}

struct testcase_t entrynodes_new_tests[] = {
    { "used_guards_parse_state",
        test_used_guards_parse_state,
        0, NULL, NULL },
    { "used_guards_parse_state_backward_compatible",
        test_used_guards_parse_state_backward_compatible,
        0, NULL, NULL },
    { "state_machine_init",
        test_STATE_PRIMARY_GUARD_is_initial_state,
        0, NULL, NULL },
    { "next_primary_guard",
        test_next_primary_guard,
        TT_FORK, &fake_network, NULL },
    { "fill_in_primary_guards",
        test_fill_in_primary_guards,
        TT_FORK, &fake_network, NULL },
    { "fill_in_sampled_set",
        test_fill_in_sampled_set,
        TT_FORK, &fake_network, NULL },
    { "fill_in_remaining_utopic",
        test_fill_in_remaining_utopic,
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
    { "STATE_TRY_UTOPIC_transitions_to_STATE_PRIMARY_GUARDS",
        test_TRY_UTOPIC_transitions_to_PRIMARY_GUARDS,
        0, NULL, NULL },
    { "ON_NEW_CONSENSUS",
        test_ON_NEW_CONSENSUS,
        0, NULL, NULL },
    { "should_continue_when_circuit_fails",
      test_choose_entry_guard_algo_should_continue_when_circuit_fails,
      0, NULL, NULL },
    { "should_not_continue_when_circuit_succeeds_for_first_time",
      test_should_not_continue_when_circuit_succeeds_for_first_time,
      0, NULL, NULL },
    { "should_continue_when_last_sucess_was_before_likely_down_interval",
      test_should_continue_when_last_sucess_was_before_likely_down_interval,
      0, NULL, NULL },
    { "should_not_continue_when_last_success_was_after_likely_down_interval",
    test_should_not_continue_when_last_success_was_after_likely_down_interval,
      0, NULL, NULL },

    END_OF_TESTCASES
};

