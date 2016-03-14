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

/* TODO:
 * algo_choose_entry_guard_next() test with state machine.
 *
 */

static void
test_STATE_PRIMARY_GUARD_is_initial_state(void *arg)
{
  guard_selection_t *guard_selection = NULL;
  smartlist_t *used_guards = smartlist_new();
  smartlist_t *exclude_nodes = smartlist_new();
  int n_primary_guards = 3;
  int dir = 0;

  (void) arg;
  guard_selection = algo_choose_entry_guard_start(
          used_guards,
          NULL, NULL,
          exclude_nodes,
          n_primary_guards,
          dir);
  tt_int_op(guard_selection->state, OP_EQ, STATE_PRIMARY_GUARDS);

 done:
  tor_free(guard_selection);
  tor_free(used_guards);
  tor_free(exclude_nodes);
}

static void
test_state_machine_should_use_new_state_as_current_state(void *arg)
{
  guard_selection_t *guard_selection = NULL;
  smartlist_t *used_guards = smartlist_new();
  smartlist_t *exclude_nodes = smartlist_new();
  int n_primary_guards = 3;
  int dir = 0;

  guard_selection = algo_choose_entry_guard_start(
          used_guards,
          NULL, NULL,
          exclude_nodes,
          n_primary_guards,
          dir);
  (void) arg;

  tt_int_op(guard_selection->state, OP_EQ, STATE_PRIMARY_GUARDS);
  transition_to(guard_selection, STATE_TRY_UTOPIC);
  tt_int_op(guard_selection->state, OP_EQ, STATE_TRY_UTOPIC);

 done:
  tor_free(guard_selection);
  tor_free(used_guards);
  tor_free(exclude_nodes);
}

static void
test_state_machine_should_return_primary_guard_by_order(void *arg)
{
  guard_selection_t *guard_selection = NULL;
  smartlist_t *used_guards = smartlist_new();
  smartlist_t *exclude_nodes = smartlist_new();
  int n_primary_guards = 3;
  int dir = 0;

  guard_selection = algo_choose_entry_guard_start(
          used_guards,
          NULL, NULL,
          exclude_nodes,
          n_primary_guards,
          dir);
  (void) arg;

  entry_guard_t *entry1 = tor_malloc_zero(sizeof(entry_guard_t));
  entry_guard_t *entry2 = tor_malloc_zero(sizeof(entry_guard_t));
  smartlist_add(guard_selection->primary_guards, entry1);
  smartlist_add(guard_selection->primary_guards, entry2);

  entry_guard_t *guard1 = algo_choose_entry_guard_next(guard_selection);
  tt_ptr_op(entry1, OP_EQ, guard1);
  entry_guard_t *guard2 = algo_choose_entry_guard_next(guard_selection);
  tt_ptr_op(entry1, OP_EQ, guard2);
  entry1->unreachable_since = 1;
  entry_guard_t *guard3 = algo_choose_entry_guard_next(guard_selection);
  tt_ptr_op(entry2, OP_EQ, guard3);
  // XXX 0 is Jan 1st 1970, I think it should be something else
  entry1->unreachable_since = 0;
  entry_guard_t *guard4 = algo_choose_entry_guard_next(guard_selection);
  tt_ptr_op(entry1, OP_EQ, guard4);

 done:
  tor_free(guard_selection);
  tor_free(used_guards);
  tor_free(exclude_nodes);
}

static void
test_PRIMARY_GUARDS_transitions_to_TRY_UTOPIC_when_theres_not_previous_state(void *arg)
{
  guard_selection_t *guard_selection = NULL;
  smartlist_t *used_guards = NULL;
  smartlist_t *exclude_nodes = NULL;
  int n_primary_guards = 3;
  int dir = 0;

  guard_selection = algo_choose_entry_guard_start(
          used_guards,
          NULL, NULL,
          exclude_nodes,
          n_primary_guards,
          dir);
  (void) arg;

  tt_int_op(guard_selection->state, OP_EQ, STATE_PRIMARY_GUARDS);
  algo_choose_entry_guard_next(guard_selection);
  tt_int_op(guard_selection->state, OP_EQ, STATE_TRY_UTOPIC);

 done:
  tor_free(guard_selection);
}

static void
test_PRIMARY_GUARDS_transitions_to_previous_state_when_theres_one(void *arg)
{
  guard_selection_t *guard_selection = NULL;
  smartlist_t *used_guards = NULL;
  smartlist_t *exclude_nodes = NULL;
  int n_primary_guards = 3;
  int dir = 0;

  guard_selection = algo_choose_entry_guard_start(
          used_guards,
          NULL, NULL,
          exclude_nodes,
          n_primary_guards,
          dir);
  (void) arg;

  tt_int_op(guard_selection->state, OP_EQ, STATE_PRIMARY_GUARDS);
  guard_selection->previous_state = STATE_TRY_DYSTOPIC;
  algo_choose_entry_guard_next(guard_selection);
  tt_int_op(guard_selection->state, OP_EQ, STATE_TRY_DYSTOPIC);

 done:
  tor_free(guard_selection);
}



struct testcase_t entrynodes_new_tests[] = {
  { "state_machine_init",
    test_STATE_PRIMARY_GUARD_is_initial_state,
    0, NULL, NULL },
  { "state_machine_transfer",
    test_state_machine_should_use_new_state_as_current_state,
    0, NULL, NULL },
  { "state_machine_transition",
    test_PRIMARY_GUARDS_transitions_to_TRY_UTOPIC_when_theres_not_previous_state,
    0, NULL, NULL },
  { "state_machine_primary",
    test_state_machine_should_return_primary_guard_by_order,
    0, NULL, NULL },
  { "state_machine_next",
    test_PRIMARY_GUARDS_transitions_to_previous_state_when_theres_one,
    0, NULL, NULL },
  END_OF_TESTCASES
};
