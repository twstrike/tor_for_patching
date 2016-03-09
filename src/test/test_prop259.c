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
test_state_machine_should_use_PrimaryState(void *arg)
{
  guard_state_t *guard_state = NULL;
  smartlist_t *used_guards = smartlist_new();
  smartlist_t *exclude_nodes = smartlist_new();
  int n_primary_guards = 3;
  int dir = 0;

  (void) arg;
  guard_state = algo_choose_entry_guard_start(
          used_guards,
          exclude_nodes,
          n_primary_guards,
          dir);
  tt_int_op(guard_state->state, OP_EQ, STATE_PRIMARY_GUARDS);

 done:
  tor_free(guard_state);
}

static void
test_state_machine_should_use_new_state_as_current_state(void *arg)
{
  guard_state_t *guard_state = NULL;
  smartlist_t *used_guards = smartlist_new();
  smartlist_t *exclude_nodes = smartlist_new();
  int n_primary_guards = 3;
  int dir = 0;

  guard_state = algo_choose_entry_guard_start(
          used_guards,
          exclude_nodes,
          n_primary_guards,
          dir);
  (void) arg;

  tt_int_op(guard_state->state, OP_EQ, STATE_PRIMARY_GUARDS);
  guard_state = transfer_to(guard_state, STATE_TRY_UTOPIC);
  tt_int_op(guard_state->state, OP_EQ, STATE_TRY_UTOPIC);

 done:
  tor_free(guard_state);
}

int mock_bad_check_treshould(guard_state_t *state)
{
    switch(state->state){
        case STATE_PRIMARY_GUARDS:
            return 1;
        case STATE_TRY_UTOPIC:
            return 1;
        case STATE_TRY_DYSTOPIC:
            return 0;
    }
    return 1;
}

static void
test_state_machine_should_fail_over_when_next_entry_guard_null(void *arg)
{
  guard_state_t *guard_state = NULL;
  smartlist_t *used_guards = smartlist_new();
  smartlist_t *exclude_nodes = smartlist_new();
  int n_primary_guards = 3;
  int dir = 0;

  guard_state = algo_choose_entry_guard_start(
          used_guards,
          exclude_nodes,
          n_primary_guards,
          dir);
  (void) arg;

  MOCK(check_treshould, mock_bad_check_treshould);
  tt_int_op(guard_state->state, OP_EQ, STATE_PRIMARY_GUARDS);
  algo_choose_entry_guard_next(guard_state);
  tt_int_op(guard_state->state, OP_EQ, STATE_TRY_DYSTOPIC);

 done:
  UNMOCK(check_treshould);
  tor_free(guard_state);
}

static void
test_state_machine_should_return_primary_guard_by_order(void *arg)
{
  guard_state_t *guard_state = NULL;
  smartlist_t *used_guards = smartlist_new();
  smartlist_t *exclude_nodes = smartlist_new();
  int n_primary_guards = 3;
  int dir = 0;

  guard_state = algo_choose_entry_guard_start(
          used_guards,
          exclude_nodes,
          n_primary_guards,
          dir);
  (void) arg;

  entry_guard_t *entry1 = tor_malloc_zero(sizeof(entry_guard_t));
  entry_guard_t *entry2 = tor_malloc_zero(sizeof(entry_guard_t));
  smartlist_add(guard_state->context->primary_guards, entry1);
  smartlist_add(guard_state->context->primary_guards, entry2);

  entry_guard_t *guard1 = algo_choose_entry_guard_next(guard_state);
  tt_ptr_op(entry1, OP_EQ, guard1);
  entry_guard_t *guard2 = algo_choose_entry_guard_next(guard_state);
  tt_ptr_op(entry1, OP_EQ, guard2);
  entry1->unreachable = 1;
  entry_guard_t *guard3 = algo_choose_entry_guard_next(guard_state);
  tt_ptr_op(entry2, OP_EQ, guard3);
  entry1->unreachable = 0;
  entry_guard_t *guard4 = algo_choose_entry_guard_next(guard_state);
  tt_ptr_op(entry1, OP_EQ, guard4);

 done:
  UNMOCK(check_treshould);
  tor_free(guard_state);
}


struct testcase_t entrynodes_new_tests[] = {
  { "state_machine_init",
    test_state_machine_should_use_PrimaryState,
    0, NULL, NULL },
  { "state_machine_transfer",
    test_state_machine_should_use_new_state_as_current_state,
    0, NULL, NULL },
  { "state_machine_failover",
    test_state_machine_should_fail_over_when_next_entry_guard_null,
    0, NULL, NULL },
  { "state_machine_primary",
    test_state_machine_should_return_primary_guard_by_order,
    0, NULL, NULL },
  END_OF_TESTCASES
};
