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
 * get_next_entry_guard() test with state machine.
 *
 */

static void
test_state_machine_should_get_next_guard(void *arg)
{
  const node_t *next_guard = NULL;
  guard_state_t *guard_state = NULL;

  (void) arg;

  guard_state = init_guard_state();
  next_guard = get_next_entry_guard(guard_state);
  tt_assert(next_guard);

 done:
  tor_free(guard_state);
}

static void
test_state_machine_should_use_PrimaryState(void *arg)
{
  guard_state_t *guard_state = NULL;

  (void) arg;

  guard_state = init_guard_state();
  tt_int_op(guard_state->state, OP_EQ, STATE_PRIMARY_GUARDS);

 done:
  tor_free(guard_state);
}

static void
test_state_machine_should_use_new_state_as_current_state(void *arg)
{
  guard_state_t *guard_state = NULL;

  (void) arg;

  guard_state = init_guard_state();
  tt_int_op(guard_state->state, OP_EQ, STATE_PRIMARY_GUARDS);
  guard_state = transfer_to(guard_state, STATE_TRY_UTOPIC);
  tt_int_op(guard_state->state, OP_EQ, STATE_TRY_UTOPIC);

 done:
  tor_free(guard_state);
}

int mock_bad_reach_treshould(guard_state_t *state)
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
  const node_t *next_guard = NULL;
  guard_state_t *guard_state = NULL;

  (void) arg;

  MOCK(reach_treshould, mock_bad_reach_treshould);
  guard_state = init_guard_state();
  tt_int_op(guard_state->state, OP_EQ, STATE_PRIMARY_GUARDS);
  next_guard = get_next_entry_guard(guard_state);
  tt_int_op(guard_state->state, OP_EQ, STATE_TRY_DYSTOPIC);

 done:
  UNMOCK(reach_treshould);
  tor_free(guard_state);
}


struct testcase_t entrynodes_new_tests[] = {
  { "state_machine_next",
    test_state_machine_should_get_next_guard,
    0, NULL, NULL },
  { "state_machine_init",
    test_state_machine_should_use_PrimaryState,
    0, NULL, NULL },
  { "state_machine_transfer",
    test_state_machine_should_use_new_state_as_current_state,
    0, NULL, NULL },
  { "state_machine_failover",
    test_state_machine_should_fail_over_when_next_entry_guard_null,
    0, NULL, NULL },
  END_OF_TESTCASES
};
