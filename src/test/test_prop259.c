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

  (void) arg;

  guard_state_t *guard_state = tor_malloc_zero(sizeof(guard_state_t));
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
  tt_str_op(guard_state->state, OP_EQ, "PirmaryState");

 done:
  tor_free(guard_state);
}


struct testcase_t entrynodes_new_tests[] = {
  { "state_machine",
    test_state_machine_should_get_next_guard,
    0, NULL, NULL },
  { "state_machine_init",
    test_state_machine_should_use_PrimaryState,
    0, NULL, NULL },
  END_OF_TESTCASES
};
