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

static void transition_to_previous_state_or_try_utopic(guard_selection_t *guard_selection) {
	if(guard_selection->previous_state != 0) {
		transition_to(guard_selection, guard_selection->previous_state);
	} else {
		transition_to(guard_selection, STATE_TRY_UTOPIC);
	}
}

MOCK_IMPL(entry_guard_t *,
algo_choose_entry_guard_next,(guard_selection_t *state))
{
    switch(state->state){
        case STATE_PRIMARY_GUARDS:
            SMARTLIST_FOREACH_BEGIN(state->primary_guards, entry_guard_t *, e) {
                if (!e->unreachable_since) {
                    return e;
                }
            } SMARTLIST_FOREACH_END(e);

						transition_to_previous_state_or_try_utopic(state);
            break;
        case STATE_TRY_UTOPIC:
						//try to get something
            break;
        case STATE_TRY_DYSTOPIC:
						//try to get something
            return NULL;
    }

		return NULL;
}

guard_selection_t *algo_choose_entry_guard_start(
        smartlist_t *used_guards,
        smartlist_t *sampled_utopic,
        smartlist_t *sampled_dystopic,
        smartlist_t *exclude_nodes,
        int n_primary_guards,
        int dir)
{
    guard_selection_t *guard_selection = tor_malloc_zero(sizeof(guard_selection_t));
    guard_selection->state = STATE_PRIMARY_GUARDS;
    guard_selection->primary_guards = smartlist_new();

		//XXX fill remaining sets from sampled

    return guard_selection;
}

void transition_to(guard_selection_t *guard_selection, const unsigned int new_state)
{
    guard_selection->state = new_state;
}

