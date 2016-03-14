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

MOCK_IMPL(entry_guard_t *,
algo_choose_entry_guard_next,(guard_state_t *state))
{
    switch(state->state){
        case STATE_PRIMARY_GUARDS:
            if (check_treshould(state)){
                transfer_to(state,STATE_TRY_UTOPIC);
            }
            SMARTLIST_FOREACH_BEGIN(state->context->primary_guards, entry_guard_t *, e) {
                if (!e->unreachable_since) {
                    return e;
                }
            } SMARTLIST_FOREACH_END(e);
            break;
        case STATE_TRY_UTOPIC:
            if (check_treshould(state)){
                transfer_to(state,STATE_TRY_DYSTOPIC);
            }
            break;
        case STATE_TRY_DYSTOPIC:
            if (check_treshould(state)){
                transfer_to(state,STATE_PRIMARY_GUARDS);
            }
            return NULL;
    }
    return algo_choose_entry_guard_next(state);
}

guard_state_t *algo_choose_entry_guard_start(
        smartlist_t *used_guards,
        smartlist_t *exclude_nodes,
        int n_primary_guards,
        int dir)
{
    guard_state_t *guard_state = tor_malloc_zero(sizeof(guard_state_t));
    guard_state->state = STATE_PRIMARY_GUARDS;
    guard_state->context = tor_malloc_zero(sizeof(guard_context_t));
    guard_state->context->primary_guards = smartlist_new();
    return guard_state;
}

guard_state_t *transfer_to(guard_state_t *guard_state,const unsigned int new_state)
{
    guard_state->state = new_state;
    return guard_state;
}

MOCK_IMPL(int,
check_treshould,(guard_state_t *state))
{
    return 0;
}
