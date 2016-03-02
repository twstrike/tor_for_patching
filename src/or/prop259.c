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

MOCK_IMPL(const node_t *,
get_next_entry_guard,(guard_state_t *state))
{
    node_t *entry = tor_malloc_zero(sizeof(node_t));
    if(reach_treshould(state)){
        switch(state->state){
            case STATE_PRIMARY:
                transfer_to(state,STATE_UTOPIC);
                break;
            case STATE_UTOPIC:
                transfer_to(state,STATE_DYSTOPIC);
                break;
            case STATE_DYSTOPIC:
                transfer_to(state,STATE_RETRY);
                break;
            case STATE_RETRY:
                state = init_guard_state();
                break;
        }
        return get_next_entry_guard(state);
    }
    return entry;
}

guard_state_t *init_guard_state(void)
{
    guard_state_t *guard_state = tor_malloc_zero(sizeof(guard_state_t));
    guard_state->state = STATE_PRIMARY;
    return guard_state;
}

guard_state_t *transfer_to(guard_state_t *guard_state,const unsigned int new_state)
{
    guard_state->state = new_state;
    return guard_state;
}

MOCK_IMPL(int,
reach_treshould,(guard_state_t *state))
{
    return 0;
}
