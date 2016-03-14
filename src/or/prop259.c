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

static entry_guard_t*
state_PRIMARY_GUARDS_next(guard_selection_t *guard_selection) {
		SMARTLIST_FOREACH_BEGIN(guard_selection->primary_guards, entry_guard_t *, e) {
				if (!e->unreachable_since) {
						return e;
				}
		} SMARTLIST_FOREACH_END(e);

		transition_to_previous_state_or_try_utopic(guard_selection);

		return NULL;
}

static const node_t* guard_to_node(const entry_guard_t *guard) {
		return node_get_by_id(guard->identity);
}

static entry_guard_t* node_to_guard(const node_t *node) {
		return entry_guard_get_by_id_digest(node->identity);
}

static void smartlist_remove_keeporder(smartlist_t *sl, const void *e) {
		int pos = smartlist_pos(sl, e);
		smartlist_del_keeporder(sl, pos);
}

STATIC entry_guard_t* next_by_bandwidth(smartlist_t *guards) {
		entry_guard_t *guard = NULL;
		smartlist_t *nodes = smartlist_new();

		SMARTLIST_FOREACH_BEGIN(guards, entry_guard_t *, e) {
			const node_t *node = guard_to_node(e);
			if(!node){
					continue; // not listed
			}

			smartlist_add(nodes, (void *)node);
		} SMARTLIST_FOREACH_END(e);

		const node_t *node = node_sl_choose_by_bandwidth(nodes, WEIGHT_FOR_GUARD);
		if(!node){
				goto done;
		}

		guard = node_to_guard(node);
		tor_assert(guard);
		smartlist_remove_keeporder(guards, guard);

done:
		tor_free(nodes);
		return guard;
}

static entry_guard_t*
each_used_guard_not_in_primary_guards(guard_selection_t *guard_selection) {
		SMARTLIST_FOREACH_BEGIN(guard_selection->used_guards, entry_guard_t *, e) {
				if(smartlist_contains(guard_selection->primary_guards, e)){
						continue;
				}

				if (!e->unreachable_since && !e->bad_since) {
						return e;
				}
		} SMARTLIST_FOREACH_END(e);

		return NULL;
}

static entry_guard_t*
each_remaining_utopic_by_bandwidth(guard_selection_t* guard_selection){
		entry_guard_t *guard = NULL;
		smartlist_t *remaining = smartlist_new();
		smartlist_add_all(remaining, guard_selection->remaining_utopic_guards);

		while(smartlist_len(remaining) > 0) {
				entry_guard_t *g = next_by_bandwidth(remaining);
				if(!g){
						break;
				}

				if (!g->unreachable_since) {
						guard = g;
						break;
				}

				smartlist_remove_keeporder(guard_selection->remaining_utopic_guards, g);
		}

		tor_free(remaining);
		return guard;
}

static entry_guard_t*
state_TRY_UTOPIC_next(guard_selection_t *guard_selection) {
		entry_guard_t *guard = each_used_guard_not_in_primary_guards(guard_selection);
		if(guard){
				return guard;
		}

		guard = each_remaining_utopic_by_bandwidth(guard_selection);
		if(guard){
				return guard;
		}

		transition_to(guard_selection, STATE_TRY_DYSTOPIC);

		return NULL;
}

MOCK_IMPL(entry_guard_t *,
algo_choose_entry_guard_next,(guard_selection_t *guard_selection))
{
		switch(guard_selection->state){
		case STATE_PRIMARY_GUARDS:
				return state_PRIMARY_GUARDS_next(guard_selection);
		case STATE_TRY_UTOPIC:
				return state_TRY_UTOPIC_next(guard_selection);
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

void algo_on_new_consensus(guard_selection_t *guard_selection)
{
    SMARTLIST_FOREACH_BEGIN(guard_selection->primary_guards, entry_guard_t *, e) {
        if (e->bad_since) {
            SMARTLIST_DEL_CURRENT(guard_selection->primary_guards, e);
        }
    } SMARTLIST_FOREACH_END(e);

    while(smartlist_len(guard_selection->primary_guards) < 3) {
         smartlist_add(guard_selection->primary_guards, next_primary_guard(guard_selection));
    }
}

entry_guard_t *next_primary_guard(guard_selection_t *guard_selection)
{
    SMARTLIST_FOREACH_BEGIN(guard_selection->used_guards, entry_guard_t *, e) {
        if (!smartlist_contains(guard_selection->primary_guards, e)){
            return e;
        }
    } SMARTLIST_FOREACH_END(e);
    return NULL;//return NEXT_BY_BANDWIDTH(REMAINING_UTOPIC_GUARDS);
}
