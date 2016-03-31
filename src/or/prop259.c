/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define PROP259_PRIVATE

//XXX Think about it from a modularity perspective and reduce
//the number of dependencies.
#include "prop259.h"
#include "nodelist.h"
#include "routerlist.h"
#include "config.h"
#include "circuitbuild.h"
#include "networkstatus.h"
#include "policies.h"
#include "router.h"
#include "confparse.h"
#include "statefile.h"

//XXX Find the appropriate place for this global state

/** Entry guard selection algorithm **/
static const node_t *entry_node = NULL;
static guard_selection_t *entry_guard_selection = NULL;

/** Related to guard selection algorithm. **/
//XXX Add proper documentation
static smartlist_t *used_guards = NULL;
static smartlist_t *sampled_utopic_guards = NULL;
static smartlist_t *sampled_dystopic_guards = NULL;

static int used_guards_dirty = 0;

//XXX review if this is the right way of doing this
static const node_t*
guard_to_node(const entry_guard_t *guard)
{
    return node_get_by_id(guard->identity);
}

//XXX review if this is the right way of doing this
static entry_guard_t*
node_to_guard(const node_t *node)
{
    return entry_guard_get_by_id_digest(node->identity);
}

static int
is_dystopic_port(uint16_t port)
{
    if (port == 80)
        return 1;

    if (port == 443)
        return 1;

    return 0;
}

static int
is_dystopic(node_t *node)
{
    //From router_choose_random_node()
    int pref_addr = 1;
    if (firewall_is_fascist_or())
        return fascist_firewall_allows_node(node, FIREWALL_OR_CONNECTION,
                                            pref_addr);

    //XXX there might be false positive if we dont support IPV6
    //but the guard only listen to a dystopic port in IPV6

    if (node->ri) {
        if (is_dystopic_port(node->ri->or_port))
            return 1;

        if (is_dystopic_port(node->ri->ipv6_orport))
            return 1;
    } else if (node->rs) {
        if (is_dystopic_port(node->rs->or_port))
            return 1;

        if (is_dystopic_port(node->rs->ipv6_orport))
            return 1;
    } else if (node->md) {
        if (is_dystopic_port(node->md->ipv6_orport))
            return 1;
    }

    return 0;
}

static int
is_live(const entry_guard_t *guard)
{
    //XXX using entry_is_live() would introduce the current progressive retry
    //behavior. I suspect we should evaluate using this at some point.
    if (guard->unreachable_since == 0)
        return 1;

    return 0;
}

MOCK_IMPL(STATIC int,
is_bad,(const entry_guard_t *guard))
{
    return (node_get_by_id(guard->identity) == NULL);
}

static int
should_ignore(const entry_guard_t *guard, int for_directory)
{
    // Dont use an entry guard when we need a directory guard
    const node_t* node = guard_to_node(guard);
    if (for_directory && !node_is_dir(node))
       return 1;

    //XXX should ignore the exit node
    // const node_t *chosen_exit =
    //state?build_state_get_exit_node(state) : NULL;
    //if (guard_to_node(guard) == chosen)
    //  return 1;

    //XXX this is how need_uptime and need_capacity fits
    //if (!node_is_unreliable(node, need_uptime, need_capacity, 0))
    //{
    //  return 0;
    //}

    return 0;
}

static int
should_try(const entry_guard_t* guard)
{
    if (guard->can_retry)
        return 1;

    return (is_live(guard) && !is_bad(guard));
}

static int
is_eligible(const entry_guard_t* guard, int for_directory)
{
    return should_try(guard) &&
        !should_ignore(guard, for_directory);
}

static void
mark_for_retry(const smartlist_t *guards)
{
    SMARTLIST_FOREACH_BEGIN(guards, entry_guard_t *, e) {
        e->can_retry = 1;
    } SMARTLIST_FOREACH_END(e);
}

static void
retry_primary_guards(guard_selection_t *guard_selection)
{
    mark_for_retry(guard_selection->primary_guards);
    transition_to(guard_selection, STATE_PRIMARY_GUARDS);
}

static void
mark_remaining_used_for_retry(guard_selection_t *guard_selection)
{
    log_warn(LD_CIRC, "Will retry remaining used guards.");

    SMARTLIST_FOREACH_BEGIN(guard_selection->used_guards, entry_guard_t *, e) {
        if (smartlist_contains(guard_selection->primary_guards, e)) {
            continue;
        }

        e->can_retry = 1;
    } SMARTLIST_FOREACH_END(e);
}

static void
transition_to_previous_state_or_try_utopic(guard_selection_t *guard_selection)
{
    if (guard_selection->previous_state != STATE_INVALID) {
        log_warn(LD_CIRC, "Going back to previous state");
        transition_to(guard_selection, guard_selection->previous_state);
    } else {
        mark_remaining_used_for_retry(guard_selection);
        transition_to(guard_selection, STATE_TRY_UTOPIC);
    }
}

static entry_guard_t*
state_PRIMARY_GUARDS_next(guard_selection_t *guard_selection)
{
    char buf[HEX_DIGEST_LEN+1];
    smartlist_t *guards = guard_selection->primary_guards;

    log_warn(LD_CIRC, "There are %d candidates", smartlist_len(guards));

    SMARTLIST_FOREACH_BEGIN(guards, entry_guard_t *, e) {
        base16_encode(buf, sizeof(buf), e->identity, DIGEST_LEN);
        log_warn(LD_CIRC, "Evaluating '%s' (%s)", e->nickname, buf);

        if (is_eligible(e, guard_selection->for_directory))
            return e;
    } SMARTLIST_FOREACH_END(e);

    log_warn(LD_CIRC, "No PRIMARY_GUARDS is live.");

    transition_to_previous_state_or_try_utopic(guard_selection);
    return NULL;
}

STATIC void
transition_to(guard_selection_t *guard_selection,
              guard_selection_state_t state)
{
    switch (state) {
    case STATE_INVALID:
        log_warn(LD_CIRC, "Transitioned to INVALID_STATE.");
        return;
    case STATE_PRIMARY_GUARDS:
        log_warn(LD_CIRC, "Transitioned to STATE_PRIMARY_GUARDS.");
        break;
    case STATE_TRY_UTOPIC:
        log_warn(LD_CIRC, "Transitioned to STATE_TRY_UTOPIC.");
        break;
    case STATE_TRY_DYSTOPIC:
        log_warn(LD_CIRC, "Transitioned to STATE_TRY_DYSTOPIC.");
        break;
    }

    guard_selection->state = state;
}

static void
save_state_and_retry_primary_guards(guard_selection_t *guard_selection)
{
    guard_selection->previous_state = guard_selection->state;
    retry_primary_guards(guard_selection);
}

STATIC const node_t*
next_node_by_bandwidth(smartlist_t *nodes)
{
    const node_t *node = node_sl_choose_by_bandwidth(nodes, WEIGHT_FOR_GUARD);
    if (node)
        smartlist_remove(nodes, node); //otherwise it may return duplicates

    return node;
}

static entry_guard_t*
each_used_guard_not_in_primary_guards(guard_selection_t *guard_selection)
{
    char buf[HEX_DIGEST_LEN+1];

    SMARTLIST_FOREACH_BEGIN(guard_selection->used_guards, entry_guard_t *, e) {
        if (smartlist_contains(guard_selection->primary_guards, e)) {
            continue;
        }

        base16_encode(buf, sizeof(buf), e->identity, DIGEST_LEN);
        log_warn(LD_CIRC, "Evaluating '%s' (%s)", e->nickname, buf);

        if (is_eligible(e, guard_selection->for_directory))
            return e;
    } SMARTLIST_FOREACH_END(e);

    return NULL;
}

static entry_guard_t*
each_remaining_by_bandwidth(smartlist_t *nodes, int for_directory)
{
    entry_guard_t *guard = NULL;
    smartlist_t *remaining = smartlist_new();

    char buf[HEX_DIGEST_LEN+1];
    log_warn(LD_CIRC, "There are %d candidates", smartlist_len(nodes));

    smartlist_add_all(remaining, nodes);
    while (smartlist_len(remaining) > 0) {
        const node_t *node = next_node_by_bandwidth(remaining);
        if (!node) {
            break;
        }

        //XXX avoid the global entry_guards but still create a entry_guard_t
        //XXX replace by entry_guard_new and only add to the global on END()
        add_an_entry_guard(node, 0, 0, 0, for_directory);
        entry_guard_t *g = node_to_guard(node);
        tor_assert(g);

        base16_encode(buf, sizeof(buf), g->identity, DIGEST_LEN);
        log_warn(LD_CIRC, "Evaluating '%s' (%s)", g->nickname, buf);

        if (!is_live(g)) {
            log_warn(LD_CIRC, "  Removing (not live).");
            smartlist_remove(nodes, node);
            continue;
        }

        if (!is_eligible(g, for_directory)) {
            log_warn(LD_CIRC, "  Ignoring (not eligible).");
            continue;
        }

        guard = g;
        break;
    }

    tor_free(remaining);
    return guard;
}

static entry_guard_t*
each_remaining_utopic_by_bandwidth(guard_selection_t* guard_selection)
{
    return each_remaining_by_bandwidth(
                   guard_selection->remaining_utopic_guards,
                   guard_selection->for_directory);
}

static entry_guard_t*
each_remaining_dystopic_by_bandwidth(guard_selection_t* guard_selection)
{
    return each_remaining_by_bandwidth(
                   guard_selection->remaining_dystopic_guards,
                   guard_selection->for_directory);
}

static entry_guard_t*
state_TRY_UTOPIC_next(guard_selection_t *guard_selection)
{
    log_warn(LD_CIRC, "Will try USED_GUARDS not in PRIMARY_GUARDS.");

    entry_guard_t *guard = each_used_guard_not_in_primary_guards(
        guard_selection);

    if (guard) {
        return guard;
    }

    log_warn(LD_CIRC, "Will try REMAINING_UTOPIC_GUARDS.");

    guard = each_remaining_utopic_by_bandwidth(guard_selection);
    if (guard) {
        return guard;
    }

    transition_to(guard_selection, STATE_TRY_DYSTOPIC);

    return NULL;
}

static entry_guard_t*
state_TRY_DYSTOPIC_next(guard_selection_t *guard_selection)
{
    log_warn(LD_CIRC, "Will try REMAINING_DYSTOPIC_GUARDS.");

    entry_guard_t *guard = each_remaining_dystopic_by_bandwidth(
        guard_selection);

    if (guard) {
        return guard;
    }

    retry_primary_guards(guard_selection);
    return NULL;
}

static int
has_any_been_tried_before(const smartlist_t *guards, time_t time)
{
    SMARTLIST_FOREACH_BEGIN(guards, entry_guard_t *, e) {
        //last_attempted is probably better because it is updated
        //on subsequent failures. But keep in mind it is only updated
        //if we have made contact before.
        if (e->last_attempted && e->last_attempted <= time) {
            return 1;
        }

    } SMARTLIST_FOREACH_END(e);

    return 0;
}

//XXX Add tests
static void
check_primary_guards_retry_interval(guard_selection_t *guard_selection,
                                    const or_options_t *options, time_t now)
{
    if (guard_selection->state == STATE_PRIMARY_GUARDS)
        return;

    int retry_interval = options->PrimaryGuardsRetryInterval ?
        options->PrimaryGuardsRetryInterval : 3;
    time_t primary_retry_time = now - retry_interval * 60;

    const smartlist_t *guards = guard_selection->primary_guards;
    if (has_any_been_tried_before(guards, primary_retry_time)) {
        log_warn(LD_CIRC, "Some PRIMARY_GUARDS have been tried more than %d "
            "minutes ago. Will retry PRIMARY_GUARDS.", retry_interval);

        save_state_and_retry_primary_guards(guard_selection);
    }
}

STATIC entry_guard_t *
choose_entry_guard_algo_next(guard_selection_t *guard_selection,
                              const or_options_t *options, time_t now)
{
    check_primary_guards_retry_interval(guard_selection, options, now);

    switch (guard_selection->state) {
    case STATE_INVALID:
        tor_assert(NULL); //XXX how to panic?
        return NULL;
    case STATE_PRIMARY_GUARDS:
        return state_PRIMARY_GUARDS_next(guard_selection);
    case STATE_TRY_UTOPIC:
        return state_TRY_UTOPIC_next(guard_selection);
    case STATE_TRY_DYSTOPIC:
        return state_TRY_DYSTOPIC_next(guard_selection);
    }

    return NULL;
}

STATIC void
fill_in_remaining_utopic(guard_selection_t *guard_selection,
                         const smartlist_t *sampled_utopic)
{
    guard_selection->remaining_utopic_guards = smartlist_new();

    SMARTLIST_FOREACH_BEGIN(sampled_utopic, node_t *, node) {
        if (!smartlist_contains(guard_selection->used_guards, node)) {
            smartlist_add(guard_selection->remaining_utopic_guards, node);
        }
    } SMARTLIST_FOREACH_END(node);
}

STATIC void
fill_in_remaining_dystopic(guard_selection_t *guard_selection,
                           const smartlist_t *sampled_dystopic)
{
    guard_selection->remaining_dystopic_guards = smartlist_new();

    SMARTLIST_FOREACH_BEGIN(sampled_dystopic, node_t *, node) {
        if (!smartlist_contains(guard_selection->used_guards, node)) {
            smartlist_add(guard_selection->remaining_dystopic_guards, node);
        }
    } SMARTLIST_FOREACH_END(node);
}

STATIC void
fill_in_primary_guards(guard_selection_t *guard_selection)
{
    guard_selection->primary_guards = smartlist_new();

    int num_guards = guard_selection->num_primary_guards;
    smartlist_t *primary = guard_selection->primary_guards;
    while (smartlist_len(primary) < num_guards) {
        entry_guard_t *guard = next_primary_guard(guard_selection);
        if (!guard)
            break;

        smartlist_add(primary, guard);
    }
}

STATIC void
guard_selection_free(guard_selection_t *guard_selection)
{
    smartlist_free(guard_selection->primary_guards);
    smartlist_free(guard_selection->remaining_utopic_guards);
    smartlist_free(guard_selection->remaining_dystopic_guards);
}

STATIC guard_selection_t*
choose_entry_guard_algo_start(
    smartlist_t *used_guards,
    const smartlist_t *sampled_utopic,
    const smartlist_t *sampled_dystopic,
    smartlist_t *exclude_nodes,
    int n_primary_guards,
    int for_directory)
{
    //XXX fill remaining sets from sampled
    (void) exclude_nodes;

    guard_selection_t *guard_selection = tor_malloc_zero(
        sizeof(guard_selection_t));
    guard_selection->for_directory = for_directory;
    guard_selection->state = STATE_PRIMARY_GUARDS;
    guard_selection->used_guards = used_guards;
    guard_selection->num_primary_guards = n_primary_guards;

    fill_in_remaining_utopic(guard_selection, sampled_utopic);
    fill_in_remaining_dystopic(guard_selection, sampled_dystopic);
    fill_in_primary_guards(guard_selection);

    log_warn(LD_CIRC, "Initializing guard_selection:\n"
        "- used: %p,\n"
        "- sampled_utopic: %p,\n"
        "- sampled_dystopic: %p,\n"
        "- exclude_nodes: %p,\n"
        "- n_primary_guards: %d,\n"
        "- for_directory: %d\n",
        used_guards, sampled_utopic, sampled_dystopic, exclude_nodes,
        n_primary_guards, for_directory);

    return guard_selection;
}

STATIC void
choose_entry_guard_algo_new_consensus(guard_selection_t *guard_selection)
{
    int num_guards = guard_selection->num_primary_guards;
    smartlist_t *guards = guard_selection->primary_guards;

    while (smartlist_len(nonbad_guards(guards)) < num_guards) {
        entry_guard_t *guard = next_primary_guard(guard_selection);
        if (guard != NULL) {
            if (!smartlist_contains(guards, guard)) {
                smartlist_add(guards, guard);
            }
        } else {
            break;
        }
    }
}

STATIC smartlist_t*
nonbad_guards(smartlist_t *guards)
{
    smartlist_t *nonbad_guards = smartlist_new();
    SMARTLIST_FOREACH_BEGIN(guards, entry_guard_t *, e) {
        if (!is_bad(e))
            smartlist_add(nonbad_guards, e);
    } SMARTLIST_FOREACH_END(e);

    return nonbad_guards;
}

static void
add_nodes_to(smartlist_t *nodes, const smartlist_t *guards)
{
    SMARTLIST_FOREACH_BEGIN(guards, entry_guard_t *, e) {
        const node_t *node = guard_to_node(e);
        if (node && !smartlist_contains(nodes, node))
            smartlist_add(nodes, (node_t*) node);
    } SMARTLIST_FOREACH_END(e);
}

static void
remaining_guards_for_next_primary(guard_selection_t *guard_selection,
          smartlist_t *dest)
{
    smartlist_t *except = smartlist_new();
    add_nodes_to(except, guard_selection->used_guards);
    add_nodes_to(except, guard_selection->primary_guards);

    smartlist_add_all(dest, guard_selection->remaining_utopic_guards);
    smartlist_subtract(dest, except);
    smartlist_free(except);
}

STATIC entry_guard_t*
next_primary_guard(guard_selection_t *guard_selection)
{
    const smartlist_t *used = guard_selection->used_guards;
    const smartlist_t *primary = guard_selection->primary_guards;

    SMARTLIST_FOREACH_BEGIN(used, entry_guard_t *, e) {
        if (!smartlist_contains(primary, e) && !is_bad(e))
            return e;
    } SMARTLIST_FOREACH_END(e);

    //Need to normalize, otherwise subtract wont work
    smartlist_t *remaining = smartlist_new();
    remaining_guards_for_next_primary(guard_selection, remaining);
    const node_t *node = next_node_by_bandwidth(remaining);
    tor_free(remaining);

    if (!node)
      return NULL;

    smartlist_remove(guard_selection->remaining_utopic_guards, node);

    //XXX replace by entry_guard_new and only add to the global on END()
    add_an_entry_guard(node, 0, 0, 0, guard_selection->for_directory);
    entry_guard_t *g = node_to_guard(node);
    tor_assert(g);

    return g;
}

STATIC void
fill_in_node_sampled_set(smartlist_t *sample, const smartlist_t *set,
                         const int size)
{
    smartlist_t *remaining = smartlist_new();

    smartlist_add_all(remaining, set);
    while (smartlist_len(sample) < size && smartlist_len(remaining) > 0) {
        const node_t *node = next_node_by_bandwidth(remaining);
        if (!node)
            break;

        smartlist_add(sample, (node_t*) node);
    }
    smartlist_free(remaining);
}

static void
fill_in_sampled_sets(const smartlist_t *utopic_nodes,
                     const smartlist_t *dystopic_nodes)
{
    //XXX Extract a configuration from this
    const double sample_set_threshold = 0.005;

    //XXX persist sampled sets in state file

    if (!sampled_utopic_guards)
        sampled_utopic_guards = smartlist_new();

    if (!sampled_dystopic_guards)
        sampled_dystopic_guards = smartlist_new();

    fill_in_node_sampled_set(sampled_utopic_guards, utopic_nodes,
        sample_set_threshold * smartlist_len(utopic_nodes));

    log_warn(LD_CIRC, "We sampled %d from %d utopic guards",
        smartlist_len(sampled_utopic_guards), smartlist_len(utopic_nodes));

    fill_in_node_sampled_set(sampled_dystopic_guards, dystopic_nodes,
        sample_set_threshold * smartlist_len(dystopic_nodes));

    log_warn(LD_CIRC, "We sampled %d from %d dystopic guards",
        smartlist_len(sampled_dystopic_guards), smartlist_len(dystopic_nodes));
}

/** How long will we let a change in our guard nodes stay un-saved
 * when we are trying to avoid disk writes? */
#define SLOW_GUARD_STATE_FLUSH_TIME 600
/** How long will we let a change in our guard nodes stay un-saved
 * when we are not trying to avoid disk writes? */
#define FAST_GUARD_STATE_FLUSH_TIME 30

static void
used_guards_changed(void)
{
  time_t when;
  used_guards_dirty = 1;

  if (get_options()->AvoidDiskWrites)
    when = time(NULL) + SLOW_GUARD_STATE_FLUSH_TIME;
  else
    when = time(NULL) + FAST_GUARD_STATE_FLUSH_TIME;

  /* or_state_save() will call guard_selection_update_state(). */
  or_state_mark_dirty(get_or_state(), when);
}

//XXX Add tests
STATIC void
choose_entry_guard_algo_end(guard_selection_t *guard_selection,
                            const entry_guard_t *guard)
{
    log_warn(LD_CIRC, "Finishing guard selection algorithm");

    //XXX Save used_guards to state file instead of global variable
    if (!smartlist_contains(guard_selection->used_guards, guard)) {
        smartlist_add(guard_selection->used_guards, (entry_guard_t*) guard);
        used_guards_changed();
    }

    guard_selection_free(guard_selection);
}

STATIC int
used_guards_parse_state(const or_state_t *state, smartlist_t *used_guards,
                        char **msg)
{
    //XXX We should probably be backward compatible with EntryGuard
    //and call entry_guards_parse_state()

    entry_guard_t *node = NULL;
    config_line_t *line;
    smartlist_t *new_entry_guards = smartlist_new();
    time_t now = time(NULL);

    *msg = NULL;
    for (line = state->UsedGuards; line; line = line->next) {
        if (!strcasecmp(line->key, "UsedGuard")) {
            smartlist_t *args = smartlist_new();
            node = tor_malloc_zero(sizeof(entry_guard_t));
            /* all entry guards on disk have been contacted */
            node->made_contact = 1;
            smartlist_add(new_entry_guards, node);
            smartlist_split_string(args, line->value, " ",
                SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);

            /* Validates nickname and fingerprint */
            if (smartlist_len(args)<2) {
                *msg = tor_strdup("Unable to parse entry nodes: "
                    "Too few arguments to EntryGuard");
            } else if (!is_legal_nickname(smartlist_get(args,0))) {
                *msg = tor_strdup("Unable to parse entry nodes: "
                    "Bad nickname for EntryGuard");
            } else {
                char *nickname = smartlist_get(args, 0);
                char *digest = smartlist_get(args, 1);

                strlcpy(node->nickname, nickname, MAX_NICKNAME_LEN+1);
                if (base16_decode(node->identity, DIGEST_LEN, digest,
                    strlen(digest))<0) {
                    *msg = tor_strdup("Unable to parse entry nodes: "
                        "Bad hex digest for EntryGuard");
                }
            }

            /* Parses DirCache / NoDirCache */
            if (smartlist_len(args) >= 3) {
                const char *is_cache = smartlist_get(args, 2);
                if (!strcasecmp(is_cache, "DirCache")) {
                    node->is_dir_cache = 1;
                } else if (!strcasecmp(is_cache, "NoDirCache")) {
                    node->is_dir_cache = 0;
                } else {
                    log_warn(LD_CONFIG,
                        "Bogus third argument to EntryGuard line: %s",
                        escaped(is_cache));
                }
            }

            SMARTLIST_FOREACH(args, char*, cp, tor_free(cp));
            smartlist_free(args);

            /* Abort on error */
            if (*msg)
                break;

        } else if (!strcasecmp(line->key, "UsedGuardDownSince") ||
            !strcasecmp(line->key, "UsedGuardUnlistedSince")) {
            time_t when;
            time_t last_try = 0;

            if (!node) {
                *msg = tor_strdup("Unable to parse used guard: "
                    "UsedGuardDownSince/UnlistedSince without UsedGuard");
                break;
            }

            if (parse_iso_time_(line->value, &when, 0)<0) {
                *msg = tor_strdup("Unable to parse used guard: "
                    "Bad time in UsedGuardDownSince/UnlistedSince");
                break;
            }

            if (when > now) {
                /* It's a bad idea to believe info in the future: you can wind
                 * up with timeouts that aren't allowed to happen for years. */
                continue;
            }

            /* Parse optional last_attempt */
            if (strlen(line->value) >= ISO_TIME_LEN+ISO_TIME_LEN+1) {
                /* ignore failure */
                (void) parse_iso_time(line->value+ISO_TIME_LEN+1, &last_try);
            }

            if (!strcasecmp(line->key, "UsedGuardDownSince")) {
                node->unreachable_since = when;
                node->last_attempted = last_try;
            } else {
                node->bad_since = when;
            }
        } else {
            log_warn(LD_BUG, "Unexpected key %s", line->key);
        }
    }

    if (*msg || !used_guards) {
        SMARTLIST_FOREACH(new_entry_guards, entry_guard_t *, e,
            entry_guard_free(e));
        smartlist_free(new_entry_guards);
    } else {
        /* Free used guards and replace by guards in state, on success */
        SMARTLIST_FOREACH(used_guards, entry_guard_t *, e,
            entry_guard_free(e));
        smartlist_clear(used_guards);
        smartlist_add_all(used_guards, new_entry_guards);

        //XXX should we?
        //update_node_guard_status();
    }

    return *msg ? -1 : 0;
}

//XXX Add test
STATIC void
used_guards_update_state(or_state_t *state, smartlist_t *used_guards)
{
    config_line_t **next, *line;

    config_free_lines(state->UsedGuards);
    next = &state->UsedGuards;
    *next = NULL;

    SMARTLIST_FOREACH_BEGIN(used_guards, entry_guard_t *, e) {
        char dbuf[HEX_DIGEST_LEN+1];
        if (!e->made_contact)
            continue; /* don't write this one to disk */

        *next = line = tor_malloc_zero(sizeof(config_line_t));
        line->key = tor_strdup("UsedGuard");

        base16_encode(dbuf, sizeof(dbuf), e->identity, DIGEST_LEN);
        tor_asprintf(&line->value, "%s %s %sDirCache", e->nickname, dbuf,
            e->is_dir_cache ? "" : "No");

        next = &(line->next);
        if (e->unreachable_since) {
            *next = line = tor_malloc_zero(sizeof(config_line_t));
            line->key = tor_strdup("UsedGuardDownSince");
            line->value = tor_malloc(ISO_TIME_LEN+1+ISO_TIME_LEN+1);
            format_iso_time(line->value, e->unreachable_since);
            if (e->last_attempted) {
                line->value[ISO_TIME_LEN] = ' ';
                format_iso_time(line->value+ISO_TIME_LEN+1, e->last_attempted);
            }
            next = &(line->next);
        }

        if (e->bad_since) {
            *next = line = tor_malloc_zero(sizeof(config_line_t));
            line->key = tor_strdup("UsedGuardUnlistedSince");
            line->value = tor_malloc(ISO_TIME_LEN+1);
            format_iso_time(line->value, e->bad_since);
            next = &(line->next);
        }

    } SMARTLIST_FOREACH_END(e);
}

//These functions adapt our proposal to current tor code

// PUBLIC INTERFACE ----------------------------------------

int
choose_entry_guard_algo_should_continue(guard_selection_t *guard_selection,
          int succeeded, time_t now, int internet_likely_down_interval)
{
    if (!succeeded) {
        log_warn(LD_CIRC, "Did not succeeded.");
        return 1;
    }

    int should_continue = 0;
    time_t last_success = guard_selection->last_success;
    if (last_success &&
        now - last_success > internet_likely_down_interval * 60) {
        log_warn(LD_CIRC, "Discarding circuit after %d minutes without "
            "success. The network may have been down and now is up again,"
            "so we retry the used guards.", internet_likely_down_interval);

        retry_primary_guards(guard_selection);
        should_continue = 1;
    }

    guard_selection->last_success = now;
    return should_continue;
}

//XXX Add tests
void
entry_guard_selection_init(void)
{
#ifndef USE_PROP_259
    return; //do nothing
#endif

    if (!router_have_minimum_dir_info()) {
        log_warn(LD_CIRC, "Cant initialize without a consensus.");
        return;
    }

    if (entry_guard_selection)
        return;

    const or_options_t *options = get_options();
    const int for_directory = 0; //XXX how to get this at this moment?
    const int num_needed = decide_num_guards(options, for_directory);

    //XXX Is this the right place to ensure it is loaded from state file?
    if (!used_guards)
        guard_selection_parse_state(get_or_state(), 1, NULL);

    //XXX support excluded nodes.
    //options->ExcludeNodes is a routerset_t, not a list of guards.
    //XXX Look at entry_guards_set_from_config to see how it filters out
    //ExcludeNodes
    entry_guard_selection = choose_entry_guard_algo_start(
        used_guards, sampled_utopic_guards, sampled_dystopic_guards,
        NULL, //XXX should be options->ExcludeNodes,
        num_needed, for_directory);
}

//XXX Add tests
const node_t *
choose_random_entry_prop259(cpath_build_state_t *state, int for_directory,
    dirinfo_type_t dirinfo_type, int *n_options_out)
{
    //XXX This might not work. What guarantees we have that the previously
    //chosen guard meets all the constraints we have now. They can have
    //changed between last run and this run.
    //if entry_node exist we will use it, otherwise we will pick one using
    //next_algo
    if (entry_node) {
        log_warn(LD_CIRC, "Reuse %s as entry guard for this circuit.",
            node_describe(entry_node));
        return entry_node;
    }

    //We have received a consensus but not enough to build a circuit
    //same as !router_have_minimum_dir_info()
    if (!entry_guard_selection)
        return NULL;

    //XXX choose_good_entry_server() ignores:
    // - routers in the same family as the exit node
    // - routers in the same family of the guards you have chosen
    //Our proposal does not care.

    log_warn(LD_CIRC, "Using proposal 259 to choose entry guards.");

    const or_options_t *options = get_options();
    const node_t *node = NULL;
    const entry_guard_t* guard = NULL;
    time_t now = time(NULL);

    /* const node_t *chosen_exit = */
    /*     state ? build_state_get_exit_node(state) : NULL; */
    /* int need_uptime = state ? state->need_uptime : 0; */
    /* int need_capacity = state ? state->need_capacity : 0; */
    /* (void) chosen_exit; */
    (void) state;
    (void) dirinfo_type;
    /* (void) need_uptime; */
    /* (void) need_capacity; */

    if (n_options_out)
        *n_options_out = 0;

    //XXX see entry_guards_set_from_config(options);

    const int num_needed = decide_num_guards(options, for_directory);
    entry_guard_selection->for_directory = for_directory;
    entry_guard_selection->num_primary_guards = num_needed;

  retry:
    guard = choose_entry_guard_algo_next(entry_guard_selection, options, now);

    // This only exists because NEXT() can return NULL when transitioning
    // between states
    if (!guard)
        goto retry;

    // Guard is not in the consensus anymore. Not sure if this is possible
    node = guard_to_node(guard);
    tor_assert(node);

    log_warn(LD_CIRC, "Chose %s as entry guard for this circuit.",
        node_describe(node));

    //XXX check entry_guards_changed();

    //XXX What is n_options_out in our case?
    if (n_options_out)
        *n_options_out = 1;

    entry_node = node;

    return node;
}

//XXX We need something like entry_guards_compute_status()
//which should also calls used_guards_changed()

//XXX Add tests
void
entry_guards_update_profiles(const or_options_t *options)
{
#ifndef USE_PROP_259
    return; //do nothing
#endif

    //XXX remove
    (void) options;

    log_warn(LD_CIRC, "Received a new consensus");

    //We recreate the sample sets without restricting to directory
    //guards, because most of the entry guards will be directory in
    //the near ideal future.
    int for_directory = 0;
    smartlist_t *utopic = get_all_guards(for_directory);
    smartlist_t *dystopic = smartlist_new();

    SMARTLIST_FOREACH_BEGIN(utopic, node_t *, node) {
        if (is_dystopic(node))
            smartlist_add(dystopic, node);
    } SMARTLIST_FOREACH_END(node);

    //XXX The size of the utopic and dystopic sets may change, but we only
    //change the sampled sets when these sizes increase.
    fill_in_sampled_sets(utopic, dystopic);

    smartlist_free(utopic);
    smartlist_free(dystopic);

    //XXX Is this necessary?
    if (entry_guard_selection)
        choose_entry_guard_algo_new_consensus(entry_guard_selection);
}

int
guard_selection_register_connect_status(const entry_guard_t *guard,
                                        int succeeded, time_t now)
{
    int should_continue = 0;

#ifndef USE_PROP_259
    return should_continue;
#endif

    log_warn(LD_CIRC, "Guard %s has succeeded = %d.",
        node_describe(guard_to_node(guard)), succeeded);

    if (!entry_guard_selection) {
        log_warn(LD_CIRC, "We have no guard_selection algo."
            " Should not continue.");
        return should_continue;
    }

    //XXX add this to options?
    int internet_likely_down_interval = 5;

    should_continue = choose_entry_guard_algo_should_continue(
        entry_guard_selection, succeeded, now, internet_likely_down_interval);

    log_warn(LD_CIRC, "Should continue? %d", should_continue);

    if (!should_continue) {
        choose_entry_guard_algo_end(entry_guard_selection, guard);
        tor_free(entry_guard_selection);
    } else {
        entry_node = NULL;

        //XXX entry_guard_register_connect_status() is smarter and only calls
        //it when any guard has changed. We will get there.
        used_guards_changed();
    }

    return should_continue;
}

int
guard_selection_parse_state(const or_state_t *state, int set, char **msg)
{
#ifndef USE_PROP_259
    return 0;
#endif

    log_warn(LD_CIRC, "Will load used guards from state file.");

    if (!used_guards)
        used_guards = smartlist_new();

    smartlist_t *guards = set ? used_guards : NULL;
    return used_guards_parse_state(state, guards, msg);
}

void
guard_selection_update_state(or_state_t *state, const or_options_t *options)
{
#ifndef USE_PROP_259
    return;
#endif

    if (!used_guards_dirty)
        return;

    used_guards_update_state(state, used_guards);

    if (!options->AvoidDiskWrites)
        or_state_mark_dirty(state, 0);

    used_guards_dirty = 0;
}

