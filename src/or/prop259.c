/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define PROP259_PRIVATE

//XXX Remove the global entry_guards. To do so, we need to replace:
//- get_entry_guards()
//- num_live_entry_guards()
//- getinfo_helper_entry_guards()
//- entries_retry_helper()
//- any_bridge_supports_microdescriptors()
//- update_node_guard_status (OK - called from *set_from_config and
//  *parse_state. This is an optimization to set the using_as_guard flag.)
//- entry_guards_compute_status (OK - when a new consensus arrives)
//- log_entry_guards (OK - wont be used)
//- add_an_entry_guard (OK - wont be used)
//- entry_guard_register_connect_status (OK - wont be used)
//- entry_guards_set_from_config (OK - wont be used)
//- entry_guards_parse_state and entry_guards_update_state (OK - wont be used)
//- choose_random_entry_impl (OK - wont be used)

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
#include "routerset.h"
#include "confparse.h"
#include "statefile.h"
#include "entrynodes.h"
#include "routerparse.h"
#include "circpathbias.h"
#include "control.h"

//XXX Find the appropriate place for this global state

/** Entry guard selection algorithm **/
static const entry_guard_t *pending_guard = NULL;
static guard_selection_t *entry_guard_selection = NULL;

static guardlist_t *used_guards = NULL;
static guardlist_t *sampled_guards = NULL;

static int used_guards_dirty = 0;
static int sampled_guards_dirty = 0;

guardlist_t*
guardlist_new(void)
{
    //XXX We could keep a hashmap to make lookups faster
    guardlist_t *gl = tor_malloc_zero(sizeof(guardlist_t));
    gl->list = smartlist_new();
    return gl;
}

static entry_guard_t*
guardlist_get_by_digest(const guardlist_t *guards, const char *digest)
{
    //XXX This could benefit from a hashmap
    GUARDLIST_FOREACH(guards, entry_guard_t *, entry,
        if (tor_memeq(digest, entry->identity, DIGEST_LEN))
            return entry;
    );

    return NULL;
}

int
guardlist_len(guardlist_t *gl)
{
    if (!gl)
        return 0;

    return smartlist_len(gl->list);
}

void
guardlist_add(guardlist_t *gl, entry_guard_t *e)
{
    smartlist_add(gl->list, e);
}

static void
guardlist_add_all_smarlist(guardlist_t *gl, const smartlist_t *sl)
{
    smartlist_add_all(gl->list, sl);
}

void
guardlist_free(guardlist_t *gl)
{
  if (!gl)
    return;

  smartlist_free(gl->list);
  tor_free(gl);
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

static void
sampled_guards_changed(void)
{
  time_t when;
  sampled_guards_dirty = 1;

  if (get_options()->AvoidDiskWrites)
    when = time(NULL) + SLOW_GUARD_STATE_FLUSH_TIME;
  else
    when = time(NULL) + FAST_GUARD_STATE_FLUSH_TIME;

  /* or_state_save() will call guard_selection_update_state(). */
  or_state_mark_dirty(get_or_state(), when);
}

//XXX review if this is the right way of doing this
static const node_t*
guard_to_node(const entry_guard_t *guard)
{
    return node_get_by_id(guard->identity);
}

static int
is_related_to_exit(const node_t *node, const node_t *chosen_exit)
{
    int retval = 0;
    smartlist_t *exit_family = smartlist_new();

    if (chosen_exit) {
        nodelist_add_node_and_family(exit_family, chosen_exit);
    }

    if (node == chosen_exit)
        retval = 1;

    if (smartlist_contains(exit_family, node))
        retval = 1;

    smartlist_free(exit_family);
    return retval;
}

MOCK_IMPL(STATIC int,
is_live,(const entry_guard_t *guard))
{
    const char *msg = NULL;
    //We ignored need_capacity and need_bandwidth and for_directory
    return entry_is_live(guard, 0, &msg) == NULL ? 0 : 1;
}

MOCK_IMPL(STATIC int,
is_bad,(const entry_guard_t *guard))
{
    return (node_get_by_id(guard->identity) == NULL);
}

/** XXX Now we have a clear vision of what is "bad" vs "unlisted" we should
 * revisit this.
 **/

static int
should_try(const entry_guard_t* guard)
{
    if (guard->can_retry)
        return 1;

    return (is_live(guard) && !is_bad(guard));
}

static int
is_suitable(const entry_guard_t *entry, int for_directory)
{
    if (!is_live(entry))
        return 0;

    if (for_directory && !entry->is_dir_cache)
        return 0;

    return 1;
}

static int
should_ignore(const entry_guard_t *guard, int for_directory)
{
    return !is_suitable(guard, for_directory);
}

static int
is_eligible(const entry_guard_t* guard, int for_directory)
{
    return should_try(guard) &&
        !should_ignore(guard, for_directory);
}

/** -------------------------------------- **/

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

    GUARDLIST_FOREACH_BEGIN(guard_selection->used_guards, entry_guard_t *, e) {
        if (smartlist_contains(guard_selection->primary_guards, e)) {
            continue;
        }

        e->can_retry = 1;
    } GUARDLIST_FOREACH_END(e);
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
    }

    guard_selection->state = state;
}

static void
save_state_and_retry_primary_guards(guard_selection_t *guard_selection)
{
    guard_selection->previous_state = guard_selection->state;
    retry_primary_guards(guard_selection);
}

static void
guards_to_nodes(smartlist_t *nodes, const smartlist_t *guards)
{
    SMARTLIST_FOREACH_BEGIN(guards, entry_guard_t *, e) {
        const node_t *node = guard_to_node(e);
        if (!node)
            continue;

        smartlist_add(nodes, (node_t*) node);
    } SMARTLIST_FOREACH_END(e);
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

    GUARDLIST_FOREACH_BEGIN(guard_selection->used_guards, entry_guard_t *, e) {
        if (smartlist_contains(guard_selection->primary_guards, e)) {
            continue;
        }

        base16_encode(buf, sizeof(buf), e->identity, DIGEST_LEN);
        log_warn(LD_CIRC, "Evaluating '%s' (%s)", e->nickname, buf);

        if (is_eligible(e, guard_selection->for_directory))
            return e;

    } GUARDLIST_FOREACH_END(e);

    return NULL;
}

static void
choose_as_new_entry_guard(node_t *node)
{
    node->using_as_guard = 1;
    log_info(LD_CIRC, "Chose %s as new entry guard.", node_describe(node));
}

static entry_guard_t*
each_remaining_by_bandwidth(smartlist_t *guards, int for_directory)
{
    char buf[HEX_DIGEST_LEN+1];
    entry_guard_t *guard = NULL;
    smartlist_t *remaining_nodes = smartlist_new();

    log_warn(LD_CIRC, "There are %d candidates", smartlist_len(guards));

    guards_to_nodes(remaining_nodes, guards);

    while (smartlist_len(remaining_nodes) > 0) {
        //XXX It would be easier if it worked on a smartlist of guards
        const node_t *node = next_node_by_bandwidth(remaining_nodes);
        if (!node)
            break;

        /** Find the guard (again) **/
        //XXX it is easier to go from guard to node than the other way around
        //because there is a global node list.
        entry_guard_t *g = NULL;
        SMARTLIST_FOREACH_BEGIN(guards, entry_guard_t *, e) {
            if (fast_memeq(e->identity, node->identity, DIGEST_LEN)) {
                g = e;
                break;
            }
        } SMARTLIST_FOREACH_END(e);

        tor_assert(g);
        choose_as_new_entry_guard((node_t*) node);

        base16_encode(buf, sizeof(buf), g->identity, DIGEST_LEN);
        log_warn(LD_CIRC, "Evaluating '%s' (%s)", g->nickname, buf);

        if (!is_live(g)) {
            log_warn(LD_CIRC, "  Removing (not live).");
            smartlist_remove(guards, g);
            continue;
        }

        if (!is_eligible(g, for_directory)) {
            log_warn(LD_CIRC, "  Ignoring (not eligible).");
            continue;
        }

        guard = g;
        break;
    }

    tor_free(remaining_nodes);
    return guard;
}

static entry_guard_t*
each_remaining_utopic_by_bandwidth(guard_selection_t* guard_selection)
{
    return each_remaining_by_bandwidth(
                   guard_selection->remaining_guards,
                   guard_selection->for_directory);
}

static entry_guard_t*
state_TRY_UTOPIC_next(guard_selection_t *guard_selection)
{
    log_warn(LD_CIRC, "Will try USED_GUARDS not in PRIMARY_GUARDS.");

    entry_guard_t *guard = each_used_guard_not_in_primary_guards(
        guard_selection);

    if (guard)
        return guard;

    log_warn(LD_CIRC, "Will try REMAINING_UTOPIC_GUARDS.");

    guard = each_remaining_utopic_by_bandwidth(guard_selection);
    if (guard) {
        return guard;
    }

    transition_to(guard_selection, STATE_PRIMARY_GUARDS);

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
    }

    return NULL;
}

static smartlist_t*
filter_set(const guardlist_t *guards)
{
    smartlist_t *filtered = smartlist_new();

    GUARDLIST_FOREACH_BEGIN(guards, entry_guard_t *, guard) {
        if (is_live(guard))
            smartlist_add(filtered, guard);
    } SMARTLIST_FOREACH_END(guard);

    return filtered;
}

//XXX define the values for this
#define MINIMUM_FILTERED_SAMPLE_SIZE 20
#define MAXIMUM_RETRIES 10

STATIC void
fill_in_remaining_utopic(guard_selection_t *guard_selection,
                         const guardlist_t *sampled_guards)
{
    guard_selection->remaining_guards = smartlist_new();

    /** Filter the sampled set **/
    //XXX consider for_directory
    smartlist_t *filtered = filter_set(sampled_guards);

    if (smartlist_len(filtered) < MINIMUM_FILTERED_SAMPLE_SIZE) {
        //XXX expand and evaluate
    }

    smartlist_subtract(filtered, guard_selection->used_guards->list);
    smartlist_add_all(guard_selection->remaining_guards, filtered);
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
    if (guard_selection->primary_guards)
        smartlist_free(guard_selection->primary_guards);

    if (guard_selection->remaining_guards)
        smartlist_free(guard_selection->remaining_guards);
}

STATIC guard_selection_t*
choose_entry_guard_algo_start(guardlist_t *used_guards,
                              const guardlist_t *sampled_guards,
                              routerset_t *exclude_nodes, int n_primary_guards,
                              int for_directory)
{
    guard_selection_t *guard_selection = tor_malloc_zero(
        sizeof(guard_selection_t));
    guard_selection->for_directory = for_directory;
    guard_selection->state = STATE_PRIMARY_GUARDS;
    guard_selection->used_guards = used_guards;
    guard_selection->num_primary_guards = n_primary_guards;

    //XXX is sampled_guards a list of guard or node?
    fill_in_remaining_utopic(guard_selection, sampled_guards);
    fill_in_primary_guards(guard_selection);

    log_warn(LD_CIRC, "Initializing guard_selection:\n"
        "- used: %p,\n"
        "- sampled_guards: %p,\n"
        "- exclude_nodes: %p,\n"
        "- n_primary_guards: %d,\n"
        "- for_directory: %d\n",
        used_guards, sampled_guards, exclude_nodes,
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

/* dest is a list of guards */
static void
remaining_guards_for_next_primary(guard_selection_t *guard_selection,
                                  smartlist_t *guards)
{
    smartlist_add_all(guards, guard_selection->remaining_guards);
    smartlist_subtract(guards, guard_selection->used_guards->list);
    smartlist_subtract(guards, guard_selection->primary_guards);
}

STATIC entry_guard_t*
next_primary_guard(guard_selection_t *guard_selection)
{
    const node_t *node = NULL;
    const guardlist_t *used = guard_selection->used_guards;
    const smartlist_t *primary = guard_selection->primary_guards;

    GUARDLIST_FOREACH_BEGIN(used, entry_guard_t *, e) {
        if (!smartlist_contains(primary, e) && !is_bad(e))
            return e;
    } GUARDLIST_FOREACH_END(e);

    { /** Get next remaining guard **/
        smartlist_t *remaining_guards = smartlist_new();
        smartlist_t *remaining_nodes = smartlist_new();

        remaining_guards_for_next_primary(guard_selection, remaining_guards);
        guards_to_nodes(remaining_nodes, remaining_guards);
        node = next_node_by_bandwidth(remaining_nodes);

        tor_free(remaining_nodes);
        tor_free(remaining_guards);
    }

    if (!node)
        return NULL;

    choose_as_new_entry_guard((node_t*) node);

    /** Remove from remaining **/
    entry_guard_t *guard = NULL;
    SMARTLIST_FOREACH_BEGIN(guard_selection->remaining_guards,
        entry_guard_t *, e) {
        if (fast_memeq(e->identity, node->identity, DIGEST_LEN)) {
            guard = e;
            SMARTLIST_DEL_CURRENT(guard_selection->remaining_guards, e);
            break;
        }
    } SMARTLIST_FOREACH_END(e);

    return guard;
}

/** returns a list of GUARDS **/
STATIC void
fill_in_sampled_guard_set(guardlist_t *sample, const smartlist_t *nodes,
                          const int size)
{
    smartlist_t *remaining = smartlist_new();

    smartlist_add_all(remaining, nodes);
    while (guardlist_len(sample) < size && smartlist_len(remaining) > 0) {
        const node_t *node = next_node_by_bandwidth(remaining);
        if (!node)
            break;

        guardlist_add(sample, entry_guard_new(node));
    }
    smartlist_free(remaining);
}

static void
fill_in_sampled_sets(const smartlist_t *utopic_nodes)
{
    //XXX Extract a configuration from this
    const double sample_set_threshold = 0.005;

    tor_assert(sampled_guards);
    fill_in_sampled_guard_set(sampled_guards, utopic_nodes,
        sample_set_threshold * smartlist_len(utopic_nodes));

    //XXX do this only when it changed
    sampled_guards_changed();

    log_warn(LD_CIRC, "We sampled %d from %d utopic guards",
        guardlist_len(sampled_guards), smartlist_len(utopic_nodes));
}

//XXX Add tests
STATIC void
choose_entry_guard_algo_end(guard_selection_t *guard_selection,
                            const entry_guard_t *guard)
{
    log_warn(LD_CIRC, "Finishing guard selection algorithm");

    //XXX The entry_guard_t generated by NEXT() is not the same
    //as the loaded by the file, so we need to compare the digests.
    guardlist_t *used = guard_selection->used_guards;
    smartlist_t *fps = smartlist_new();
    GUARDLIST_FOREACH(used, entry_guard_t *, e,
        smartlist_add(fps, (void*)e->identity));

    if (!smartlist_contains_digest(fps, guard->identity)) {
        guardlist_add(used, (entry_guard_t*) guard);
        used_guards_changed();
    }

    smartlist_free(fps);
}

/** Largest amount that we'll backdate chosen_on_date */
#define CHOSEN_ON_DATE_SLOP (3600*24*30)

static time_t
entry_guard_chosen_on_date(const time_t now)
{
  /* Choose expiry time smudged over the past month. The goal here
   * is to a) spread out when Tor clients rotate their guards, so they
   * don't all select them on the same day, and b) avoid leaving a
   * precise timestamp in the state file about when we first picked
   * this guard. For details, see the Jan 2010 or-dev thread. */
    return crypto_rand_time_range(now - CHOSEN_ON_DATE_SLOP, now);
}

static int
guards_parse_state(config_line_t *line, const char *state_version,
                   const char* config_name, smartlist_t *guards,
                   char **msg)
{
    entry_guard_t *node = NULL;
    smartlist_t *new_entry_guards = smartlist_new();
    int changed = 0;
    time_t now = time(NULL);
    digestmap_t *added_by = digestmap_new();

    char *down_since_config_name = NULL;
    char *unlisted_since_config_name = NULL;
    char *added_by_config_name = NULL;
    char *path_use_bias_config_name = NULL;
    char *path_bias_config_name = NULL;

    tor_asprintf(&down_since_config_name, "%sDownSince", config_name);
    tor_asprintf(&unlisted_since_config_name, "%sUnlistedSince", config_name);
    tor_asprintf(&added_by_config_name, "%sAddedBy", config_name);
    tor_asprintf(&path_use_bias_config_name, "%sPathUseBias", config_name);
    tor_asprintf(&path_bias_config_name, "%sPathBias", config_name);

    *msg = NULL;
    for (; line; line = line->next) {
        if (!strcasecmp(line->key, config_name)) {
            smartlist_t *args = smartlist_new();
            node = tor_malloc_zero(sizeof(entry_guard_t));

            /* all entry guards on disk have been contacted */
            //Not true, only valid for USED_GUARDS
            //node->made_contact = 1;

            smartlist_add(new_entry_guards, node);
            smartlist_split_string(args, line->value, " ",
                SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);

            /* Validates nickname and fingerprint */
            if (smartlist_len(args)<2) {
                tor_asprintf(msg, "Unable to parse entry nodes: "
                    "Too few arguments to %s", config_name);
            } else if (!is_legal_nickname(smartlist_get(args,0))) {
                tor_asprintf(msg, "Unable to parse entry nodes: "
                    "Bad nickname for %s", config_name);
            } else {
                char *nickname = smartlist_get(args, 0);
                char *digest = smartlist_get(args, 1);

                strlcpy(node->nickname, nickname, MAX_NICKNAME_LEN+1);
                if (base16_decode(node->identity, DIGEST_LEN, digest,
                    strlen(digest))<0) {
                    tor_asprintf(msg, "Unable to parse entry nodes: "
                        "Bad hex digest for %s", config_name);
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
                        "Bogus third argument to %s line: %s",
                        config_name, escaped(is_cache));
                }
            }

            SMARTLIST_FOREACH(args, char*, cp, tor_free(cp));
            smartlist_free(args);

            /* Abort on error */
            if (*msg)
                break;

        } else if (!strcasecmp(line->key, down_since_config_name) ||
            !strcasecmp(line->key, unlisted_since_config_name)) {
            time_t when;
            time_t last_try = 0;

            if (!node) {
                tor_asprintf(msg, "Unable to parse used guard: "
                    "%sDownSince/UnlistedSince without %s", config_name,
                    config_name);
                break;
            }

            if (parse_iso_time_(line->value, &when, 0)<0) {
                tor_asprintf(msg, "Unable to parse used guard: "
                    "Bad time in %sDownSince/UnlistedSince", config_name);
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

            if (!strcasecmp(line->key, down_since_config_name)) {
                node->unreachable_since = when;
                node->last_attempted = last_try;
            } else {
                node->bad_since = when;
            }

        } else if (!strcasecmp(line->key, added_by_config_name)) {
            char d[DIGEST_LEN];
            /* format is digest version date */
            if (strlen(line->value) < HEX_DIGEST_LEN+1+1+1+ISO_TIME_LEN) {
                log_warn(LD_BUG, "%s line is not long enough.",
                    added_by_config_name);
                continue;
            }

            if (base16_decode(d, sizeof(d), line->value, HEX_DIGEST_LEN)<0 ||
                line->value[HEX_DIGEST_LEN] != ' ') {
                log_warn(LD_BUG, "%s line %s does not begin with "
                    "hex digest", added_by_config_name, escaped(line->value));
                continue;
            }

            digestmap_set(added_by, d,
                tor_strdup(line->value+HEX_DIGEST_LEN+1));
        } else if (!strcasecmp(line->key, path_use_bias_config_name)) {
            const or_options_t *options = get_options();
            double use_cnt, success_cnt;

            if (!node) {
                tor_asprintf(msg, "Unable to parse entry nodes: "
                    "%s without %s", path_use_bias_config_name, config_name);
                break;
            }

            if (tor_sscanf(line->value, "%lf %lf",
                &use_cnt, &success_cnt) != 2) {
                log_info(LD_GENERAL, "Malformed path use bias line for node"
                    " %s", node->nickname);
                continue;
            }

            if (use_cnt < success_cnt) {
                int severity = LOG_INFO;
                /* If this state file was written by a Tor that would have
                 * already fixed it, then the overcounting bug is still
                 * there.. */
                if (tor_version_as_new_as(state_version, "0.2.4.13-alpha")) {
                    severity = LOG_NOTICE;
                }
                log_fn(severity, LD_BUG,
                    "State file contains unexpectedly high usage success "
                    "counts %lf/%lf for Guard %s ($%s)",
                    success_cnt, use_cnt,
                    node->nickname, hex_str(node->identity, DIGEST_LEN));
                success_cnt = use_cnt;
            }

            node->use_attempts = use_cnt;
            node->use_successes = success_cnt;

            log_info(LD_GENERAL, "Read %f/%f path use bias for node %s",
                node->use_successes, node->use_attempts, node->nickname);

            /* Note: We rely on the < comparison here to allow us to set a 0
             * rate and disable the feature entirely. If refactoring, don't
             * change to <= */
            if (pathbias_get_use_success_count(node)/node->use_attempts
                < pathbias_get_extreme_use_rate(options) &&
                pathbias_get_dropguards(options)) {
                node->path_bias_disabled = 1;
                log_info(LD_GENERAL,
                    "Path use bias is too high (%f/%f); disabling node %s",
                    node->circ_successes, node->circ_attempts, node->nickname);
            }
        } else if (!strcasecmp(line->key, path_bias_config_name)) {
            const or_options_t *options = get_options();
            double hop_cnt, success_cnt, timeouts, collapsed,
                   successful_closed, unusable;

            if (!node) {
                tor_asprintf(msg, "Unable to parse entry nodes: "
                    "%s without %s", path_bias_config_name, config_name);
                break;
            }

            /* First try 3 params, then 2. */
            /* In the long run: circuit_success ~= successful_circuit_close +
             *                                     collapsed_circuits +
             *                                     unusable_circuits */
            if (tor_sscanf(line->value, "%lf %lf %lf %lf %lf %lf",
                &hop_cnt, &success_cnt, &successful_closed,
                &collapsed, &unusable, &timeouts) != 6) {
                int old_success, old_hops;
                if (tor_sscanf(line->value, "%u %u", &old_success,
                    &old_hops) != 2) {
                    continue;
                }
                log_info(LD_GENERAL, "Reading old-style %s %s",
                    path_bias_config_name, escaped(line->value));

                success_cnt = old_success;
                successful_closed = old_success;
                hop_cnt = old_hops;
                timeouts = 0;
                collapsed = 0;
                unusable = 0;
            }

            if (hop_cnt < success_cnt) {
                int severity = LOG_INFO;
                /* If this state file was written by a Tor that would have
                 * already fixed it, then the overcounting bug is still
                 * there.. */
                if (tor_version_as_new_as(state_version, "0.2.4.13-alpha")) {
                    severity = LOG_NOTICE;
                }
                log_fn(severity, LD_BUG,
                    "State file contains unexpectedly high success counts "
                    "%lf/%lf for Guard %s ($%s)",
                    success_cnt, hop_cnt,
                    node->nickname, hex_str(node->identity, DIGEST_LEN));
                success_cnt = hop_cnt;
            }

            node->circ_attempts = hop_cnt;
            node->circ_successes = success_cnt;

            node->successful_circuits_closed = successful_closed;
            node->timeouts = timeouts;
            node->collapsed_circuits = collapsed;
            node->unusable_circuits = unusable;

            log_info(LD_GENERAL, "Read %f/%f path bias for node %s",
                node->circ_successes, node->circ_attempts, node->nickname);
            /* Note: We rely on the < comparison here to allow us to set a 0
             * rate and disable the feature entirely. If refactoring, don't
             * change to <= */
            if (pathbias_get_close_success_count(node)/node->circ_attempts
                < pathbias_get_extreme_rate(options) &&
                pathbias_get_dropguards(options)) {
                node->path_bias_disabled = 1;
                log_info(LD_GENERAL,
                    "Path bias is too high (%f/%f); disabling node %s",
                    node->circ_successes, node->circ_attempts, node->nickname);
            }
        } else {
            log_warn(LD_BUG, "Unexpected key %s", line->key);
        }
    }

    SMARTLIST_FOREACH_BEGIN(new_entry_guards, entry_guard_t *, e) {
        char *sp;
        char *val = digestmap_get(added_by, e->identity);
        if (val && (sp = strchr(val, ' '))) {
            time_t when;
            *sp++ = '\0';
            if (parse_iso_time(sp, &when)<0) {
                log_warn(LD_BUG, "Can't read time %s in %s", sp,
                    added_by_config_name);
            } else {
                e->chosen_by_version = tor_strdup(val);
                e->chosen_on_date = when;
            }
        } else {
            if (state_version) {
                time_t now = time(NULL);
                e->chosen_on_date = entry_guard_chosen_on_date(now);
                e->chosen_by_version = tor_strdup(state_version);
            }
        }

        if (e->path_bias_disabled && !e->bad_since)
            e->bad_since = time(NULL);
    }
    SMARTLIST_FOREACH_END(e);

    if (*msg || !guards) {
        SMARTLIST_FOREACH(new_entry_guards, entry_guard_t *, e,
            entry_guard_free(e));
        smartlist_free(new_entry_guards);
    } else {
        /* Free used guards and replace by guards in state, on success */
        SMARTLIST_FOREACH(guards, entry_guard_t *, e,
            entry_guard_free(e));
        smartlist_clear(guards);
        smartlist_add_all(guards, new_entry_guards);

        remove_obsolete_guards(now, new_entry_guards);
        if (smartlist_len(new_entry_guards)) {
            changed = 1;

            log_warn(LD_CIRC, "GUARDS loaded:");
            log_guards(LOG_WARN, guards);
        }

        //XXX should we?
        //This updates the using_as_guard for each node
        //update_node_guard_status();
    }

    tor_free(down_since_config_name);
    tor_free(unlisted_since_config_name);
    tor_free(added_by_config_name);
    tor_free(path_use_bias_config_name);
    tor_free(path_bias_config_name);

    return *msg ? -1 : changed;
}

static int
sampled_guards_parse_state(const or_state_t *state, smartlist_t *sample,
                           char **msg)
{
    return guards_parse_state(state->SampledGuards, state->TorVersion,
        "SampledGuard", sample, msg);
}

STATIC int
used_guards_parse_state(const or_state_t *state, smartlist_t *used_guards,
                        char **msg)
{
    return guards_parse_state(state->UsedGuards, state->TorVersion,
        "UsedGuard", used_guards, msg);
}

STATIC int
entry_guards_parse_state_backward(const or_state_t *state,
                                  smartlist_t *entry_guards, char **msg)
{
    int ret = guards_parse_state(state->EntryGuards, state->TorVersion,
        "EntryGuard", entry_guards, msg);

    if (ret == 1)
        used_guards_changed();

    return ret;
}

static void
guards_update_state(config_line_t **next, const guardlist_t *guards,
                    const char* config_name)
{
    log_warn(LD_CIRC, "Will store %s", config_name);

    config_line_t *line = NULL;
    char *down_since_config_name = NULL;
    char *unlisted_since_config_name = NULL;
    char *added_by_config_name = NULL;
    char *path_use_bias_config_name = NULL;
    char *path_bias_config_name = NULL;

    tor_asprintf(&down_since_config_name, "%sDownSince", config_name);
    tor_asprintf(&unlisted_since_config_name, "%sUnlistedSince", config_name);
    tor_asprintf(&added_by_config_name, "%sAddedBy", config_name);
    tor_asprintf(&path_use_bias_config_name, "%sPathUseBias", config_name);
    tor_asprintf(&path_bias_config_name, "%sPathBias", config_name);

    GUARDLIST_FOREACH_BEGIN(guards, entry_guard_t *, e) {
        char dbuf[HEX_DIGEST_LEN+1];
        *next = line = tor_malloc_zero(sizeof(config_line_t));
        line->key = tor_strdup(config_name);

        base16_encode(dbuf, sizeof(dbuf), e->identity, DIGEST_LEN);
        tor_asprintf(&line->value, "%s %s %sDirCache", e->nickname, dbuf,
            e->is_dir_cache ? "" : "No");

        next = &(line->next);
        if (e->unreachable_since) {
            *next = line = tor_malloc_zero(sizeof(config_line_t));
            line->key = tor_strdup(down_since_config_name);
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
            line->key = tor_strdup(unlisted_since_config_name);
            line->value = tor_malloc(ISO_TIME_LEN+1);
            format_iso_time(line->value, e->bad_since);
            next = &(line->next);
        }

        if (e->chosen_on_date && e->chosen_by_version &&
            !strchr(e->chosen_by_version, ' ')) {
            char d[HEX_DIGEST_LEN+1];
            char t[ISO_TIME_LEN+1];
            *next = line = tor_malloc_zero(sizeof(config_line_t));
            line->key = tor_strdup(added_by_config_name);
            base16_encode(d, sizeof(d), e->identity, DIGEST_LEN);
            format_iso_time(t, e->chosen_on_date);
            tor_asprintf(&line->value, "%s %s %s",
                d, e->chosen_by_version, t);
            next = &(line->next);
        }

        if (e->circ_attempts > 0) {
            *next = line = tor_malloc_zero(sizeof(config_line_t));
            line->key = tor_strdup(path_bias_config_name);
            /* In the long run: circuit_success ~= successful_circuit_close +
             *                                     collapsed_circuits +
             *                                     unusable_circuits */
            tor_asprintf(&line->value, "%f %f %f %f %f %f",
                e->circ_attempts, e->circ_successes,
                pathbias_get_close_success_count(e),
                e->collapsed_circuits,
                e->unusable_circuits, e->timeouts);
            next = &(line->next);
        }

        if (e->use_attempts > 0) {
            *next = line = tor_malloc_zero(sizeof(config_line_t));
            line->key = tor_strdup(path_use_bias_config_name);

            tor_asprintf(&line->value, "%f %f",
                e->use_attempts,
                pathbias_get_use_success_count(e));
            next = &(line->next);
        }

    } GUARDLIST_FOREACH_END(e);

    tor_free(down_since_config_name);
    tor_free(unlisted_since_config_name);
    tor_free(added_by_config_name);
    tor_free(path_use_bias_config_name);
    tor_free(path_bias_config_name);
}

//XXX Add test
//XXX Make it able to also save SampledGuards
STATIC void
used_guards_update_state(or_state_t *state, guardlist_t *used_guards)
{
    config_line_t **next = NULL;

    //EntryGuards is replaced by UsedGuards
    config_free_lines(state->EntryGuards);
    next = &state->EntryGuards;
    *next = NULL;

    config_free_lines(state->UsedGuards);
    next = &state->UsedGuards;
    *next = NULL;

    guards_update_state(next, used_guards, "UsedGuard");
}

static void
sampled_guards_update_state(or_state_t *state, guardlist_t *sampled_guards)
{
    config_line_t **next = NULL;

    config_free_lines(state->SampledGuards);
    next = &state->SampledGuards;
    *next = NULL;

    guards_update_state(next, sampled_guards, "SampledGuard");
}

static int
decide_if_should_continue(const entry_guard_t *guard, int succeeded,
                          time_t now)
{
    int should_continue = 0;

    //XXX Is this possible?
    if (!entry_guard_selection) {
        log_warn(LD_CIRC, "We have no guard_selection algo."
            " Should not continue.");
        return 0;
    }

    //XXX add this to options
    int internet_likely_down_interval = 5;

    should_continue = choose_entry_guard_algo_should_continue(
        entry_guard_selection, succeeded, now, internet_likely_down_interval);

    log_warn(LD_CIRC, "Should continue? %d", should_continue);

    if (!should_continue) {
        choose_entry_guard_algo_end(entry_guard_selection, guard);
        guard_selection_free(entry_guard_selection);
        tor_free(entry_guard_selection);
    } else {
        //XXX entry_guard_register_connect_status() is smarter and only calls
        //it when any guard has changed. We will get there.
        used_guards_changed();
    }

    return should_continue;
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

    const or_options_t *options = get_options();
    const int for_directory = 0; //XXX how to get this at this moment?
    const int num_needed = decide_num_guards(options, for_directory);

    //XXX Is this the right place to ensure it is loaded from state file?
    if (!used_guards)
        guard_selection_parse_used_guards_state(get_or_state(), 1, NULL);

    if (!sampled_guards)
        guard_selection_parse_sampled_guards_state(get_or_state(), 1, NULL);

    entry_guard_selection = choose_entry_guard_algo_start(
        used_guards, sampled_guards,
        options->ExcludeNodes,
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
    //If pending_guard exist we keep using it until there is a feedback on
    //the connection.
    if (pending_guard) {
        const node_t *node = node_get_by_id(pending_guard->identity);
        if (node) {
            log_warn(LD_CIRC, "Reuse %s as entry guard for this circuit.",
                node_describe(node));
            return node;
        }

        //XXX should it also restart the guard selection state?
        pending_guard = NULL;
    }

    //entry guard selection context should be the same for this batch of
    //circuits. The same entry guard will be used for all the circuits in this
    //batch until it fails.
    if (!entry_guard_selection)
        entry_guard_selection_init();

    //We can not choose guards yet, probably due not having enough guards
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
    (void) dirinfo_type;
    /* (void) need_uptime; */
    /* (void) need_capacity; */

    if (n_options_out)
        *n_options_out = 0;

    //XXX see entry_guards_set_from_config(options);

    const int num_needed = decide_num_guards(options, for_directory);
    entry_guard_selection->for_directory = for_directory;
    entry_guard_selection->num_primary_guards = num_needed;

    const node_t *chosen_exit =
        state ? build_state_get_exit_node(state) : NULL;

  retry:
    guard = choose_entry_guard_algo_next(entry_guard_selection, options, now);

    // This only exists because NEXT() can return NULL when transitioning
    // between states
    if (!guard)
        goto retry;

    // Guard is not in the consensus anymore. Not sure if this is possible
    node = guard_to_node(guard);
    tor_assert(node);

    // This is another part of IS_SUITABLE. It's here to avoid
    // passing the exit node to the guard_selection_t
    if (is_related_to_exit(node, chosen_exit))
        goto retry;

    log_warn(LD_CIRC, "Chose %s as entry guard for this circuit.",
        node_describe(node));

    //XXX check entry_guards_changed();

    //XXX What is n_options_out in our case?
    if (n_options_out)
        *n_options_out = 1;

    pending_guard = guard;
    return node;
}

//XXX We need something like entry_guards_compute_status()
//which should also calls used_guards_changed()

//XXX Add tests
static void
fill_in_from_entrynodes(const or_options_t *options, guardlist_t *dest)
{
    tor_assert(dest);

    smartlist_t *entry_nodes, *worse_entry_nodes, *entry_fps;
    smartlist_t *old_entry_guards_on_list, *old_entry_guards_not_on_list;
    // old entry guards in the primary
    old_entry_guards_on_list = smartlist_new();
    // old entry guards not in the primary
    old_entry_guards_not_on_list = smartlist_new();

    // EntryNodes in options
    entry_nodes = smartlist_new();
    // EntryNodes in options but not is_possible_gurad
    worse_entry_nodes = smartlist_new();

    // convert EntryNodes to entry_nodes excluding ExcludeNodes
    routerset_get_all_nodes(entry_nodes, options->EntryNodes,
        options->ExcludeNodes, 0);

    //add fingerprints from entry_nodes
    entry_fps = smartlist_new();
    SMARTLIST_FOREACH(entry_nodes, const node_t *,node,
        smartlist_add(entry_fps, (void*)node->identity));

    //XXX split up old guards into two list according to
    //USED_GUARDS (sure ?) list
    if (entry_guard_selection && entry_guard_selection->used_guards) {
        SMARTLIST_FOREACH(entry_guard_selection->used_guards->list,
            entry_guard_t *, e, {
            if (smartlist_contains_digest(entry_fps, e->identity))
                smartlist_add(old_entry_guards_on_list, e);
            else
                smartlist_add(old_entry_guards_not_on_list, e);
        });
    }

    /* Remove all currently configured guard nodes, excluded nodes, unreachable
     * nodes, or non-Guard nodes from entry_nodes. */
    SMARTLIST_FOREACH_BEGIN(entry_nodes, const node_t *, node) {
        if (entry_guard_get_by_id_digest(node->identity)) {
            SMARTLIST_DEL_CURRENT(entry_nodes, node);
            continue;
        } else if (! node->is_possible_guard) {
            smartlist_add(worse_entry_nodes, (node_t*)node);
            SMARTLIST_DEL_CURRENT(entry_nodes, node);
        }
    } SMARTLIST_FOREACH_END(node);

    smartlist_t *sample = smartlist_new();

    /* First, the previously configured guards that are in EntryNodes. */
    smartlist_add_all(sample, old_entry_guards_on_list);
    /* Next, scramble the rest of EntryNodes, putting the guards first. */
    smartlist_shuffle(entry_nodes);
    smartlist_shuffle(worse_entry_nodes);
    smartlist_add_all(entry_nodes, worse_entry_nodes);
    /* Next, the rest of EntryNodes */
    smartlist_add_all(sample, entry_nodes);

    /* Finally, free the remaining previously configured guards that are not in
     * EntryNodes. */
    SMARTLIST_FOREACH(old_entry_guards_not_on_list, entry_guard_t *, e,
        entry_guard_free(e));

    //XXX update_node_guard_status();

    /** Fill in ignoring sample size  **/
    fill_in_sampled_guard_set(dest, sample,
        smartlist_len(sample));

    //XXX do this only when it changed
    sampled_guards_changed();

    log_warn(LD_CIRC, "We sampled %d from %d EntryNodes",
        guardlist_len(dest), smartlist_len(sample));

    smartlist_free(old_entry_guards_on_list);
    smartlist_free(old_entry_guards_not_on_list);
    smartlist_free(entry_nodes);
    smartlist_free(worse_entry_nodes);
    smartlist_free(entry_fps);
}

static void
fill_in_restricted(const or_options_t *options)
{
    if (options->EntryNodes)
        fill_in_from_entrynodes(options, sampled_guards);
}

//XXX Add tests
static void
prune_guardlist(const time_t now, guardlist_t *gl)
{
    int changed = 0;
    log_warn(LD_CIRC, "Prunning a list of guards");

    changed = remove_dead_guards(now, gl->list);
    if (changed)
        log_warn(LD_CIRC, "Removed some dead guards");

    changed = remove_obsolete_guards(now, gl->list);
    if (changed)
        log_warn(LD_CIRC, "Removed some obsolete guards");
}

//XXX Add tests
//This matches entry_guards_compute_status
void
entry_guards_update_profiles(const or_options_t *options, const time_t now)
{
    log_warn(LD_CIRC, "Received a new consensus");

    if (used_guards)
        prune_guardlist(now, used_guards);

    if (sampled_guards)
        prune_guardlist(now, sampled_guards);

    //We recreate the sample sets without restricting to directory
    //guards, because most of the entry guards will be directory in
    //the near ideal future.
    int for_directory = 0;

    // XXX we put this here for now because it's consuming guards and trying
    // to fill the sample_set with option->EntryNodes or options->UseBridge
    // or other
    // XXX We probably want to do this on options_act because this can change
    // before we receive a consensus
    if (entry_list_is_constrained(options)) {
        fill_in_restricted(options);
    } else {
        smartlist_t *utopic = get_all_guards(for_directory);
        fill_in_sampled_sets(utopic);
        smartlist_free(utopic);
    }

    //XXX Is this necessary?
    if (entry_guard_selection)
        choose_entry_guard_algo_new_consensus(entry_guard_selection);
}

int
update_entry_guards_connection_status(entry_guard_t *entry,
                                      const int succeeded, const time_t now)
{
    int changed = 0;
    char buf[HEX_DIGEST_LEN+1];
    base16_encode(buf, sizeof(buf), entry->identity, DIGEST_LEN);

    if (succeeded) {
        if (entry->unreachable_since) {
            log_info(LD_CIRC, "Entry guard '%s' (%s) is now reachable again."
                " Good.", entry->nickname, buf);

            entry->can_retry = 0;
            entry->unreachable_since = 0;
            entry->last_attempted = now;
            control_event_guard(entry->nickname, entry->identity, "UP");
            changed = 1;
        }
        if (!entry->made_contact) {
            entry->made_contact = 1;
            changed = 1;
        }
    } else { /* ! succeeded */
        if (entry->made_contact && !entry->unreachable_since) {
            log_info(LD_CIRC, "Unable to connect to entry guard '%s' (%s). "
                "Marking as unreachable.", entry->nickname, buf);
            entry->unreachable_since = entry->last_attempted = now;
            control_event_guard(entry->nickname, entry->identity, "DOWN");
            changed = 1;
            entry->can_retry = 0; /* We gave it an early chance; no good. */
        } else {
            char tbuf[ISO_TIME_LEN+1];
            format_iso_time(tbuf, entry->unreachable_since);
            log_debug(LD_CIRC, "Failed to connect to unreachable entry guard "
                "'%s' (%s).  It has been unreachable since %s.",
                entry->nickname, buf, tbuf);
            entry->last_attempted = now;
            entry->can_retry = 0; /* We gave it an early chance; no good. */
        }
    }

    return changed;
}

int
guard_selection_register_connect_status(const char *digest, int succeeded,
                                        int mark_relay_status, time_t now)
{
  int changed = 0;
  int should_continue = 0;
  entry_guard_t *entry = NULL;

  if (!pending_guard)
      return 0;

  // This is not the guard we are waiting for
  if (!fast_memeq(pending_guard->identity, digest, DIGEST_LEN))
      return 0;

  /* Process the pending gaurd */
  entry = (entry_guard_t*) pending_guard;

  //XXX We need to find a way to clear this when this callback is not
  //invoked (when there is already a connection established to this guard)
  pending_guard = NULL;

  log_warn(LD_CIRC, "Guard %s has succeeded = %d. Processing...",
      node_describe(guard_to_node(entry)), succeeded);

  /* if the caller asked us to, also update the is_running flags for this
   * relay */
  if (mark_relay_status)
    router_set_status(digest, succeeded);

  changed = update_entry_guards_connection_status(entry, succeeded, now);
  should_continue = decide_if_should_continue(entry, succeeded, now);

  if (changed)
    entry_guards_changed();

  return should_continue ? -1 : 0;
}

void
guard_selection_update_state(or_state_t *state, const or_options_t *options)
{
    if (!used_guards_dirty && !sampled_guards_dirty)
        return;

    if (used_guards_dirty)
        used_guards_update_state(state, used_guards);

    if (sampled_guards_dirty)
        sampled_guards_update_state(state, sampled_guards);

    if (!options->AvoidDiskWrites)
        or_state_mark_dirty(state, 0);

    used_guards_dirty = 0;
    sampled_guards_dirty = 0;
}

entry_guard_t *
used_guard_get_by_digest(const char *digest)
{
    if (!entry_guard_selection)
        return NULL;

    return guardlist_get_by_digest(entry_guard_selection->used_guards, digest);
}

void
log_guards(int severity, const smartlist_t *guards)
{
  smartlist_t *elements = smartlist_new();
  char *s;

  SMARTLIST_FOREACH_BEGIN(guards, entry_guard_t *, e)
    {
      if (is_live(e))
        smartlist_add_asprintf(elements, "%s [%s] (up %s)",
                     e->nickname,
                     hex_str(e->identity, DIGEST_LEN),
                     e->made_contact ? "made-contact" : "never-contacted");
      else
        smartlist_add_asprintf(elements, "%s [%s] (NOT LIVE, %s)",
                     e->nickname,
                     hex_str(e->identity, DIGEST_LEN),
                     e->made_contact ? "made-contact" : "never-contacted");
    }
  SMARTLIST_FOREACH_END(e);

  s = smartlist_join_strings(elements, ",", 0, NULL);
  SMARTLIST_FOREACH(elements, char*, cp, tor_free(cp));
  smartlist_free(elements);
  log_fn(severity,LD_CIRC,"%s",s);
  tor_free(s);
}

int
guard_selection_parse_sampled_guards_state(const or_state_t *state, int set,
                                           char **msg)
{
    log_warn(LD_CIRC, "Will load sample set from state file.");

    if (set) {
        tor_assert(!sampled_guards);
        sampled_guards = guardlist_new();
    }

    smartlist_t *guards = set ? smartlist_new() : NULL;
    int ret = sampled_guards_parse_state(state, guards, msg);

    if (set && ret == 1) {
        //XXX Should we mark them as made_contact if they are also in used?
        guardlist_add_all_smarlist(sampled_guards, guards);
    }

    smartlist_free(guards);
    return ret;
}

int
guard_selection_parse_used_guards_state(const or_state_t *state, int set,
                                        char **msg)
{
    log_warn(LD_CIRC, "Will load used guards from state file.");

    if (set) {
        tor_assert(!used_guards);
        used_guards = guardlist_new();
    }

    smartlist_t *guards = set ? smartlist_new() : NULL;
    int ret = entry_guards_parse_state_backward(state, guards, msg);
    if (ret == 0) {
        ret = used_guards_parse_state(state, guards, msg);
    }

    if (set && ret == 1) {
        guardlist_add_all_smarlist(used_guards, guards);
        /* We have made contact to all USED_GUARDS */
        GUARDLIST_FOREACH(used_guards, entry_guard_t *, entry,
            entry->made_contact = 1;
        );
    }

    //XXX Parse sampled set
    //Should we update their

    smartlist_free(guards);
    return ret;
}

/**
 * Return the minimum lifetime of working entry guard, in seconds,
 * as given in the consensus networkstatus.  (Plus CHOSEN_ON_DATE_SLOP,
 * so that we can do the chosen_on_date randomization while achieving the
 * desired minimum lifetime.)
 */
static int32_t
guards_get_lifetime(void)
{
  const or_options_t *options = get_options();
#define DFLT_GUARD_LIFETIME (86400 * 60)   /* Two months. */
#define MIN_GUARD_LIFETIME  (86400 * 30)   /* One months. */
#define MAX_GUARD_LIFETIME  (86400 * 1826) /* Five years. */

  if (options->GuardLifetime >= 1) {
    return CLAMP(MIN_GUARD_LIFETIME,
                 options->GuardLifetime,
                 MAX_GUARD_LIFETIME) + CHOSEN_ON_DATE_SLOP;
  }

  return networkstatus_get_param(NULL, "GuardLifetime",
                                 DFLT_GUARD_LIFETIME,
                                 MIN_GUARD_LIFETIME,
                                 MAX_GUARD_LIFETIME) + CHOSEN_ON_DATE_SLOP;
}

/** Remove any entry guard which was selected by an unknown version of Tor,
 * or which was selected by a version of Tor that's known to select
 * entry guards badly, or which was selected more 2 months ago. */
/* XXXX The "obsolete guards" and "chosen long ago guards" things should
 * probably be different functions. */
int
remove_obsolete_guards(time_t now, smartlist_t *guards)
{
    log_warn(LD_CIRC, "Will remove OBSOLETE guards");

    int changed = 0, i;
    int32_t guard_lifetime = guards_get_lifetime();

    for (i = 0; i < smartlist_len(guards); ++i) {
        entry_guard_t *entry = smartlist_get(guards, i);
        const char *ver = entry->chosen_by_version;
        const char *msg = NULL;
        tor_version_t v;
        int version_is_bad = 0, date_is_bad = 0;
        if (!ver) {
            msg = "does not say what version of Tor it was selected by";
            version_is_bad = 1;
        } else if (tor_version_parse(ver, &v)) {
            msg = "does not seem to be from any recognized version of Tor";
            version_is_bad = 1;
        }
        if (!version_is_bad && entry->chosen_on_date + guard_lifetime < now) {
            /* It's been too long since the date listed in our state file. */
            msg = "was selected several months ago";
            date_is_bad = 1;
        }

        if (version_is_bad || date_is_bad) { /* we need to drop it */
            char dbuf[HEX_DIGEST_LEN+1];
            tor_assert(msg);
            base16_encode(dbuf, sizeof(dbuf), entry->identity, DIGEST_LEN);
            log_fn(version_is_bad ? LOG_NOTICE : LOG_INFO, LD_CIRC,
                "Entry guard '%s' (%s) %s. (Version=%s.) Replacing it.",
                entry->nickname, dbuf, msg, ver?escaped(ver):"none");
            control_event_guard(entry->nickname, entry->identity, "DROPPED");
            entry_guard_free(entry);
            smartlist_del_keeporder(guards, i--);
            log_guards(LOG_INFO, guards);
            changed = 1;
        }
    }

    return changed ? 1 : 0;
}

/** How long (in seconds) do we allow an entry guard to be nonfunctional,
 * unlisted, excluded, or otherwise nonusable before we give up on it? */
#define ENTRY_GUARD_REMOVE_AFTER (30*24*60*60)

/** Remove all entry guards that have been down or unlisted for so
 * long that we don't think they'll come up again. Return 1 if we
 * removed any, or 0 if we did nothing. */
int
remove_dead_guards(time_t now, smartlist_t* guards)
{
    log_warn(LD_CIRC, "Will remove DEAD guards");

    char dbuf[HEX_DIGEST_LEN+1];
    char tbuf[ISO_TIME_LEN+1];
    int i;
    int changed = 0;

    for (i = 0; i < smartlist_len(guards); ) {
        entry_guard_t *entry = smartlist_get(guards, i);
        if (entry->bad_since &&
            ! entry->path_bias_disabled &&
            entry->bad_since + ENTRY_GUARD_REMOVE_AFTER < now) {

            base16_encode(dbuf, sizeof(dbuf), entry->identity, DIGEST_LEN);
            format_local_iso_time(tbuf, entry->bad_since);
            log_info(LD_CIRC, "Entry guard '%s' (%s) has been down or unlisted"
                " since %s local time; removing.",
                entry->nickname, dbuf, tbuf);
            control_event_guard(entry->nickname, entry->identity, "DROPPED");
            entry_guard_free(entry);
            smartlist_del_keeporder(guards, i);
            log_guards(LOG_INFO, guards);
            changed = 1;
        } else
            ++i;
    }
    return changed ? 1 : 0;
}

