/* Copyright (c) 2014, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include <math.h>
#include <time.h>

#define DIRVOTE_PRIVATE
#define NETWORKSTATUS_PRIVATE
#define ROUTERLIST_PRIVATE
#define TOR_UNIT_TESTING
#include "or.h"
#include "config.h"
#include "container.h"
#include "directory.h"
#include "dirvote.h"
#include "networkstatus.h"
#include "nodelist.h"
#include "policies.h"
#include "routerlist.h"
#include "routerparse.h"
#include "test.h"
#include "test_dir_common.h"

extern const char AUTHORITY_CERT_1[];
extern const char AUTHORITY_SIGNKEY_1[];
extern const char AUTHORITY_CERT_2[];
extern const char AUTHORITY_SIGNKEY_2[];
extern const char AUTHORITY_CERT_3[];
extern const char AUTHORITY_SIGNKEY_3[];

void construct_consensus(const char **consensus_text_md);

/* 4 digests + 3 sep + pre + post + NULL */
static char output[4*BASE64_DIGEST256_LEN+3+2+2+1];

static void
mock_get_from_dirserver(uint8_t dir_purpose, uint8_t router_purpose,
                        const char *resource, int pds_flags,
                        download_want_authority_t want_authority)
{
  (void)dir_purpose;
  (void)router_purpose;
  (void)pds_flags;
  (void)want_authority;
  tt_assert(resource);
  strlcpy(output, resource, sizeof(output));
 done:
  ;
}

static void
test_routerlist_initiate_descriptor_downloads(void *arg)
{
  const char *prose = "unhurried and wise, we perceive.";
  smartlist_t *digests = smartlist_new();
  (void)arg;

  for (int i = 0; i < 20; i++) {
    smartlist_add(digests, (char*)prose);
  }

  MOCK(directory_get_from_dirserver, mock_get_from_dirserver);
  initiate_descriptor_downloads(NULL, DIR_PURPOSE_FETCH_MICRODESC,
                                digests, 3, 7, 0);
  UNMOCK(directory_get_from_dirserver);

  tt_str_op(output, OP_EQ, "d/"
            "dW5odXJyaWVkIGFuZCB3aXNlLCB3ZSBwZXJjZWl2ZS4-"
            "dW5odXJyaWVkIGFuZCB3aXNlLCB3ZSBwZXJjZWl2ZS4-"
            "dW5odXJyaWVkIGFuZCB3aXNlLCB3ZSBwZXJjZWl2ZS4-"
            "dW5odXJyaWVkIGFuZCB3aXNlLCB3ZSBwZXJjZWl2ZS4"
            ".z");

 done:
  smartlist_free(digests);
}

static int count = 0;

static void
mock_initiate_descriptor_downloads(const routerstatus_t *source,
                                   int purpose, smartlist_t *digests,
                                   int lo, int hi, int pds_flags)
{
  (void)source;
  (void)purpose;
  (void)digests;
  (void)pds_flags;
  (void)hi;
  (void)lo;
  count += 1;
}

static void
test_routerlist_launch_descriptor_downloads(void *arg)
{
  smartlist_t *downloadable = smartlist_new();
  time_t now = time(NULL);
  char *cp;
  (void)arg;

  for (int i = 0; i < 100; i++) {
    cp = tor_malloc(DIGEST256_LEN);
    tt_assert(cp);
    crypto_rand(cp, DIGEST256_LEN);
    smartlist_add(downloadable, cp);
  }

  MOCK(initiate_descriptor_downloads, mock_initiate_descriptor_downloads);
  launch_descriptor_downloads(DIR_PURPOSE_FETCH_MICRODESC, downloadable,
                              NULL, now);
  tt_int_op(3, ==, count);
  UNMOCK(initiate_descriptor_downloads);

 done:
  SMARTLIST_FOREACH(downloadable, char *, cp1, tor_free(cp1));
  smartlist_free(downloadable);
}

void
construct_consensus(const char **consensus_text_md)
{
  networkstatus_t *vote = NULL;
  networkstatus_t *v1 = NULL, *v2 = NULL, *v3 = NULL;
  networkstatus_voter_info_t *voter = NULL;
  authority_cert_t *cert1=NULL, *cert2=NULL, *cert3=NULL;
  crypto_pk_t *sign_skey_1=NULL, *sign_skey_2=NULL, *sign_skey_3=NULL;
  crypto_pk_t *sign_skey_leg=NULL;
  time_t now = time(NULL);
  smartlist_t *votes = NULL;
  addr_policy_t *pol1 = NULL, *pol2 = NULL, *pol3 = NULL;
  int n_vrs;

  tt_assert(!dir_common_authority_pk_init(&cert1, &cert2, &cert3,
                                          &sign_skey_1, &sign_skey_2,
                                          &sign_skey_3));
  sign_skey_leg = pk_generate(4);

  dir_common_construct_vote_1(&vote, cert1, sign_skey_1,
                              &dir_common_gen_routerstatus_for_v3ns,
                              &v1, &n_vrs, now, 1);

  tt_assert(v1);
  tt_int_op(n_vrs, ==, 4);
  tt_int_op(smartlist_len(v1->routerstatus_list), ==, 4);

  dir_common_construct_vote_2(&vote, cert2, sign_skey_2,
                              &dir_common_gen_routerstatus_for_v3ns,
                              &v2, &n_vrs, now, 1);

  tt_assert(v2);
  tt_int_op(n_vrs, ==, 4);
  tt_int_op(smartlist_len(v2->routerstatus_list), ==, 4);

  dir_common_construct_vote_3(&vote, cert3, sign_skey_3,
                              &dir_common_gen_routerstatus_for_v3ns,
                              &v3, &n_vrs, now, 1);

  tt_assert(v3);
  tt_int_op(n_vrs, ==, 4);
  tt_int_op(smartlist_len(v3->routerstatus_list), ==, 4);

  votes = smartlist_new();
  smartlist_add(votes, v1);
  smartlist_add(votes, v2);
  smartlist_add(votes, v3);

  *consensus_text_md = networkstatus_compute_consensus(votes, 3,
                                                   cert1->identity_key,
                                                   sign_skey_1,
                                                   "AAAAAAAAAAAAAAAAAAAA",
                                                   sign_skey_leg,
                                                   FLAV_MICRODESC);

  tt_assert(*consensus_text_md);

 done:
  if (vote)
    tor_free(vote);
  if (voter)
    tor_free(voter);
  if (pol1)
    tor_free(pol1);
  if (pol2)
    tor_free(pol2);
  if (pol3)
    tor_free(pol3);
}

static void
test_router_pick_directory_server_impl(void *arg)
{
  (void)arg;

  networkstatus_t *con_md = NULL;
  const char *consensus_text_md = NULL;
  int flags = PDS_IGNORE_FASCISTFIREWALL|PDS_RETRY_IF_NO_SERVERS;
  or_options_t *options = get_options_mutable();
  const routerstatus_t *rs = NULL;
  options->UseMicrodescriptors = 1;
  char *router1_id = NULL, *router2_id = NULL, *router3_id = NULL;
  node_t *node_router1 = NULL, *node_router2 = NULL, *node_router3 = NULL;
  config_line_t *policy_line = NULL;
  time_t now = time(NULL);
  int tmp_dirport1, tmp_dirport3;

  (void)arg;

  /* No consensus available, fail early */
  rs = router_pick_directory_server_impl(V3_DIRINFO, (const int) 0, NULL);
  tt_assert(rs == NULL);

  construct_consensus(&consensus_text_md);
  tt_assert(consensus_text_md);
  con_md = networkstatus_parse_vote_from_string(consensus_text_md, NULL,
                                                NS_TYPE_CONSENSUS);
  tt_assert(con_md);
  tt_int_op(con_md->flavor,==, FLAV_MICRODESC);
  tt_assert(con_md->routerstatus_list);
  tt_int_op(smartlist_len(con_md->routerstatus_list), ==, 3);
  tt_assert(!networkstatus_set_current_consensus_from_ns(con_md,
                                                 "microdesc"));
  nodelist_set_consensus(con_md);
  nodelist_assert_ok();

  rs = router_pick_directory_server_impl(V3_DIRINFO, flags, NULL);
  /* We should not fail now we have a consensus and routerstatus_list
   * and nodelist are populated. */
  tt_assert(rs != NULL);

  /* Manipulate the nodes so we get the dir server we expect */
  router1_id = tor_malloc(DIGEST_LEN);
  memset(router1_id, TEST_DIR_ROUTER_ID_1, DIGEST_LEN);
  router2_id = tor_malloc(DIGEST_LEN);
  memset(router2_id, TEST_DIR_ROUTER_ID_2, DIGEST_LEN);
  router3_id = tor_malloc(DIGEST_LEN);
  memset(router3_id, TEST_DIR_ROUTER_ID_3, DIGEST_LEN);

  node_router1 = node_get_mutable_by_id(router1_id);
  node_router2 = node_get_mutable_by_id(router2_id);
  node_router3 = node_get_mutable_by_id(router3_id);

  node_router1->is_possible_guard = 1;

  node_router1->is_running = 0;
  node_router3->is_running = 0;
  rs = router_pick_directory_server_impl(V3_DIRINFO, flags, NULL);
  tt_assert(rs != NULL);
  tt_assert(tor_memeq(rs->identity_digest, router2_id, DIGEST_LEN));
  rs = NULL;
  node_router1->is_running = 1;
  node_router3->is_running = 1;

  node_router1->rs->is_v2_dir = 0;
  node_router3->rs->is_v2_dir = 0;
  tmp_dirport1 = node_router1->rs->dir_port;
  tmp_dirport3 = node_router3->rs->dir_port;
  node_router1->rs->dir_port = 0;
  node_router3->rs->dir_port = 0;
  rs = router_pick_directory_server_impl(V3_DIRINFO, flags, NULL);
  tt_assert(rs != NULL);
  tt_assert(tor_memeq(rs->identity_digest, router2_id, DIGEST_LEN));
  rs = NULL;
  node_router1->rs->is_v2_dir = 1;
  node_router3->rs->is_v2_dir = 1;
  node_router1->rs->dir_port = tmp_dirport1;
  node_router3->rs->dir_port = tmp_dirport3;

  node_router1->is_valid = 0;
  node_router3->is_valid = 0;
  rs = router_pick_directory_server_impl(V3_DIRINFO, flags, NULL);
  tt_assert(rs != NULL);
  tt_assert(tor_memeq(rs->identity_digest, router2_id, DIGEST_LEN));
  rs = NULL;
  node_router1->is_valid = 1;
  node_router3->is_valid = 1;

  flags |= PDS_FOR_GUARD;
  node_router1->using_as_guard = 1;
  node_router2->using_as_guard = 1;
  node_router3->using_as_guard = 1;
  rs = router_pick_directory_server_impl(V3_DIRINFO, flags, NULL);
  tt_assert(rs == NULL);
  node_router1->using_as_guard = 0;
  rs = router_pick_directory_server_impl(V3_DIRINFO, flags, NULL);
  tt_assert(rs != NULL);
  tt_assert(tor_memeq(rs->identity_digest, router1_id, DIGEST_LEN));
  rs = NULL;
  node_router2->using_as_guard = 0;
  node_router3->using_as_guard = 0;

  /* One not valid, one guard. This should leave one remaining */
  node_router1->is_valid = 0;
  node_router2->using_as_guard = 1;
  rs = router_pick_directory_server_impl(V3_DIRINFO, flags, NULL);
  tt_assert(rs != NULL);
  tt_assert(tor_memeq(rs->identity_digest, router3_id, DIGEST_LEN));
  rs = NULL;
  node_router1->is_valid = 1;
  node_router2->using_as_guard = 0;

  /* Manipulate overloaded */

  node_router2->rs->last_dir_503_at = now;
  node_router3->rs->last_dir_503_at = now;
  rs = router_pick_directory_server_impl(V3_DIRINFO, flags, NULL);
  tt_assert(rs != NULL);
  tt_assert(tor_memeq(rs->identity_digest, router1_id, DIGEST_LEN));
  node_router2->rs->last_dir_503_at = 0;
  node_router3->rs->last_dir_503_at = 0;

  /* Set a Fascist firewall */
  flags &= ! PDS_IGNORE_FASCISTFIREWALL;
  policy_line = tor_malloc_zero(sizeof(config_line_t));
  policy_line->key = tor_strdup("ReachableORAddresses");
  policy_line->value = tor_strdup("accept *:442, reject *:*");
  options->ReachableORAddresses = policy_line;
  policies_parse_from_options(options);

  node_router1->rs->or_port = 444;
  node_router2->rs->or_port = 443;
  node_router3->rs->or_port = 442;
  rs = router_pick_directory_server_impl(V3_DIRINFO, flags, NULL);
  tt_assert(rs != NULL);
  tt_assert(tor_memeq(rs->identity_digest, router3_id, DIGEST_LEN));
  node_router1->rs->or_port = 442;
  node_router2->rs->or_port = 443;
  node_router3->rs->or_port = 444;
  rs = router_pick_directory_server_impl(V3_DIRINFO, flags, NULL);
  tt_assert(rs != NULL);
  tt_assert(tor_memeq(rs->identity_digest, router1_id, DIGEST_LEN));

  /* Fascist firewall and overloaded */
  node_router1->rs->or_port = 442;
  node_router2->rs->or_port = 443;
  node_router3->rs->or_port = 442;
  node_router3->rs->last_dir_503_at = now;
  rs = router_pick_directory_server_impl(V3_DIRINFO, flags, NULL);
  tt_assert(rs != NULL);
  tt_assert(tor_memeq(rs->identity_digest, router1_id, DIGEST_LEN));
  node_router3->rs->last_dir_503_at = 0;

  /* Fascists against OR and Dir */
  policy_line = tor_malloc_zero(sizeof(config_line_t));
  policy_line->key = tor_strdup("ReachableAddresses");
  policy_line->value = tor_strdup("accept *:80, reject *:*");
  options->ReachableDirAddresses = policy_line;
  policies_parse_from_options(options);
  node_router1->rs->or_port = 442;
  node_router2->rs->or_port = 441;
  node_router3->rs->or_port = 443;
  node_router1->rs->dir_port = 80;
  node_router2->rs->dir_port = 80;
  node_router3->rs->dir_port = 81;
  node_router1->rs->last_dir_503_at = now;
  rs = router_pick_directory_server_impl(V3_DIRINFO, flags, NULL);
  tt_assert(rs != NULL);
  tt_assert(tor_memeq(rs->identity_digest, router1_id, DIGEST_LEN));
  node_router1->rs->last_dir_503_at = 0;

 done:
  if (router1_id)
    tor_free(router1_id);
  if (router2_id)
    tor_free(router2_id);
  if (router3_id)
    tor_free(router3_id);
  if (options->ReachableORAddresses ||
      options->ReachableDirAddresses)
    policies_free_all();
}

#define NODE(name, flags) \
  { #name, test_routerlist_##name, (flags), NULL, NULL }
#define ROUTER(name,flags) \
  { #name, test_router_##name, (flags), NULL, NULL }

struct testcase_t routerlist_tests[] = {
  NODE(initiate_descriptor_downloads, 0),
  NODE(launch_descriptor_downloads, 0),
  ROUTER(pick_directory_server_impl, TT_FORK),
  END_OF_TESTCASES
};

