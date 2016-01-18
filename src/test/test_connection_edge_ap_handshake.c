/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CONNECTION_PRIVATE
#define CONNECTION_EDGE_PRIVATE
#define ROUTERSET_PRIVATE
#define LOG_PRIVATE

#include "or.h"
#include "config.h"
#include "connection.h"
#include "connection_edge.h"
#include "connection_or.h"
#include "addressmap.h"
#include "nodelist.h"
#include "routerset.h"
#include "util.h"
#include "torlog.h"
#include "test.h"
#include "log_test_helpers.h"

#define NS_MODULE conn_edge_ap_handshake

static int mock_should_close = 0;
static int mock_end_reason = 0;
static addressmap_entry_source_t mock_exit_source;

static void
connection_ap_handshake_rewrite_mock(entry_connection_t *conn,
                                       rewrite_result_t *result)
{
  tor_assert(result);
  result->should_close = mock_should_close;
  result->end_reason = mock_end_reason;
  memcpy(&result->exit_source, &mock_exit_source, sizeof(addressmap_entry_source_t));
  (void) conn;
}

static int unattachment_reason_spy;
static void
connection_mark_unattached_ap_mock(entry_connection_t *conn,
                                     int reason,
                                     int line,
                                     const char *file)
{
  tor_assert(reason);
  unattachment_reason_spy = reason;
  (void) conn;
  (void) line;
  (void) file;
}

static char mock_safe_logging;
static int mock_allow_dot_exit = 0;
static int mock_strict_nodes = 0;
static routerset_t *mock_exclude_exit_nodes;
static routerset_t *mock_exclude_exit_nodes_union;

static or_options_t* options_mock = NULL;

static const or_options_t *
get_options_mock(void)
{
  return options_mock;
}

static void
free_options_mock(void)
{
  tor_free(options_mock);
}

static void
init_options_mock(void)
{
  printf("\nit did start the options... mock_allow_dot_exit = %d", mock_allow_dot_exit);
  options_mock = tor_malloc_zero(sizeof(or_options_t));
  options_mock->ExcludeExitNodes = NULL;
  options_mock->SafeLogging_ = mock_safe_logging;
  options_mock->AllowDotExit = mock_allow_dot_exit;
  options_mock->StrictNodes = mock_strict_nodes;
  options_mock->ExcludeExitNodes = mock_exclude_exit_nodes;
  options_mock->ExcludeExitNodesUnion_ = mock_exclude_exit_nodes_union;
}

static entry_connection_t *
init_tests(void)
{
  addressmap_init();
  init_options_mock();
  MOCK(connection_ap_handshake_rewrite, connection_ap_handshake_rewrite_mock);
  MOCK(connection_mark_unattached_ap_, connection_mark_unattached_ap_mock);
  MOCK(get_options, get_options_mock);
  return entry_connection_new(CONN_TYPE_AP, AF_INET);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_with_answer(void *data)
{
  mock_should_close = 1;
  mock_end_reason = END_STREAM_REASON_DONE;
  entry_connection_t *conn = init_tests();
  (void) data;

  int res = connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);
  tt_int_op(res, OP_EQ, 0);

  done:
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
    connection_free_(ENTRY_TO_CONN(conn));
    addressmap_free_all();
    free_options_mock();
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_with_error(void *data)
{
  mock_should_close = 1;
  mock_end_reason = END_STREAM_REASON_MISC;
  entry_connection_t *conn = init_tests();
  (void) data;

  int res = connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);

  tt_int_op(res, OP_EQ, -1);

  done:
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
    connection_free_(ENTRY_TO_CONN(conn));
    addressmap_free_all();
    free_options_mock();
}

#define SET_SOCKS_ADDRESS(socks, dest) \
  strlcpy(socks->address, dest, sizeof(socks->address));

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_when_hostname_is_bogus(void *data)
{
  mock_safe_logging = SAFELOG_SCRUB_NONE;
  mock_should_close = 0;
  entry_connection_t *conn = init_tests();
  (void) data;

  SET_SOCKS_ADDRESS(conn->socks_request, "www.bogus.onion");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;

  int prev_log = setup_capture_of_logs(LOG_INFO);
  int res = connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);

  tt_int_op(unattachment_reason_spy, OP_EQ, END_STREAM_REASON_TORPROTOCOL);
  tt_int_op(res, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(-1), OP_EQ, "Invalid onion hostname bogus; rejecting\n");

  done:
    UNMOCK(get_options);
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
    connection_free_(ENTRY_TO_CONN(conn));
    free_options_mock();
    addressmap_free_all();
    teardown_capture_of_logs(prev_log);
    escaped(NULL);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_when_hostname_is_unallowed_exit(void *data)
{
  mock_safe_logging = SAFELOG_SCRUB_NONE;
  mock_allow_dot_exit = 0;
  mock_should_close = 0;
  mock_exit_source = ADDRMAPSRC_AUTOMAP;
  entry_connection_t *conn = init_tests();
  (void) data;

  SET_SOCKS_ADDRESS(conn->socks_request, "www.notgood.exit");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;

  int prev_log = setup_capture_of_logs(LOG_INFO);
  int res = connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);

  tt_int_op(unattachment_reason_spy, OP_EQ, END_STREAM_REASON_TORPROTOCOL);
  tt_int_op(res, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(-1), OP_EQ, "Stale automapped address for 'www.notgood.exit', with AllowDotExit disabled. Refusing.\n");

  done:
    UNMOCK(get_options);
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
    connection_free_(ENTRY_TO_CONN(conn));
    free_options_mock();
    addressmap_free_all();
    teardown_capture_of_logs(prev_log);
    escaped(NULL);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_when_hostname_is_dns_exit(void *data)
{
  mock_safe_logging = SAFELOG_SCRUB_NONE;
  mock_should_close = 0;
  mock_exit_source = ADDRMAPSRC_DNS;
  entry_connection_t *conn = init_tests();
  (void) data;

  SET_SOCKS_ADDRESS(conn->socks_request, "www.dns.exit");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;

  int prev_log = setup_capture_of_logs(LOG_INFO);
  int res = connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);

  tt_int_op(unattachment_reason_spy, OP_EQ, END_STREAM_REASON_TORPROTOCOL);
  tt_int_op(res, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(-1), OP_EQ, "Address 'www.dns.exit', with impossible source for the .exit part. Refusing.\n");

  done:
    UNMOCK(get_options);
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
    connection_free_(ENTRY_TO_CONN(conn));
    free_options_mock();
    addressmap_free_all();
    teardown_capture_of_logs(prev_log);
    escaped(NULL);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_when_exit_address_is_not_remapped(void *data)
{
  mock_safe_logging = SAFELOG_SCRUB_NONE;
  mock_allow_dot_exit = 0;
  mock_should_close = 0;
  mock_exit_source = ADDRMAPSRC_NONE;
  entry_connection_t *conn = init_tests();
  (void) data;

  SET_SOCKS_ADDRESS(conn->socks_request, "www.notremapped.exit");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;

  int prev_log = setup_capture_of_logs(LOG_INFO);
  int res = connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);

  tt_int_op(unattachment_reason_spy, OP_EQ, END_STREAM_REASON_TORPROTOCOL);
  tt_int_op(res, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(-1), OP_EQ, "Address 'www.notremapped.exit', with impossible source for the .exit part. Refusing.\n");

  done:
    UNMOCK(get_options);
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
    connection_free_(ENTRY_TO_CONN(conn));
    free_options_mock();
    addressmap_free_all();
    teardown_capture_of_logs(prev_log);
    escaped(NULL);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_when_exit_address_is_malformed(void *data)
{
  mock_safe_logging = SAFELOG_SCRUB_NONE;
  mock_allow_dot_exit = 1;
  mock_should_close = 0;
  mock_exit_source = ADDRMAPSRC_NONE;
  entry_connection_t *conn = init_tests();
  (void) data;

  SET_SOCKS_ADDRESS(conn->socks_request, "malformed..exit");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;

  int prev_log = setup_capture_of_logs(LOG_INFO);
  int res = connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);

  tt_int_op(unattachment_reason_spy, OP_EQ, END_STREAM_REASON_TORPROTOCOL);
  tt_int_op(res, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(-1), OP_EQ, "Malformed exit address 'malformed..exit'. Refusing.\n");

  done:
    UNMOCK(get_options);
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
    connection_free_(ENTRY_TO_CONN(conn));
    free_options_mock();
    addressmap_free_all();
    teardown_capture_of_logs(prev_log);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_for_unrecognized_exit_address(void *data)
{
  mock_safe_logging = SAFELOG_SCRUB_NONE;
  mock_allow_dot_exit = 1;
  mock_should_close = 0;
  mock_exit_source = ADDRMAPSRC_NONE;
  entry_connection_t *conn = init_tests();
  (void) data;

  SET_SOCKS_ADDRESS(conn->socks_request, "www.wellformed.exit");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;

  int prev_log = setup_capture_of_logs(LOG_INFO);
  int res = connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);

  tt_int_op(unattachment_reason_spy, OP_EQ, END_STREAM_REASON_TORPROTOCOL);
  tt_int_op(res, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(-1), OP_EQ, "Unrecognized relay in exit address 'www.exit'. Refusing.\n");

  done:
    UNMOCK(get_options);
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
    connection_free_(ENTRY_TO_CONN(conn));
    free_options_mock();
    addressmap_free_all();
    teardown_capture_of_logs(prev_log);
    escaped(NULL);
}

static node_t *exit_node_mock = NULL;
static void
destroy_exit_node_mock(void)
{
  if(!exit_node_mock)
    return;
  tor_free(exit_node_mock->rs);
  tor_free(exit_node_mock);
}

static char mock_nickname[MAX_NICKNAME_LEN+1];
static const node_t *
node_get_by_nickname_mock(const char *nickname, int warn)
{
  tor_assert(nickname);
  tor_assert(warn);
  exit_node_mock = tor_malloc_zero(sizeof(node_t));
  exit_node_mock->rs = tor_malloc_zero(sizeof(routerstatus_t));
  strlcpy(exit_node_mock->rs->nickname, mock_nickname, MAX_NICKNAME_LEN+1);
  return exit_node_mock;
}

static void
init_exit_node_mock(void)
{
  MOCK(node_get_by_nickname, node_get_by_nickname_mock);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_for_excluded_exit(void *data)
{
  mock_should_close = 0;
  mock_exit_source = ADDRMAPSRC_NONE;
  mock_safe_logging = SAFELOG_SCRUB_NONE;
  mock_allow_dot_exit = 1;
  mock_strict_nodes = 0;
  mock_exclude_exit_nodes = routerset_new();
  entry_connection_t *conn = init_tests();
  (void) data;

  init_exit_node_mock();

  SET_SOCKS_ADDRESS(conn->socks_request, "www.wellformed.exit");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;
  strlcpy(mock_nickname, "wellformed", MAX_NICKNAME_LEN+1);
  routerset_t *excluded_nodes = excluded_nodes = routerset_new();
  smartlist_add(excluded_nodes->list, tor_strdup("wellformed"));
  strmap_set(excluded_nodes->names, tor_strdup("wellformed"), exit_node_mock);

  int prev_log = setup_capture_of_logs(LOG_INFO);
  int res = connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);

  tt_int_op(unattachment_reason_spy, OP_EQ, END_STREAM_REASON_TORPROTOCOL);
  tt_int_op(res, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(-1), OP_EQ, "Excluded relay in exit address 'www.exit'. Refusing.\n");

  done:
    UNMOCK(get_options);
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
    UNMOCK(node_get_by_nickname);
    connection_free_(ENTRY_TO_CONN(conn));
    free_options_mock();
    routerset_free(mock_exclude_exit_nodes);
    routerset_free(excluded_nodes);
    destroy_exit_node_mock();
    addressmap_free_all();
    teardown_capture_of_logs(prev_log);
    escaped(NULL);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_to_port0(void *data)
{
  mock_should_close = 0;
  mock_exit_source = ADDRMAPSRC_NONE;
  mock_safe_logging = SAFELOG_SCRUB_NONE;
  mock_allow_dot_exit = 1;
  mock_exclude_exit_nodes = routerset_new();
  mock_exclude_exit_nodes_union = routerset_new();
  entry_connection_t *conn = init_tests();
  (void) data;

  init_exit_node_mock();

  SET_SOCKS_ADDRESS(conn->socks_request, "www.wellformed.exit");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;

  int prev_log = setup_capture_of_logs(LOG_INFO);
  int res = connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);

  tt_int_op(unattachment_reason_spy, OP_EQ, END_STREAM_REASON_TORPROTOCOL);
  tt_int_op(res, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(-1), OP_EQ, "Excluded relay in exit address 'www.exit'. Refusing.\n");
  
done:
    UNMOCK(get_options);
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
    UNMOCK(node_get_by_nickname);
    connection_free_(ENTRY_TO_CONN(conn));
    free_options_mock();
    routerset_free(mock_exclude_exit_nodes_union);
    routerset_free(mock_exclude_exit_nodes);
    destroy_exit_node_mock();
    addressmap_free_all();
    teardown_capture_of_logs(prev_log);
    escaped(NULL); // stop memory leak of last escaped value
}

#define CONN_EDGE_AP_HANDSHAKE(name,flags)                              \
  { #name, test_conn_edge_ap_handshake_##name, (flags), NULL, NULL }

struct testcase_t conn_edge_ap_handshake_tests[] =
{
  CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_with_answer, TT_FORK),
  CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_with_error, TT_FORK),
  CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_when_hostname_is_bogus, TT_FORK),
  CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_when_hostname_is_unallowed_exit, TT_FORK),
  CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_when_hostname_is_dns_exit, TT_FORK),
  CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_when_exit_address_is_not_remapped, TT_FORK),
  CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_when_exit_address_is_malformed, TT_FORK),
  CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_for_unrecognized_exit_address, TT_FORK),
  CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_for_excluded_exit, TT_FORK),
  CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_to_port0, TT_FORK),
  END_OF_TESTCASES
};
