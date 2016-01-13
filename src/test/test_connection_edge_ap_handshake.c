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

static entry_connection_t *
init_tests(void)
{
  addressmap_init();
  MOCK(connection_ap_handshake_rewrite, connection_ap_handshake_rewrite_mock);
  MOCK(connection_mark_unattached_ap_, connection_mark_unattached_ap_mock);
  return entry_connection_new(CONN_TYPE_AP, AF_INET);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_with_answer(void *data)
{
  entry_connection_t *conn = init_tests();
  (void) data;

  mock_should_close = 1;
  mock_end_reason = END_STREAM_REASON_DONE;

  int res = connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);
  tt_int_op(res, OP_EQ, 0);

  done:
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_with_error(void *data)
{
  entry_connection_t *conn = init_tests();
  (void) data;

  mock_should_close = 1;
  mock_end_reason = END_STREAM_REASON_MISC;

  int res = connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);

  tt_int_op(res, OP_EQ, -1);

  done:
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
}

#define SET_SOCKS_ADDRESS(socks, dest) \
  strlcpy(socks->address, dest, sizeof(socks->address));

static or_options_t *options_mock = NULL;
static const or_options_t *
get_options_mock(void)
{
  tor_assert(options_mock);
  return options_mock;
}

inline static void
init_mock_options(void)
{
  options_mock = tor_malloc_zero(sizeof(options_mock));
  options_mock->ExcludeExitNodes = NULL;
}

inline static void
destroy_mock_options(void)
{
  tor_free(options_mock);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_when_hostname_is_bogus(void *data)
{
  entry_connection_t *conn = init_tests();
  (void) data;

  MOCK(get_options, get_options_mock);

  init_mock_options();

  options_mock->SafeLogging_ = SAFELOG_SCRUB_NONE;
  mock_should_close = 0;
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
    destroy_mock_options();
    teardown_capture_of_logs(prev_log);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_when_hostname_is_unallowed_exit(void *data)
{
  entry_connection_t *conn = init_tests();
  (void) data;

  MOCK(get_options, get_options_mock);
  init_mock_options();

  options_mock->SafeLogging_ = SAFELOG_SCRUB_NONE;
  options_mock->AllowDotExit = 0;
  mock_should_close = 0;
  mock_exit_source = ADDRMAPSRC_AUTOMAP;
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
    destroy_mock_options();
    teardown_capture_of_logs(prev_log);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_when_hostname_is_dns_exit(void *data)
{
  entry_connection_t *conn = init_tests();
  (void) data;

  MOCK(get_options, get_options_mock);

  init_mock_options();

  options_mock->SafeLogging_ = SAFELOG_SCRUB_NONE;
  mock_should_close = 0;
  mock_exit_source = ADDRMAPSRC_DNS;
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
    destroy_mock_options();
    teardown_capture_of_logs(prev_log);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_when_exit_address_is_not_remapped(void *data)
{
  entry_connection_t *conn = init_tests();
  (void) data;

  MOCK(get_options, get_options_mock);

  init_mock_options();

  options_mock->SafeLogging_ = SAFELOG_SCRUB_NONE;
  mock_should_close = 0;
  mock_exit_source = ADDRMAPSRC_NONE;
  SET_SOCKS_ADDRESS(conn->socks_request, "www.notremapped.exit");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;
  options_mock->AllowDotExit = 0;

  int prev_log = setup_capture_of_logs(LOG_INFO);
  int res = connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);

  tt_int_op(unattachment_reason_spy, OP_EQ, END_STREAM_REASON_TORPROTOCOL);
  tt_int_op(res, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(-1), OP_EQ, "Address 'www.notremapped.exit', with impossible source for the .exit part. Refusing.\n");

  done:
    UNMOCK(get_options);
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
    destroy_mock_options();
    teardown_capture_of_logs(prev_log);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_when_exit_address_is_malformed(void *data)
{
  entry_connection_t *conn = init_tests();
  (void) data;

  MOCK(get_options, get_options_mock);

  init_mock_options();

  options_mock->SafeLogging_ = SAFELOG_SCRUB_NONE;
  mock_should_close = 0;
  mock_exit_source = ADDRMAPSRC_NONE;
  SET_SOCKS_ADDRESS(conn->socks_request, "malformed..exit");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;
  options_mock->AllowDotExit = 1;

  int prev_log = setup_capture_of_logs(LOG_INFO);
  int res = connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);

  tt_int_op(unattachment_reason_spy, OP_EQ, END_STREAM_REASON_TORPROTOCOL);
  tt_int_op(res, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(-1), OP_EQ, "Malformed exit address 'malformed..exit'. Refusing.\n");

  done:
    UNMOCK(get_options);
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
    destroy_mock_options();
    teardown_capture_of_logs(prev_log);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_for_unrecognized_exit_address(void *data)
{
  entry_connection_t *conn = init_tests();
  (void) data;

  MOCK(get_options, get_options_mock);

  init_mock_options();

  mock_should_close = 0;
  mock_exit_source = ADDRMAPSRC_NONE;
  SET_SOCKS_ADDRESS(conn->socks_request, "www.wellformed.exit");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;
  options_mock->AllowDotExit = 1;
  options_mock->SafeLogging_ = SAFELOG_SCRUB_NONE;

  int prev_log = setup_capture_of_logs(LOG_INFO);
  int res = connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);

  tt_int_op(unattachment_reason_spy, OP_EQ, END_STREAM_REASON_TORPROTOCOL);
  tt_int_op(res, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(-1), OP_EQ, "Unrecognized relay in exit address 'www.exit'. Refusing.\n");

  done:
    UNMOCK(get_options);
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
    destroy_mock_options();
    teardown_capture_of_logs(prev_log);
}

static node_t *exit_node_mock = NULL;
static const node_t *
node_get_by_nickname_mock(const char *nickname, int warn)
{
  tor_assert(nickname);
  tor_assert(warn);
  return exit_node_mock;
}

static void
init_exit_node_mock(void)
{
  exit_node_mock = tor_malloc_zero(sizeof(node_t));
  exit_node_mock->rs = tor_malloc_zero(sizeof(routerstatus_t));
}

static void
destroy_exit_node_mock(void)
{
  tor_free(exit_node_mock->rs);
  tor_free(exit_node_mock);
}

static routerset_t *excluded_nodes = NULL;

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_for_excluded_exit(void *data)
{
  entry_connection_t *conn = init_tests();
  (void) data;

  MOCK(get_options, get_options_mock);
  MOCK(node_get_by_nickname, node_get_by_nickname_mock);

  init_exit_node_mock();
  init_mock_options();

  mock_should_close = 0;
  mock_exit_source = ADDRMAPSRC_NONE;
  SET_SOCKS_ADDRESS(conn->socks_request, "www.wellformed.exit");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;
  strlcpy(exit_node_mock->rs->nickname, "wellformed", MAX_NICKNAME_LEN+1);

  options_mock->AllowDotExit = 1;
  options_mock->StrictNodes = 0;
  options_mock->SafeLogging_ = SAFELOG_SCRUB_NONE;

  excluded_nodes = routerset_new();
  smartlist_add(excluded_nodes->list, tor_strdup("wellformed"));
  strmap_set(excluded_nodes->names, tor_strdup("wellformed"), exit_node_mock);
  options_mock->ExcludeExitNodes = excluded_nodes;

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
    destroy_mock_options();
    destroy_exit_node_mock();
    tor_free(excluded_nodes);
    teardown_capture_of_logs(prev_log);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_to_port0(void *data)
{
  entry_connection_t *conn = init_tests();
  (void) data;

  MOCK(get_options, get_options_mock);
  MOCK(node_get_by_nickname, node_get_by_nickname_mock);

  init_mock_options();
  init_exit_node_mock();

  mock_should_close = 0;
  mock_exit_source = ADDRMAPSRC_NONE;
  SET_SOCKS_ADDRESS(conn->socks_request, "www.wellformed.exit");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;
  options_mock->AllowDotExit = 1;
  options_mock->ExcludeExitNodes = routerset_new();
  options_mock->ExcludeExitNodesUnion_ = routerset_new();
  options_mock->SafeLogging_ = SAFELOG_SCRUB_NONE;

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
    destroy_mock_options();
    destroy_exit_node_mock();
    teardown_capture_of_logs(prev_log);
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
