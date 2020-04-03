/*
 * Copyright (c) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//#include <stdlib.h>
//#include <net/net_context.h>

#include "tcp2.c"

/* #include <tcp2.h> */
/* #include <tcp2_priv.h> */
/* #include "tcp2_test.h" */

#include <ztest.h>

static struct net_context *context;
static struct tcp *conn, *peer;
static struct net_pkt *pkt_in, *pkt_out;
static struct tcphdr *th_in, *th_out;
struct net_buf *buf;
static u8_t data[] = { 1 };

static int tcp2_send(struct net_pkt *pkt);

void tcp2_test_setup_once(void)
{
	tcp_send_cb = tcp2_send;

	peer = k_calloc(1, sizeof(struct tcp));

	peer->dst = tcp_endpoint_new_from_string("192.0.2.1", 4242);
	peer->src = tcp_endpoint_new_from_string("192.0.2.2", 4242);
}

static void tcp2_test_setup(void)
{
	net_context_get(AF_INET, SOCK_STREAM, IPPROTO_TCP, &context);

	net_context_ref(context);

	conn = context->tcp;

	conn->src = tcp_endpoint_new_from_string("192.0.2.1", 4242);
	conn->dst = tcp_endpoint_new_from_string("192.0.2.2", 4242);

	pkt_in = tcp_pkt_make(peer, 0);
	th_in = th_get(pkt_in);
}

static void tcp2_test_teardown(void)
{
	while ((conn = (void *)sys_slist_get(&tp_conns))) {

		context = conn->context;

		tcp_dbg("context: %p", context);

		if (context->conn_handler) {
			net_conn_unregister(context->conn_handler);
			context->conn_handler = NULL;
		}

		net_context_unref(context);

		net_context_put(context);
	}

	context = NULL;
	conn = NULL;

	net_pkt_unref(pkt_in);
	pkt_in = NULL;

	if (pkt_out) {
		net_pkt_unref(pkt_out);
		pkt_out = NULL;
		th_out = NULL;
	}
}

int tcp2_send(struct net_pkt *pkt)
{
	tcp_dbg("%s", tcp_th(pkt));

	pkt_out = pkt;

	th_out = th_get(pkt);

	return EXIT_SUCCESS;
}

static void tcp2_1(void)
{
	tcp_in(conn, pkt_in);

	zassert_equal(th_out->th_flags, SYN, "");
}

static void tcp2_2(void)
{
	th_in->th_flags = SYN;

	tcp_in(conn, pkt_in);

	zassert_equal(th_out->th_flags, SYN | ACK, "");
}

static void tcp2_3(void)
{
	tcp_conn_new(pkt_in);
}

static void tcp2_4(void)
{
	conn->state = TCP_ESTABLISHED;

	net_tcp_queue(conn, (void*)data, sizeof(data), NULL);
}

static void tcp2_5(void)
{
	tcp_input(pkt_in);
}

static void tcp2_6(void)
{
	net_tcp_put(context);
}

static void tcp2_7(void)
{
	conn->state = TCP_ESTABLISHED;

	th_in->th_flags = PSH;

	buf = tcp_nbuf_alloc(&tcp_nbufs, 1);

	tcp_chain(pkt_in, buf);

	tcp_adj(pkt_in, 1);

	tcp_in(conn, pkt_in);

	//tcp_recv(0, data, sizeof(data), 0);
}

static void tcp2_8(void)
{
	net_tcp_listen(context);

	net_tcp_queue_data(context, NULL);

	net_tcp_send_data(context, NULL, NULL);

	net_tcp_update_recv_wnd(context, 0);
}

static void tcp2_9(void)
{
	net_tcp_recv(context, NULL, NULL);
}

static void tcp2_10(void)
{
	net_tcp_accept(context, NULL, NULL);
}

static void tcp2_11(void)
{
	union tcp_endpoint *local =
		tcp_endpoint_new_from_string("192.0.2.1", 4242);
	union tcp_endpoint *remote =
		tcp_endpoint_new_from_string("192.0.2.1", 4242);

	net_tcp_connect(context, (void *)local, (void *)remote,
			0, 0, 0, NULL, NULL);

	k_free(local);
	k_free(remote);
}

static void tcp2_12(void)
{
	th_in->th_flags = SYN | URG;

	tcp_in(conn, pkt_in);
}

static void tcp2_13(void)
{
	net_tcp_recv(context, NULL, NULL);
}

void tcp2_accept_cb(struct net_context *new_context, struct sockaddr *remote,
			socklen_t sa_len, int status,
			void *user_data/*old context*/)
{
	tcp_dbg("");
}

static void tcp2_14(void)
{
	conn->accept_cb = tcp2_accept_cb;

	tcp_pkt_received(NULL, pkt_in, NULL, NULL, context);
}

static void tcp2_15(void)
{
	th_in->th_off = 1;

	tcp_in(conn, pkt_in);
}

static void tcp2_16(void)
{
	tcp_send(pkt_in);
}

static void tcp2_17(void)
{
	conn->state = TCP_ESTABLISHED;

	th_in->th_flags = PSH;

	sys_slist_append(&conn->send_queue, &pkt_in->next);

	tcp_send_process(&conn->send_timer);
}

static void tcp2_18(void)
{
	tcp_options_check(data, sizeof(data));
}

static void tcp2_19(void)
{
	net_tcp_finalize(pkt_in);
}

static void tcp2_20(void)
{
	sys_slist_append(&conn->send_queue, &pkt_in->next);

	conn->in_retransmission = true;

	k_timer_start(&conn->send_timer, K_MSEC(100), 0);

	tcp_send_timer_cancel(conn);
}


static void tcp2_21(void)
{
	th_in->th_flags = FIN | ACK | PSH | RST | SYN | URG;

	tcp_in(conn, pkt_in);
}

void test_main(void)
{
	tcp2_test_setup_once();

	if (0) {
		int i = 1;

		while (i--) {
			tcp_dbg("%d", i);

			tcp2_test_setup();

			tcp2_1();

			tcp2_test_teardown();
		}
		tcp_dbg("");

		exit(EXIT_SUCCESS);
	}

#define _(_test) \
	ztest_unit_test_setup_teardown(_test, \
		tcp2_test_setup, \
		tcp2_test_teardown)

	ztest_test_suite(tcp2,
				_(tcp2_1),
				_(tcp2_2),
				_(tcp2_3),
				_(tcp2_4),
				_(tcp2_5),
				_(tcp2_6),
				_(tcp2_7),
				_(tcp2_8),
				_(tcp2_9),
				_(tcp2_10),
				_(tcp2_11),
				_(tcp2_12),
				_(tcp2_13),
				_(tcp2_14),
				_(tcp2_15),
				_(tcp2_16),
				_(tcp2_17),
				_(tcp2_18),
				_(tcp2_19),
				_(tcp2_20),
				_(tcp2_21)

		);
#undef _
	ztest_run_test_suite(tcp2);
}
