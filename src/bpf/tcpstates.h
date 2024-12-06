// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Hengqi Chen */
#ifndef __TCPSTATES_H
#define __TCPSTATES_H

struct event {
	unsigned __int128 saddr;
	unsigned __int128 daddr;
	__u64 ts;
	__u64 srtt_us;
	__u16 family;
	__u16 protocol;
	__u16 sport;
	__u16 dport;
};

#endif /* __TCPSTATES_H */

