/* *  Copyright (C) 2020  The DOSBox Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef DOSBOX_ETHERNET_SLIRP_H
#define DOSBOX_ETHERNET_SLIRP_H

#include "config.h"

#if C_SLIRP

#include "ethernet.h"
#include <slirp/libslirp.h>
#include <list>

#include <winsock2.h>

struct slirp_timer {
	int used;
	int64_t expires;
	SlirpTimerCb cb;
	void *cb_opaque;
};

struct windows_revents {
	int fd;
	int revents;
};

class SlirpEthernetConnection : public EthernetConnection {
	public:
		SlirpEthernetConnection(void);
		~SlirpEthernetConnection(void);
		bool Initialize(Section* config);
		void SendPacket(uint8_t* packet, int len);
		void GetPackets(std::function<void(uint8_t*, int)> callback);

		void Receive_Packet(uint8_t* packet, int len);

		struct slirp_timer* Timer_New(SlirpTimerCb cb, void *cb_opaque);
		void Timer_Free(struct slirp_timer* timer);
		void Timer_Mod(struct slirp_timer* timer, int64_t expire_time);

		int Poll_Add(int fd, int slirp_events);
		int Poll_Get_Slirp_Revents(int idx);
		void Poll_Register(int fd);
		void Poll_Unregister(int fd);

	private:
		void Timers_Run(void);
		void Polls_Add_Registered(void);
		bool Polls_Check(void);
		void Polls_Clear(void);

		std::list<int> fds_registered;

		struct windows_revents revents[256];
		int num_revents = 0;

		/* TODO: list */
		struct slirp_timer timers[256] = { 0 };
		Slirp* slirp = nullptr;
		SlirpConfig config = { 0 };
		SlirpCb slirp_callbacks = { 0 };
		std::function<void(uint8_t*, int)> get_packet_callback;
};

#endif

#endif
