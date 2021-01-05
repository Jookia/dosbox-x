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

#include "config.h"

#if C_SLIRP

#include "ethernet_slirp.h"
#include <time.h>
#include <algorithm>
#include "dosbox.h"

#ifdef WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

ssize_t slirp_send_packet(const void *buf, size_t len, void *opaque)
{
	SlirpEthernetConnection* conn = (SlirpEthernetConnection*)opaque;
	conn->Receive_Packet((uint8_t*)buf, len);
	return len;
}

void slirp_guest_error(const char *msg, void *opaque)
{
	(void)opaque;
	LOG_MSG("SLIRP: ERROR: %s", msg);
}

int64_t slirp_clock_get_ns(void *opaque)
{
	(void)opaque;
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	/* if clock_gettime fails we have more serious problems */
	return ts.tv_nsec + (ts.tv_sec * 1e9);
}

void *slirp_timer_new(SlirpTimerCb cb, void *cb_opaque, void *opaque)
{
	SlirpEthernetConnection* conn = (SlirpEthernetConnection*)opaque;
	return conn->Timer_New(cb, cb_opaque);
}

void slirp_timer_free(void *timer, void *opaque)
{
	SlirpEthernetConnection* conn = (SlirpEthernetConnection*)opaque;
	struct slirp_timer *real_timer = (struct slirp_timer*)timer;
	conn->Timer_Free(real_timer);
}

void slirp_timer_mod(void *timer, int64_t expire_time, void *opaque)
{
	SlirpEthernetConnection* conn = (SlirpEthernetConnection*)opaque;
	struct slirp_timer *real_timer = (struct slirp_timer*)timer;
	conn->Timer_Mod(real_timer, expire_time);
}

int slirp_add_poll(int fd, int events, void *opaque)
{
	SlirpEthernetConnection* conn = (SlirpEthernetConnection*)opaque;
	return conn->Poll_Add(fd, events);
}

int slirp_get_revents(int idx, void *opaque)
{
	SlirpEthernetConnection* conn = (SlirpEthernetConnection*)opaque;
	return conn->Poll_Get_Slirp_Revents(idx);
}

void slirp_register_poll_fd(int fd, void *opaque)
{
	SlirpEthernetConnection* conn = (SlirpEthernetConnection*)opaque;
	conn->Poll_Register(fd);
}

void slirp_unregister_poll_fd(int fd, void *opaque)
{
	SlirpEthernetConnection* conn = (SlirpEthernetConnection*)opaque;
	conn->Poll_Unregister(fd);
}

void slirp_notify(void *opaque)
{
	(void)opaque;
	return;
}

SlirpEthernetConnection::SlirpEthernetConnection(void)
      : EthernetConnection()
{
	slirp_callbacks.send_packet = slirp_send_packet;
	slirp_callbacks.guest_error = slirp_guest_error;
	slirp_callbacks.clock_get_ns = slirp_clock_get_ns;
	slirp_callbacks.timer_new = slirp_timer_new;
	slirp_callbacks.timer_free = slirp_timer_free;
	slirp_callbacks.timer_mod = slirp_timer_mod;
	slirp_callbacks.register_poll_fd = slirp_register_poll_fd;
	slirp_callbacks.unregister_poll_fd = slirp_unregister_poll_fd;
	slirp_callbacks.notify = slirp_notify;
}

SlirpEthernetConnection::~SlirpEthernetConnection(void)
{
	if(slirp) slirp_cleanup(slirp);
}

bool SlirpEthernetConnection::Initialize(Section* dosbox_config)
{
	Section_prop *section = static_cast<Section_prop*>(dosbox_config);

	if(!section->Get_bool("enable")) {
		LOG_MSG("SLIRP disabled, refusing to initialize");
		return false;
	}

	/* Config */
	config.version = 1;
	config.restricted = section->Get_bool("restricted");
	config.disable_host_loopback = section->Get_bool("disable_host_loopback");
	config.if_mtu = section->Get_int("mtu"); /* 0 = IF_MTU_DEFAULT */
	config.if_mru = section->Get_int("mru"); /* 0 = IF_MRU_DEFAULT */
	config.enable_emu = 0; /* Buggy, don't use */
	/* IPv4 */
	config.in_enabled = 1;
	inet_pton(AF_INET, section->Get_string("ipv4_network"), &config.vnetwork);
	inet_pton(AF_INET, section->Get_string("ipv4_netmask"), &config.vnetmask);
	inet_pton(AF_INET, section->Get_string("ipv4_host"), &config.vhost);
	inet_pton(AF_INET, section->Get_string("ipv4_nameserver"), &config.vnameserver);
	inet_pton(AF_INET, section->Get_string("ipv4_dhcp_start"), &config.vdhcp_start);
	/* IPv6 code is left here as reference but disabled as no DOS-era
	 * software supports it and might get confused by it */
	config.in6_enabled = 0;
	inet_pton(AF_INET6, "fec0::", &config.vprefix_addr6);
	config.vprefix_len = 64;
	inet_pton(AF_INET6, "fec0::2", &config.vhost6);
	inet_pton(AF_INET6, "fec0::3", &config.vnameserver6);
	/* DHCPv4, BOOTP, TFTP */
	config.vhostname = "DOSBox-X";
	config.vdnssearch = NULL;
	config.vdomainname = NULL;
	config.tftp_server_name = NULL;
	config.tftp_path = NULL;
	config.bootfile = NULL;

	slirp = slirp_new(&config, &slirp_callbacks, this);
	if(slirp)
	{
		LOG_MSG("SLIRP successfully initialized");
		return true;
	}
	else
	{
		/* TODO: better error message? */
		LOG_MSG("SLIRP failed to initialize");
		return false;
	}
}

void SlirpEthernetConnection::SendPacket(uint8_t* packet, int len)
{
	slirp_input(slirp, packet, len);
}

void SlirpEthernetConnection::GetPackets(std::function<void(uint8_t*, int)> callback)
{
	get_packet_callback = callback;
	Polls_Clear();
	Polls_Add_Registered();
	uint32_t timeout;
	// TODO: TIMEOUT
	slirp_pollfds_fill(slirp, &timeout, slirp_add_poll, this);
	bool select_error = !Polls_Check();
	slirp_pollfds_poll(slirp, select_error, slirp_get_revents, this);
	Timers_Run();
}

void SlirpEthernetConnection::Receive_Packet(uint8_t* packet, int len)
{
	get_packet_callback(packet, len);
}

struct slirp_timer* SlirpEthernetConnection::Timer_New(SlirpTimerCb cb, void *cb_opaque)
{
	for(int i = 0; i < 256; ++i)
	{
		struct slirp_timer *timer = &timers[i];
		if(!timer->used)
		{
			timer->used = 1;
			timer->expires = 0;
			timer->cb = cb;
			timer->cb_opaque = cb_opaque;
			return timer;
		}
	}
	return nullptr;
}

void SlirpEthernetConnection::Timer_Free(struct slirp_timer* timer)
{
	timer->used = 0;
}

void SlirpEthernetConnection::Timer_Mod(struct slirp_timer* timer, int64_t expire_time)
{
	timer->expires = expire_time;
}

void SlirpEthernetConnection::Timers_Run(void)
{
	int64_t now = slirp_clock_get_ns(NULL);
	for(int i = 0; i < 256; ++i)
	{
		struct slirp_timer *timer = &timers[i];
		if(timer->used && timer->expires && timer->expires < now)
		{
			timer->expires = 0;
			timer->cb(timer->cb_opaque);
		}
	}
}

void SlirpEthernetConnection::Poll_Register(int fd)
{
	Poll_Unregister(fd);
	fds_registered.push_back(fd);
}

void SlirpEthernetConnection::Poll_Unregister(int fd)
{
	std::remove(fds_registered.begin(), fds_registered.end(), fd);
}

void SlirpEthernetConnection::Polls_Add_Registered(void)
{
	for(std::list<int>::iterator i = fds_registered.begin();
		i != fds_registered.end(); ++i)
	{
		Poll_Add(*i, SLIRP_POLL_IN | SLIRP_POLL_OUT);
	}
}

//
// PLATFORM SPECIFIC CODE
//

int SlirpEthernetConnection::Poll_Add(int fd, int slirp_events)
{
	SOCKET sock = (SOCKET)fd;
	WSAEVENT event = WSACreateEvent();
	assert(event != WSA_INVALID_EVENT);
	DWORD ret = WSAEventSelect(sock, event, FD_READ | FD_WRITE | FD_OOB | FD_CLOSE);
	if(ret != 0) LOG_MSG("bad fd %i", fd);
	assert(ret == 0);
	WSANETWORKEVENTS net_events;
	int ret2 = WSAEnumNetworkEvents(sock, event, &net_events);
	assert(ret2 == 0);
	WSACloseEvent(event);
	int neteventmask = net_events.lNetworkEvents;
	if(neteventmask == 0)
		return fd;
	struct windows_revents* revent = &revents[num_revents++];
	revent->fd = fd;
	revent->revents = 0;
	if(neteventmask & FD_READ) revent->revents |= SLIRP_POLL_IN;
	if(neteventmask & FD_WRITE) revent->revents |= SLIRP_POLL_OUT;
	if(neteventmask & FD_OOB) revent->revents |= SLIRP_POLL_PRI;
	if(neteventmask & FD_CLOSE) revent->revents |= SLIRP_POLL_HUP;
	//revent->revents &= slirp_events;
	LOG_MSG("rervents: %i revents %p fd %i idx %i", revent->revents, revent, revent->fd, fd);
	return fd;
}

bool SlirpEthernetConnection::Polls_Check(void)
{
	return true;
}

int SlirpEthernetConnection::Poll_Get_Slirp_Revents(int idx)
{
	if(num_revents == 0) return 0;
	for(int i = 0; i < num_revents; ++i) {
		struct windows_revents* revent = &revents[i];
		if(revent->fd == idx) {
			return revent->revents;
		}
	}
	return 0;
}

void SlirpEthernetConnection::Polls_Clear(void)
{
	num_revents = 0;
}

#endif
