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
	Polls_Clear();
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
	Polls_Clear();
	Poll_Add_Registered();
	uint32_t timeout = 0;
	slirp_pollfds_fill(slirp, &timeout, slirp_add_poll, this);
	struct timeval select_timeout;
	select_timeout.tv_sec = 0;
	select_timeout.tv_usec = timeout * 1000;
	get_packet_callback = callback;
	int ret = select(fds_max + 1, &fds_read, &fds_write, &fds_except, &select_timeout);
	/* TODO: ret? */
	if(ret < -1)
		printf("SELECT BAD\n");
	slirp_pollfds_poll(slirp, 0, slirp_get_revents, this);
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

int SlirpEthernetConnection::Poll_Add(int fd, int slirp_events)
{
	if(slirp_events & SLIRP_POLL_IN)  FD_SET(fd, &fds_read);
	if(slirp_events & SLIRP_POLL_OUT) FD_SET(fd, &fds_write);
	if(slirp_events & SLIRP_POLL_PRI) FD_SET(fd, &fds_except);
	if(fd > fds_max) fds_max = fd;
	return fd;
}

int SlirpEthernetConnection::Poll_Get_Slirp_Revents(int idx)
{
	int slirp_revents = 0;
	if(FD_ISSET(idx, &fds_read))   slirp_revents |= SLIRP_POLL_IN;
	if(FD_ISSET(idx, &fds_write))  slirp_revents |= SLIRP_POLL_OUT;
	if(FD_ISSET(idx, &fds_except)) slirp_revents |= SLIRP_POLL_PRI;
	if(FD_ISSET(idx, &fds_except)) {
		char buf[32];
		int toread = recv(idx, buf, sizeof(buf), MSG_PEEK);
		if(toread == -1) {
			slirp_revents |= SLIRP_POLL_ERR;
			printf("POLLERR SET\n");
		}
		if(toread == 0) {
			slirp_revents |= SLIRP_POLL_HUP;
			printf("POLLUP SET\n");
		}
	}
	{
		int sock_error;
		socklen_t opt_len = sizeof(sock_error);
		int err = getsockopt(idx, SOL_SOCKET, SO_ERROR,
			(char*)&sock_error, &opt_len);
		if(sock_error != 0 || err == 0)
			slirp_revents |= SLIRP_POLL_ERR;
	}
	return slirp_revents;
}

void SlirpEthernetConnection::Polls_Clear(void)
{
	FD_ZERO(&fds_read);
	FD_ZERO(&fds_write);
	FD_ZERO(&fds_except);
	fds_max = 0;
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

void SlirpEthernetConnection::Poll_Add_Registered(void)
{
	for(std::list<int>::iterator i = fds_registered.begin();
		i != fds_registered.end(); ++i)
	{
		Poll_Add(*i, SLIRP_POLL_IN | SLIRP_POLL_OUT);
	}
}

#endif
