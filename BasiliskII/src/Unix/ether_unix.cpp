/*
 *  ether_unix.cpp - Ethernet device driver, Unix specific stuff (Linux and FreeBSD)
 *
 *  Basilisk II (C) 1997-2008 Christian Bauer
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "sysdeps.h"

/*
 *  NOTES concerning MacOS X issues:
 *  - poll() does not exist in 10.2.8, but is available in 10.4.4
 *  - select(), and very likely poll(), are not cancellation points. So
 *    the ethernet thread doesn't stop on exit. An explicit check is
 *    performed to workaround this problem.
 */
#if (defined __APPLE__ && defined __MACH__) || ! defined HAVE_POLL
#define USE_POLL 0
#else
#define USE_POLL 1
#endif

// Define to let the slirp library determine the right timeout for select()
#define USE_SLIRP_TIMEOUT 1

#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <map>

#if defined(__FreeBSD__) || defined(sgi) || (defined(__APPLE__) && defined(__MACH__))
#include <net/if.h>
#endif

#if defined(HAVE_LINUX_IF_H) && defined(HAVE_LINUX_IF_TUN_H)
#include <linux/if.h>
#include <linux/if_tun.h>
#endif

#if defined(HAVE_NET_IF_H) && defined(HAVE_NET_IF_TUN_H)
#include <net/if.h>
#include <net/if_tun.h>
#endif

#ifdef HAVE_SLIRP
#include "libslirp.h"
#include "ctl.h"
#endif

#include <amqp.h>
#include <amqp_tcp_socket.h>
#include <amqp_ssl_socket.h>

#include "cpu_emulation.h"
#include "main.h"
#include "macos_util.h"
#include "prefs.h"
#include "user_strings.h"
#include "ether.h"
#include "ether_defs.h"

#ifndef NO_STD_NAMESPACE
using std::map;
#endif

#define DEBUG 0
#include "debug.h"

#define STATISTICS 0
#define MONITOR 0


// Ethernet device types
enum {
	NET_IF_SHEEPNET,
	NET_IF_ETHERTAP,
	NET_IF_TUNTAP,
	NET_IF_SLIRP,
	NET_IF_AMQP
};

// Constants
#if ENABLE_TUNTAP
static const char ETHERCONFIG_FILE_NAME[] = DATADIR "/tunconfig";
#endif

// Global variables
static int fd = -1;							// fd of sheep_net device
static pthread_t ether_thread;				// Packet reception thread
static pthread_attr_t ether_thread_attr;	// Packet reception thread attributes
static bool thread_active = false;			// Flag: Packet reception thread installed
static sem_t int_ack;						// Interrupt acknowledge semaphore
static bool udp_tunnel;						// Flag: UDP tunnelling active, fd is the socket descriptor
static int net_if_type = -1;				// Ethernet device type
static char *net_if_name = NULL;			// TUN/TAP device name
static const char *net_if_script = NULL;	// Network config script
static pthread_t slirp_thread;				// Slirp reception thread
static bool slirp_thread_active = false;	// Flag: Slirp reception threadinstalled
static int slirp_output_fd = -1;			// fd of slirp output pipe
static int slirp_input_fds[2] = { -1, -1 };	// fds of slirp input pipe
static amqp_connection_state_t amqp_connection = 0;	// AMQP connection
static amqp_envelope_t *amqp_envelope = 0;	// AMQP packet, saved here so it can be passed to the interrupt code
static char amqp_exchange[128];				// AMQP exchange to publish upon
#ifdef SHEEPSHAVER
static bool net_open = false;				// Flag: initialization succeeded, network device open
static uint8 ether_addr[6];					// Our Ethernet address
#else
const bool ether_driver_opened = true;		// Flag: is the MacOS driver opened?
#endif

// Attached network protocols, maps protocol type to MacOS handler address
static map<uint16, uint32> net_protocols;

// Prototypes
static void *receive_func(void *arg);
static void *slirp_receive_func(void *arg);
static int16 ether_do_add_multicast(uint8 *addr);
static int16 ether_do_del_multicast(uint8 *addr);
static int16 ether_do_write(uint32 arg);
static void ether_do_interrupt(void);
static void slirp_add_redirs();
static int slirp_add_redir(const char *redir_str);
amqp_connection_state_t amqp_queue_connect(const char *url);
void amqp_queue_disconnect(amqp_connection_state_t connection);

/*
 *  Start packet reception thread
 */

static bool start_thread(void)
{
	if (sem_init(&int_ack, 0, 0) < 0) {
		printf("WARNING: Cannot init semaphore");
		return false;
	}

	Set_pthread_attr(&ether_thread_attr, 1);
	thread_active = (pthread_create(&ether_thread, &ether_thread_attr, receive_func, NULL) == 0);
	if (!thread_active) {
		printf("WARNING: Cannot start Ethernet thread");
		return false;
	}

#ifdef HAVE_SLIRP
	if (net_if_type == NET_IF_SLIRP) {
		slirp_thread_active = (pthread_create(&slirp_thread, NULL, slirp_receive_func, NULL) == 0);
		if (!slirp_thread_active) {
			printf("WARNING: Cannot start slirp reception thread\n");
			return false;
		}
	}
#endif

	return true;
}


/*
 *  Stop packet reception thread
 */

static void stop_thread(void)
{
#ifdef HAVE_SLIRP
	if (slirp_thread_active) {
#ifdef HAVE_PTHREAD_CANCEL
		pthread_cancel(slirp_thread);
#endif
		pthread_join(slirp_thread, NULL);
		slirp_thread_active = false;
	}
#endif

	if (thread_active) {
#ifdef HAVE_PTHREAD_CANCEL
		pthread_cancel(ether_thread);
#endif
		pthread_join(ether_thread, NULL);
		sem_destroy(&int_ack);
		thread_active = false;
	}
}


/*
 *  Execute network script up|down
 */

static bool execute_network_script(const char *action)
{
	if (net_if_script == NULL || net_if_name == NULL)
		return false;

	int pid = fork();
	if (pid >= 0) {
		if (pid == 0) {
			char *args[4];
			args[0] = (char *)net_if_script;
			args[1] = net_if_name;
			args[2] = (char *)action;
			args[3] = NULL;
			execv(net_if_script, args);
			exit(1);
		}
		int status;
		while (waitpid(pid, &status, 0) != pid);
		return WIFEXITED(status) && WEXITSTATUS(status) == 0;
	}

	return false;
}


/*
 *  Initialization
 */

bool ether_init(void)
{
	int val;
	char str[256];

	// Do nothing if no Ethernet device specified
	const char *name = PrefsFindString("ether");
	if (name == NULL)
		return false;

	// Determine Ethernet device type
	net_if_type = -1;
	if (strncmp(name, "tap", 3) == 0)
		net_if_type = NET_IF_ETHERTAP;
#if ENABLE_TUNTAP
	else if (strcmp(name, "tun") == 0)
		net_if_type = NET_IF_TUNTAP;
#endif
#ifdef HAVE_SLIRP
	else if (strcmp(name, "slirp") == 0)
		net_if_type = NET_IF_SLIRP;
#endif
	else if (strncmp(name, "amqp", 4) == 0)
		net_if_type = NET_IF_AMQP;
	else
		net_if_type = NET_IF_SHEEPNET;

	// Don't raise SIGPIPE, let errno be set to EPIPE
	struct sigaction sigpipe_sa;
	if (sigaction(SIGPIPE, NULL, &sigpipe_sa) == 0) {
		assert(sigpipe_sa.sa_handler == SIG_DFL || sigpipe_sa.sa_handler == SIG_IGN);
		sigfillset(&sigpipe_sa.sa_mask);
		sigpipe_sa.sa_flags = 0;
		sigpipe_sa.sa_handler = SIG_IGN;
		sigaction(SIGPIPE, &sigpipe_sa, NULL);
	}

#ifdef HAVE_SLIRP
	// Initialize slirp library
	if (net_if_type == NET_IF_SLIRP) {
		if (slirp_init() < 0) {
			sprintf(str, "%s", GetString(STR_SLIRP_NO_DNS_FOUND_WARN));
			WarningAlert(str);
			return false;
		}

		// Open slirp output pipe
		int fds[2];
		if (pipe(fds) < 0)
			return false;
		fd = fds[0];
		slirp_output_fd = fds[1];

		// Open slirp input pipe
		if (pipe(slirp_input_fds) < 0)
			return false;

		// Set up port redirects
		slirp_add_redirs();
	}
#endif

	if(net_if_type == NET_IF_AMQP) {
		amqp_connection = amqp_queue_connect(name);
		if(amqp_connection == 0)
			return false;
		// Start packet reception thread
		if (!start_thread())
			goto open_error;
		return true; // return early to bypass fd setup
	}

	// Open sheep_net or ethertap or TUN/TAP device
	char dev_name[16];
	switch (net_if_type) {
	case NET_IF_ETHERTAP:
		sprintf(dev_name, "/dev/%s", name);
		break;
	case NET_IF_TUNTAP:
		strcpy(dev_name, "/dev/net/tun");
		break;
	case NET_IF_SHEEPNET:
		strcpy(dev_name, "/dev/sheep_net");
		break;
	}
	if (net_if_type != NET_IF_SLIRP) {
		fd = open(dev_name, O_RDWR);
		if (fd < 0) {
			sprintf(str, GetString(STR_NO_SHEEP_NET_DRIVER_WARN), dev_name, strerror(errno));
			WarningAlert(str);
			goto open_error;
		}
	}

#if ENABLE_TUNTAP
	// Open TUN/TAP interface
	if (net_if_type == NET_IF_TUNTAP) {
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
		strcpy(ifr.ifr_name, "tun%d");
		if (ioctl(fd, TUNSETIFF, (void *) &ifr) != 0) {
			sprintf(str, GetString(STR_SHEEP_NET_ATTACH_WARN), strerror(errno));
			WarningAlert(str);
			goto open_error;
		}

		// Get network config script file path
		net_if_script = PrefsFindString("etherconfig");
		if (net_if_script == NULL)
			net_if_script = ETHERCONFIG_FILE_NAME;

		// Start network script up
		if (net_if_script == NULL) {
			sprintf(str, GetString(STR_TUN_TAP_CONFIG_WARN), "script not found");
			WarningAlert(str);
			goto open_error;
		}
		net_if_name = strdup(ifr.ifr_name);
		if (!execute_network_script("up")) {
			sprintf(str, GetString(STR_TUN_TAP_CONFIG_WARN), "script execute error");
			WarningAlert(str);
			goto open_error;
		}
		D(bug("Connected to host network interface: %s\n", net_if_name));
	}
#endif

#if defined(__linux__)
	// Attach sheep_net to selected Ethernet card
	if (net_if_type == NET_IF_SHEEPNET && ioctl(fd, SIOCSIFLINK, name) < 0) {
		sprintf(str, GetString(STR_SHEEP_NET_ATTACH_WARN), strerror(errno));
		WarningAlert(str);
		goto open_error;
	}
#endif

	// Set nonblocking I/O
#ifdef USE_FIONBIO
	int nonblock = 1;
	if (ioctl(fd, FIONBIO, &nonblock) < 0) {
		sprintf(str, GetString(STR_BLOCKING_NET_SOCKET_WARN), strerror(errno));
		WarningAlert(str);
		goto open_error;
	}
#else
	val = fcntl(fd, F_GETFL, 0);
	if (val < 0 || fcntl(fd, F_SETFL, val | O_NONBLOCK) < 0) {
		sprintf(str, GetString(STR_BLOCKING_NET_SOCKET_WARN), strerror(errno));
		WarningAlert(str);
		goto open_error;
	}
#endif

	// Get Ethernet address
	if (net_if_type == NET_IF_ETHERTAP || net_if_type == NET_IF_TUNTAP) {
		pid_t p = getpid();	// If configured for multicast, ethertap requires that the lower 32 bit of the Ethernet address are our PID
		ether_addr[0] = 0xfe;
		ether_addr[1] = 0xfd;
		ether_addr[2] = p >> 24;
		ether_addr[3] = p >> 16;
		ether_addr[4] = p >> 8;
		ether_addr[5] = p;
#ifdef HAVE_SLIRP
	} else if (net_if_type == NET_IF_SLIRP) {
		ether_addr[0] = 0x52;
		ether_addr[1] = 0x54;
		ether_addr[2] = 0x00;
		ether_addr[3] = 0x12;
		ether_addr[4] = 0x34;
		ether_addr[5] = 0x56;
#endif
	} else
		ioctl(fd, SIOCGIFADDR, ether_addr);
	D(bug("Ethernet address %02x %02x %02x %02x %02x %02x\n", ether_addr[0], ether_addr[1], ether_addr[2], ether_addr[3], ether_addr[4], ether_addr[5]));

	// Start packet reception thread
	if (!start_thread())
		goto open_error;

	// Everything OK
	return true;

open_error:
	stop_thread();

	if (fd > 0) {
		close(fd);
		fd = -1;
	}
	if (slirp_input_fds[0] >= 0) {
		close(slirp_input_fds[0]);
		slirp_input_fds[0] = -1;
	}
	if (slirp_input_fds[1] >= 0) {
		close(slirp_input_fds[1]);
		slirp_input_fds[1] = -1;
	}
	if (slirp_output_fd >= 0) {
		close(slirp_output_fd);
		slirp_output_fd = -1;
	}
	return false;
}


/*
 *  Deinitialization
 */

void ether_exit(void)
{
	// Stop reception threads
	stop_thread();

	// Shut down TUN/TAP interface
	if (net_if_type == NET_IF_TUNTAP)
		execute_network_script("down");

	// Free TUN/TAP device name
	if (net_if_name)
		free(net_if_name);

	// Close sheep_net device
	if (fd > 0)
		close(fd);

	// Close slirp input buffer
	if (slirp_input_fds[0] >= 0)
		close(slirp_input_fds[0]);
	if (slirp_input_fds[1] >= 0)
		close(slirp_input_fds[1]);

	// Close slirp output buffer
	if (slirp_output_fd > 0)
		close(slirp_output_fd);

	if(net_if_type == NET_IF_AMQP) {
		if(amqp_connection != 0) {
			amqp_queue_disconnect(amqp_connection);
			amqp_connection = 0;
		}
	}

#if STATISTICS
	// Show statistics
	printf("%ld messages put on write queue\n", num_wput);
	printf("%ld error acks\n", num_error_acks);
	printf("%ld packets transmitted (%ld raw, %ld normal)\n", num_tx_packets, num_tx_raw_packets, num_tx_normal_packets);
	printf("%ld tx packets dropped because buffer full\n", num_tx_buffer_full);
	printf("%ld packets received\n", num_rx_packets);
	printf("%ld packets passed upstream (%ld Fast Path, %ld normal)\n", num_rx_fastpath + num_unitdata_ind, num_rx_fastpath, num_unitdata_ind);
	printf("EtherIRQ called %ld times\n", num_ether_irq);
	printf("%ld rx packets dropped due to low memory\n", num_rx_no_mem);
	printf("%ld rx packets dropped because no stream found\n", num_rx_dropped);
	printf("%ld rx packets dropped because stream not ready\n", num_rx_stream_not_ready);
	printf("%ld rx packets dropped because no memory for unitdata_ind\n", num_rx_no_unitdata_mem);
#endif
}


/*
 *  Glue around low-level implementation
 */

#ifdef SHEEPSHAVER
// Error codes
enum {
	eMultiErr		= -91,
	eLenErr			= -92,
	lapProtErr		= -94,
	excessCollsns	= -95
};

// Initialize ethernet
void EtherInit(void)
{
	net_open = false;

	// Do nothing if the user disabled the network
	if (PrefsFindBool("nonet"))
		return;

	net_open = ether_init();
}

// Exit ethernet
void EtherExit(void)
{
	ether_exit();
	net_open = false;
}

// Get ethernet hardware address
void AO_get_ethernet_address(uint32 arg)
{
	uint8 *addr = Mac2HostAddr(arg);
	if (net_open)
		OTCopy48BitAddress(ether_addr, addr);
	else {
		addr[0] = 0x12;
		addr[1] = 0x34;
		addr[2] = 0x56;
		addr[3] = 0x78;
		addr[4] = 0x9a;
		addr[5] = 0xbc;
	}
	D(bug("AO_get_ethernet_address: got address %02x%02x%02x%02x%02x%02x\n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]));
}

// Add multicast address
void AO_enable_multicast(uint32 addr)
{
	if (net_open)
		ether_do_add_multicast(Mac2HostAddr(addr));
}

// Disable multicast address
void AO_disable_multicast(uint32 addr)
{
	if (net_open)
		ether_do_del_multicast(Mac2HostAddr(addr));
}

// Transmit one packet
void AO_transmit_packet(uint32 mp)
{
	if (net_open) {
		switch (ether_do_write(mp)) {
		case noErr:
			num_tx_packets++;
			break;
		case excessCollsns:
			num_tx_buffer_full++;
			break;
		}
	}
}

// Copy packet data from message block to linear buffer
static inline int ether_arg_to_buffer(uint32 mp, uint8 *p)
{
	return ether_msgb_to_buffer(mp, p);
}

// Ethernet interrupt
void EtherIRQ(void)
{
	D(bug("EtherIRQ\n"));
	num_ether_irq++;

	OTEnterInterrupt();
	ether_do_interrupt();
	OTLeaveInterrupt();

	// Acknowledge interrupt to reception thread
	D(bug(" EtherIRQ done\n"));
	sem_post(&int_ack);
}
#else
// Add multicast address
int16 ether_add_multicast(uint32 pb)
{
	return ether_do_add_multicast(Mac2HostAddr(pb + eMultiAddr));
}

// Disable multicast address
int16 ether_del_multicast(uint32 pb)
{
	return ether_do_del_multicast(Mac2HostAddr(pb + eMultiAddr));
}

// Transmit one packet
int16 ether_write(uint32 wds)
{
	return ether_do_write(wds);
}

// Copy packet data from WDS to linear buffer
static inline int ether_arg_to_buffer(uint32 wds, uint8 *p)
{
	return ether_wds_to_buffer(wds, p);
}

// Dispatch packet to protocol handler
static void ether_dispatch_packet(uint32 p, uint32 length)
{
	// Get packet type
	uint16 type = ReadMacInt16(p + 12);

	// Look for protocol
	uint16 search_type = (type <= 1500 ? 0 : type);
	if (net_protocols.find(search_type) == net_protocols.end())
		return;
	uint32 handler = net_protocols[search_type];

	// No default handler
	if (handler == 0)
		return;

	// Copy header to RHA
	Mac2Mac_memcpy(ether_data + ed_RHA, p, 14);
	D(bug(" header %08x%04x %08x%04x %04x\n", ReadMacInt32(ether_data + ed_RHA), ReadMacInt16(ether_data + ed_RHA + 4), ReadMacInt32(ether_data + ed_RHA + 6), ReadMacInt16(ether_data + ed_RHA + 10), ReadMacInt16(ether_data + ed_RHA + 12)));

	// Call protocol handler
	M68kRegisters r;
	r.d[0] = type;									// Packet type
	r.d[1] = length - 14;							// Remaining packet length (without header, for ReadPacket)
	r.a[0] = p + 14;								// Pointer to packet (Mac address, for ReadPacket)
	r.a[3] = ether_data + ed_RHA + 14;				// Pointer behind header in RHA
	r.a[4] = ether_data + ed_ReadPacket;			// Pointer to ReadPacket/ReadRest routines
	D(bug(" calling protocol handler %08x, type %08x, length %08x, data %08x, rha %08x, read_packet %08x\n", handler, r.d[0], r.d[1], r.a[0], r.a[3], r.a[4]));
	Execute68k(handler, &r);
}

// Ethernet interrupt
void EtherInterrupt(void)
{
	D(bug("EtherIRQ\n"));
	ether_do_interrupt();

	// Acknowledge interrupt to reception thread
	D(bug(" EtherIRQ done\n"));
	sem_post(&int_ack);
}
#endif


/*
 *  Reset
 */

void ether_reset(void)
{
	net_protocols.clear();
}


/*
 *  Add multicast address
 */

static int16 ether_do_add_multicast(uint8 *addr)
{
	switch (net_if_type) {
	case NET_IF_ETHERTAP:
	case NET_IF_SHEEPNET:
		if (ioctl(fd, SIOCADDMULTI, addr) < 0) {
			D(bug("WARNING: Couldn't enable multicast address\n"));
			if (net_if_type == NET_IF_ETHERTAP) {
				return noErr;
			} else {
				return eMultiErr;
			}
		}
		return noErr;
	default:
		return noErr;
	}
}


/*
 *  Delete multicast address
 */

static int16 ether_do_del_multicast(uint8 *addr)
{
	switch (net_if_type) {
	case NET_IF_ETHERTAP:
	case NET_IF_SHEEPNET:
		if (ioctl(fd, SIOCDELMULTI, addr) < 0) {
			D(bug("WARNING: Couldn't disable multicast address\n"));
			return eMultiErr;
		}
		return noErr;
	default:
		return noErr;
	}
}


/*
 *  Attach protocol handler
 */

int16 ether_attach_ph(uint16 type, uint32 handler)
{
	if (net_protocols.find(type) != net_protocols.end())
		return lapProtErr;
	net_protocols[type] = handler;
	return noErr;
}


/*
 *  Detach protocol handler
 */

int16 ether_detach_ph(uint16 type)
{
	if (net_protocols.erase(type) == 0)
		return lapProtErr;
	return noErr;
}


/*
 *  Transmit raw ethernet packet
 */

static int16 ether_do_write(uint32 arg)
{
	// Copy packet to buffer
	uint8 packet[1516], *p = packet;
	int len = 0;
#if defined(__linux__)
	if (net_if_type == NET_IF_ETHERTAP) {
		*p++ = 0;	// Linux ethertap discards the first 2 bytes
		*p++ = 0;
		len += 2;
	}
#endif
	len += ether_arg_to_buffer(arg, p);

#if MONITOR
	bug("Sending Ethernet packet:\n");
	for (int i=0; i<len; i++) {
		bug("%02x ", packet[i]);
	}
	bug("\n");
#endif

	// Transmit packet
#ifdef HAVE_SLIRP
	if (net_if_type == NET_IF_SLIRP) {
		const int slirp_input_fd = slirp_input_fds[1];
		write(slirp_input_fd, &len, sizeof(len));
		write(slirp_input_fd, packet, len);
		return noErr;
	} else
#endif
	if(net_if_type == NET_IF_AMQP) {
		amqp_basic_properties_t props;
		props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG;
		props.content_type = amqp_cstring_bytes("application/x-appletalk-packet");
		props.delivery_mode = 2; /* persistent delivery mode */
		amqp_bytes_t messageBody;
		messageBody.len = len;
		messageBody.bytes = packet;
		if(amqp_basic_publish(amqp_connection, 1, amqp_cstring_bytes(amqp_exchange), amqp_cstring_bytes("basilisk_ii"), 0, 0, &props, messageBody) < 0)
			WarningAlert("Unable to publish packet to AMQP server");
		return noErr;
	} else
	if (write(fd, packet, len) < 0) {
		D(bug("WARNING: Couldn't transmit packet\n"));
		return excessCollsns;
	} else
		return noErr;
}


/*
 *  Start UDP packet reception thread
 */

bool ether_start_udp_thread(int socket_fd)
{
	fd = socket_fd;
	udp_tunnel = true;
	return start_thread();
}


/*
 *  Stop UDP packet reception thread
 */

void ether_stop_udp_thread(void)
{
	stop_thread();
	fd = -1;
}


/*
 *  SLIRP output buffer glue
 */

#ifdef HAVE_SLIRP
int slirp_can_output(void)
{
	return 1;
}

void slirp_output(const uint8 *packet, int len)
{
	write(slirp_output_fd, packet, len);
}

void *slirp_receive_func(void *arg)
{
	const int slirp_input_fd = slirp_input_fds[0];

	for (;;) {
		// Wait for packets to arrive
		fd_set rfds, wfds, xfds;
		int nfds;
		struct timeval tv;

		// ... in the input queue
		FD_ZERO(&rfds);
		FD_SET(slirp_input_fd, &rfds);
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		if (select(slirp_input_fd + 1, &rfds, NULL, NULL, &tv) > 0) {
			int len;
			read(slirp_input_fd, &len, sizeof(len));
			uint8 packet[1516];
			assert(len <= sizeof(packet));
			read(slirp_input_fd, packet, len);
			slirp_input(packet, len);
		}

		// ... in the output queue
		nfds = -1;
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		FD_ZERO(&xfds);
		int timeout = slirp_select_fill(&nfds, &rfds, &wfds, &xfds);
#if ! USE_SLIRP_TIMEOUT
		timeout = 10000;
#endif
		tv.tv_sec = 0;
		tv.tv_usec = timeout;
		if (select(nfds + 1, &rfds, &wfds, &xfds, &tv) >= 0)
			slirp_select_poll(&rfds, &wfds, &xfds);

#ifdef HAVE_PTHREAD_TESTCANCEL
		// Explicit cancellation point if select() was not covered
		// This seems to be the case on MacOS X 10.2
		pthread_testcancel();
#endif
	}
	return NULL;
}
#else
int slirp_can_output(void)
{
	return 0;
}

void slirp_output(const uint8 *packet, int len)
{
}
#endif

bool amqp_check_status(amqp_rpc_reply_t status, char const *context) {
	char str[256];
	switch (status.reply_type) {
		case AMQP_RESPONSE_NORMAL:
			return true;

		case AMQP_RESPONSE_NONE:
			snprintf(str, sizeof(str), "%s: missing RPC reply type", context);
			WarningAlert(str);
			break;

		case AMQP_RESPONSE_LIBRARY_EXCEPTION:
			snprintf(str, sizeof(str), "%s: %s", context, amqp_error_string2(status.library_error));
			WarningAlert(str);
			break;

		case AMQP_RESPONSE_SERVER_EXCEPTION:
			switch (status.reply.id) {
				case AMQP_CONNECTION_CLOSE_METHOD: {
					amqp_connection_close_t *m = (amqp_connection_close_t*)status.reply.decoded;
					snprintf(str, sizeof(str), "%s: server connection error %uh, message: %.*s", context, m->reply_code, (int)m->reply_text.len, m->reply_text.bytes);
					WarningAlert(str);
					break;
				}
				case AMQP_CHANNEL_CLOSE_METHOD: {
					amqp_channel_close_t *m = (amqp_channel_close_t*)status.reply.decoded;
					snprintf(str, sizeof(str), "%s: server channel error %uh, message: %.*s", context, m->reply_code, (int)m->reply_text.len, m->reply_text.bytes);
					WarningAlert(str);
					break;
				}
				default:
					snprintf(str, sizeof(str), "%s: unknown server error, method id 0x%08X", context, status.reply.id);
					WarningAlert(str);
					break;
			}
			break;
	}
	return false;
}

// amqps?://user:password@hostname:port[/vhost]?exchange
amqp_connection_state_t amqp_queue_connect(const char *url) {
	amqp_connection_state_t connection = 0;
	amqp_socket_t *socket = 0;
	char *parsedUrl = (char*)alloca(strlen(url) + 1);
	strcpy(parsedUrl, url);

	bool useSSL = false;
	char *password = (char*)"guest";
	char *hostname = (char*)"localhost";
	int port = 5671;
	char *vhost = (char*)"/";
	char *exchange = (char*)"appleshare";

	if(strncmp(parsedUrl, "amqps", 5) == 0)
		useSSL = true;
	char *user = (char*)strstr(parsedUrl, "://");
	if(user) {
		user += 3; // skip past the ://
		password = strchr(user, ':');
		if(password) {
			*(password++) = 0;
			hostname = strchr(password, '@');
			if(hostname) {
				*(hostname++) = 0;
				char *p = strchr(hostname, ':');
				if(p) {
					*(p++) = 0;
					port = atoi(p);
					if(port == 0) port = 5671;
					vhost = strchr(p, '/');
					if(vhost) {
						p = strchr(vhost, '?');
						if(p) {
							*(p++) = 0;
							exchange = p;
						}
					} else
						vhost = (char*)"/";
				}
			} else
				hostname = (char*)"localhost";
		} else
			password = (char*)"guest";
	} else
		user = (char*)"guest";

	strncpy(amqp_exchange, exchange, sizeof(amqp_exchange));

	connection = amqp_new_connection();

	if(useSSL) {
		socket = amqp_ssl_socket_new(connection);
		amqp_ssl_socket_set_verify_peer(socket, 0);
		amqp_ssl_socket_set_verify_hostname(socket, 1);
	} else
		socket = amqp_tcp_socket_new(connection);

	if (socket == 0) {
		WarningAlert("Can't create AMQP socket");
		amqp_queue_disconnect(connection);
		return 0;
	}

	if(amqp_socket_open(socket, hostname, port)) {
		WarningAlert("Unable to open AMQP socket");
		amqp_queue_disconnect(connection);
		return 0;
	}

	amqp_rpc_reply_t status = amqp_login(connection, vhost, 0, 131072, 0, AMQP_SASL_METHOD_PLAIN, user, password);
	if(amqp_check_status(status, "amqp_login") == false) {
		amqp_queue_disconnect(connection);
		return 0;
	}

	amqp_channel_open(connection, 1);
	status = amqp_get_rpc_reply(connection);
	if(amqp_check_status(status, "amqp_channel_open") == false) {
		amqp_queue_disconnect(connection);
		return 0;
	}

	amqp_exchange_declare(connection, 1, amqp_cstring_bytes(exchange), amqp_cstring_bytes("fanout"), 0, 0, 0, 0, amqp_empty_table);
	status = amqp_get_rpc_reply(connection);
	if(amqp_check_status(status, "amqp_exchange_declare") == false) {
		amqp_queue_disconnect(connection);
		return 0;
	}

	D(bug("Connected to AMQP server %s:%d\n", hostname, port));
	return connection;
}

void amqp_queue_disconnect(amqp_connection_state_t connection) {
	if(connection != 0) {
		amqp_rpc_reply_t status = amqp_channel_close(amqp_connection, 1, AMQP_REPLY_SUCCESS);
		if(amqp_check_status(status, "amqp_channel_close")) {
			status = amqp_connection_close(amqp_connection, AMQP_REPLY_SUCCESS);
			if(amqp_check_status(status, "amqp_connection_close")) {
				if(amqp_destroy_connection(amqp_connection) < 0)
					WarningAlert("Unable to destroy AMQP connection");
			}
		}
	}
}


/*
 *  Packet reception thread
 */

static void *receive_func(void *arg)
{
	amqp_connection_state_t readQueue = 0;
	if(net_if_type == NET_IF_AMQP) {
		readQueue = amqp_queue_connect(PrefsFindString("ether"));
		if(readQueue == 0)
			return 0;
		amqp_queue_declare_ok_t *r = amqp_queue_declare(readQueue, 1, amqp_empty_bytes, 0, 0, 0, 1, amqp_empty_table);
		amqp_rpc_reply_t status = amqp_get_rpc_reply(readQueue);
		if(amqp_check_status(status, "amqp_queue_declare") == false) {
			amqp_queue_disconnect(readQueue);
			return 0;
		}

		amqp_bytes_t queueName = amqp_bytes_malloc_dup(r->queue);
		if (queueName.bytes == 0) {
			WarningAlert("Out of memory while copying queue name");
			amqp_queue_disconnect(readQueue);
			return 0;
		}

		D(bug("Listening for message on queue: %.*s\n", (int)queueName.len, queueName.bytes));

		amqp_queue_bind(readQueue, 1, queueName, amqp_cstring_bytes(amqp_exchange), amqp_cstring_bytes("*"), amqp_empty_table);
		status = amqp_get_rpc_reply(readQueue);
		if(amqp_check_status(status, "amqp_queue_bind") == false) {
			amqp_queue_disconnect(readQueue);
			return 0;
		}

		amqp_basic_consume(readQueue, 1, queueName, amqp_empty_bytes, 0, 1, 0, amqp_empty_table);
		status = amqp_get_rpc_reply(readQueue);
		if(amqp_check_status(status, "amqp_basic_consume") == false) {
			amqp_queue_disconnect(readQueue);
			return 0;
		}

		amqp_envelope = (amqp_envelope_t*)malloc(sizeof(amqp_envelope_t));
	}

	for (;;) {

		if(net_if_type == NET_IF_AMQP && readQueue != 0) {
			amqp_maybe_release_buffers(readQueue);

			amqp_rpc_reply_t res = amqp_consume_message(readQueue, amqp_envelope, 0, 0);
			if (AMQP_RESPONSE_NORMAL != res.reply_type) {
				printf("AMQP error\n");
				break;
			}

			if(strncmp((char*)amqp_envelope->routing_key.bytes, "basilisk_ii", amqp_envelope->routing_key.len) == 0) {
				amqp_destroy_envelope(amqp_envelope);
				continue;
			}
		} else {
			// Wait for packets to arrive
#if USE_POLL
			struct pollfd pf = {fd, POLLIN, 0};
			int res = poll(&pf, 1, -1);
#else
			fd_set rfds;
			FD_ZERO(&rfds);
			FD_SET(fd, &rfds);
			// A NULL timeout could cause select() to block indefinitely,
			// even if it is supposed to be a cancellation point [MacOS X]
			struct timeval tv = { 0, 20000 };
			int res = select(fd + 1, &rfds, NULL, NULL, &tv);
#ifdef HAVE_PTHREAD_TESTCANCEL
			pthread_testcancel();
#endif
			if (res == 0 || (res == -1 && errno == EINTR))
				continue;
#endif
			if (res <= 0)
				break;
		}

		if (ether_driver_opened) {
			// Trigger Ethernet interrupt
			D(bug(" packet received, triggering Ethernet interrupt\n"));
			SetInterruptFlag(INTFLAG_ETHER);
			TriggerInterrupt();

			// Wait for interrupt acknowledge by EtherInterrupt()
			sem_wait(&int_ack);
		} else
			Delay_usec(20000);
	}

	if(readQueue != 0) {
		amqp_queue_disconnect(readQueue);
		readQueue = 0;
	}

	if(amqp_envelope != 0) {
		free(amqp_envelope);
		amqp_envelope = 0;
	}

	return NULL;
}


/*
 *  Ethernet interrupt - activate deferred tasks to call IODone or protocol handlers
 */

void ether_do_interrupt(void)
{
	// Call protocol handler for received packets
	EthernetPacket ether_packet;
	uint32 packet = ether_packet.addr();
	ssize_t length;
	for (;;) {

#ifndef SHEEPSHAVER
		if (udp_tunnel) {

			// Read packet from socket
			struct sockaddr_in from;
			socklen_t from_len = sizeof(from);
			length = recvfrom(fd, Mac2HostAddr(packet), 1514, 0, (struct sockaddr *)&from, &from_len);
			if (length < 14)
				break;
			ether_udp_read(packet, length, &from);

		} else
#endif
		if(net_if_type == NET_IF_AMQP && amqp_envelope->message.body.len <= 1514) {
			memcpy(Mac2HostAddr(packet), amqp_envelope->message.body.bytes, amqp_envelope->message.body.len);
			ether_dispatch_packet(packet, amqp_envelope->message.body.len);
			amqp_destroy_envelope(amqp_envelope);
			break;
		} else
		{

			// Read packet from sheep_net device
#if defined(__linux__)
			length = read(fd, Mac2HostAddr(packet), net_if_type == NET_IF_ETHERTAP ? 1516 : 1514);
#else
			length = read(fd, Mac2HostAddr(packet), 1514);
#endif
			if (length < 14)
				break;

#if MONITOR
			bug("Receiving Ethernet packet:\n");
			for (int i=0; i<length; i++) {
				bug("%02x ", ReadMacInt8(packet + i));
			}
			bug("\n");
#endif

			// Pointer to packet data (Ethernet header)
			uint32 p = packet;
#if defined(__linux__)
			if (net_if_type == NET_IF_ETHERTAP) {
				p += 2;			// Linux ethertap has two random bytes before the packet
				length -= 2;
			}
#endif

			// Dispatch packet
			ether_dispatch_packet(p, length);
		}
	}
}

// Helper function for port forwarding
static int get_str_sep(char *buf, int buf_size, const char **pp, int sep)
{
	const char *p, *p1;
	int len;
	p = *pp;
	p1 = strchr(p, sep);
	if (!p1)
		return -1;
	len = p1 - p;
	p1++;
	if (buf_size > 0) {
		if (len > buf_size - 1)
			len = buf_size - 1;
		memcpy(buf, p, len);
		buf[len] = '\0';
	}
	*pp = p1;
	return 0;
}

// Set up port forwarding for slirp
static void slirp_add_redirs()
{
	int index = 0;
	const char *str;
	while ((str = PrefsFindString("redir", index++)) != NULL) {
		slirp_add_redir(str);
	}
}

// Add a port forward/redirection for slirp
static int slirp_add_redir(const char *redir_str)
{
	// code adapted from qemu source
	struct in_addr guest_addr = {0};
	int host_port, guest_port;
	const char *p;
	char buf[256];
	int is_udp;
	char *end;
	char str[256];

	p = redir_str;
	if (!p || get_str_sep(buf, sizeof(buf), &p, ':') < 0) {
		goto fail_syntax;
	}
	if (!strcmp(buf, "tcp") || buf[0] == '\0') {
		is_udp = 0;
	} else if (!strcmp(buf, "udp")) {
		is_udp = 1;
	} else {
		goto fail_syntax;
	}

	if (get_str_sep(buf, sizeof(buf), &p, ':') < 0) {
		goto fail_syntax;
	}
	host_port = strtol(buf, &end, 0);
	if (*end != '\0' || host_port < 1 || host_port > 65535) {
		goto fail_syntax;
	}

	if (get_str_sep(buf, sizeof(buf), &p, ':') < 0) {
		goto fail_syntax;
	}
	// 0.0.0.0 doesn't seem to work, so default to a client address
	// if none is specified
	if (buf[0] == '\0' ?
			!inet_aton(CTL_LOCAL, &guest_addr) :
			!inet_aton(buf, &guest_addr)) {
		goto fail_syntax;
	}

	guest_port = strtol(p, &end, 0);
	if (*end != '\0' || guest_port < 1 || guest_port > 65535) {
		goto fail_syntax;
	}

	if (slirp_redir(is_udp, host_port, guest_addr, guest_port) < 0) {
		sprintf(str, "could not set up host forwarding rule '%s'", redir_str);
		WarningAlert(str);
		return -1;
	}
	return 0;

 fail_syntax:
	sprintf(str, "invalid host forwarding rule '%s'", redir_str);
	WarningAlert(str);
	return -1;
}
