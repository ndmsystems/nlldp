/* Copyright (c) 2017 NDM Systems, Inc. http://www.ndmsystems.com/

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <pwd.h>
#include <grp.h>

#include <linux/if.h>
#include <linux/ip.h>
#include <linux/if_packet.h>

/* libndm headers */
#include <ndm/log.h>
#include <ndm/ip_sockaddr.h>
#include <ndm/time.h>
#include <ndm/sys.h>
#include <ndm/attr.h>
#include <ndm/mac_addr.h>
#include <ndm/feedback.h>

#define NESEP_						NDM_FEEDBACK_ENV_SEPARATOR
#define FEEDBACK					"/tmp/run/lddp.fb"

#define POLL_TIME					(60 * 1024) // 60 sec
#define READ_RETRY_MS				100 // ms
#define READ_RETRY_TIMES			5 //

#define ETH_P_LLDP					0x88cc

#define TLV_HDR(id_, len_)			htons((uint16_t)(((id_) << 9) + (len_)))
#define TLV_LEN(hdr_)				(ntohs(hdr_) & 0x01ff)
#define TLV_TAG(hdr_)				((ntohs(hdr_) >> 9) & 0x7f)
#define TLV_HDR_LEN					2
#define OFFSET(s_, p_)				((p_) > (s_) ? (uint8_t *)(p_) - (uint8_t *)(s_) : 0)


struct lldp_tlv
{
	uint16_t hdr;
	union
	{
		uint8_t data[512];
		struct
		{
			uint8_t subtype;
			uint8_t data[511];
		} sub;
		struct
		{
			uint8_t org[3];
			uint8_t subtype;
			uint8_t data[508];
		} org;
	} u;
} NDM_ATTR_PACKED;

static const uint8_t const org_uniq_code[] = { 'N', 'D', 'M' };

/* external configuration */
static const char *user = "nobody";

/* internal state */
static int fd_recv = -1;
static struct pollfd pfds[1];

static bool nlldo_drop_privileges()
{
	if (geteuid() == 0) {
		struct group *grp;
		struct passwd *pwd;

		errno = 0;
		pwd = getpwnam(user);

		if (pwd == NULL) {
			NDM_LOG_ERROR("Unable to get UID for user \"%s\": %s",
				user, strerror(errno));
			return false;
		}

		errno = 0;
		grp = getgrnam(user);

		if (grp == NULL) {
			NDM_LOG_ERROR("Unable to get GID for group \"%s\": %s",
				user, strerror(errno));
			return false;
		}

		if (setgid(grp->gr_gid) == -1) {
			NDM_LOG_ERROR("Unable to set new group \"%s\": %s",
				user, strerror(errno));
			return false;
		}

		if (setuid(pwd->pw_uid) == -1) {
			NDM_LOG_ERROR("Unable to set new user \"%s\": %s",
				user, strerror(errno));
			return false;
		}
	}

	return true;
}

static bool nlldo_set_nonblock(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) == -1) {
		const int err = errno;

		NDM_LOG_ERROR("unable to get socket flags: %s", strerror(err));

		return false;
	}

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		const int err = errno;

		NDM_LOG_ERROR("unable to set socket flags: %s", strerror(err));

		return false;
	}

	return true;
}


static bool nlldo_nonblock_read(
		int fd, void *p, size_t buf_size, size_t *bytes_read, struct sockaddr_ll *sa)
{
	socklen_t len = sizeof(*sa);
	const ssize_t n = recvfrom(fd, p, buf_size, 0, (struct sockaddr *)sa, &len);

	*bytes_read = 0;

	if (n < 0) {
		const int error = errno;

		if (error == EINTR || error == EAGAIN || error == EWOULDBLOCK) {
			return false;

		} else {
			NDM_LOG_ERROR("unable receive packet: %s", strerror(error));

			return false;
		}
	} else if (len != sizeof(*sa) - 2) {
		NDM_LOG_ERROR("invalid address size");

		return false;

	} else {
		*bytes_read = (size_t)n;
	}

	return true;
}

static void nlldo_handle_packet()
{
	uint8_t packet[2048];
	uint8_t *p = packet;
	uint16_t ethertype;
	size_t bytes_read = 0;
	struct sockaddr_ll sa;
	struct lldp_tlv *tlv;
	struct ndm_mac_addr_t p_mac;
	uint32_t p_management_ip = 0;
	uint8_t p_description[384];
	uint8_t p_mode[32];
	uint16_t p_port = 0;
	uint8_t p_fw[128];

	ndm_mac_addr_init(&p_mac);
	memset(p_description, 0, sizeof(p_description));
	memset(p_mode, 0, sizeof(p_mode));
	memset(p_fw, 0, sizeof(p_fw));

	if (!nlldo_nonblock_read(fd_recv, packet, sizeof(packet), &bytes_read, &sa) ||
		bytes_read == 0) {

		NDM_LOG_ERROR("unable to receive LLDP packet: %u", bytes_read);

		return;
	}

	if (bytes_read == sizeof(packet))
		NDM_LOG_ERROR("packet is truncated");

	if (sa.sll_protocol != htons(ETH_P_LLDP))
		return;

	ethertype = *((uint16_t *)(p + 2 * ETHER_ADDR_LEN));

	if (ethertype != htons(ETH_P_LLDP))
		return;

	if (ethertype == htons(ETH_P_8021Q) &&
		*((uint16_t *)(p + 2 * ETHER_ADDR_LEN + 4)) != htons(ETH_P_LLDP))
		return;

	if (ethertype == htons(ETH_P_8021Q))
		p += 2 * ETHER_ADDR_LEN + 2 + 4;
	else
		p += 2 * ETHER_ADDR_LEN + 2;

	if (OFFSET(packet, p) + TLV_HDR_LEN > bytes_read) {
		NDM_LOG_ERROR("malformed packet");

		return;
	}

	while (OFFSET(packet, p) + TLV_HDR_LEN <= bytes_read) {
		tlv = (struct lldp_tlv *)p;

		if (OFFSET(packet, p) + TLV_HDR_LEN + TLV_LEN(tlv->hdr) > bytes_read) {
			NDM_LOG_ERROR("len: %d", TLV_LEN(tlv->hdr));
			break;
		}

		switch (TLV_TAG(tlv->hdr)) {
			case 1: /* Chassis id */
				if (tlv->u.sub.subtype == 4) { /* mac address */
					if (!ndm_mac_addr_assign_array(&p_mac, tlv->u.sub.data, ETHER_ADDR_LEN)) {
						goto exit;
					}
				} else
					goto exit;
				break;

			case 8: /* Management address */
				if ((TLV_LEN(tlv->hdr) >= 6) &&
					(*((uint8_t *)(tlv->u.data)) == 5) && /* address string length */
					(*((uint8_t *)(tlv->u.data + 1)) == 1)) { /* address subtype: IPv4 */
						p_management_ip = *((uint32_t *)(tlv->u.data + 2));
				} else
					goto exit;
				break;

			case 6: /* System description */
				if (TLV_LEN(tlv->hdr) < sizeof(p_description)) {
					memcpy(p_description, tlv->u.data, TLV_LEN(tlv->hdr));
				}
				break;

			case 127:
				if (!memcmp(tlv->u.org.org, org_uniq_code, sizeof(org_uniq_code))) {
					/* NDM Systems private tags */
					switch (tlv->u.org.subtype) {
						case 1: /* System mode */
							if (TLV_LEN(tlv->hdr) - 4 < sizeof(p_mode)) {
								memcpy(p_mode, tlv->u.org.data, TLV_LEN(tlv->hdr) - 4);
							}
							break;
						case 2: /* System port */
							if (TLV_LEN(tlv->hdr) - 4 == sizeof(p_port)) {
								p_port = ntohs(*((uint16_t*)tlv->u.org.data));
							}
							break;
						case 3: /* FW version */
							if (TLV_LEN(tlv->hdr) - 4 < sizeof(p_fw)) {
								memcpy(p_fw, tlv->u.org.data, TLV_LEN(tlv->hdr) - 4);
							}
						default:
							break;
					};
				}
				break;

			case 0: /* End of LLDPDU */
				break;

			default:
				break;
		};

		p += TLV_HDR_LEN + TLV_LEN(tlv->hdr);
	}

	{
		const char *args[] =
		{
			FEEDBACK,
			"lldp",
			NULL
		};

		if( !ndm_feedback(NDM_FEEDBACK_TIMEOUT_MSEC,
				args,
				"%s=%s" NESEP_
				"%s=%u" NESEP_
				"%s=%s" NESEP_
				"%s=%s" NESEP_
				"%s=%u" NESEP_
				"%s=%d" NESEP_
				"%s=%s",
				"mac", ndm_mac_addr_as_string(&p_mac),
				"ip", p_management_ip,
				"desc", p_description,
				"mode", p_mode,
				"http_port", p_port,
				"inderface_idx", sa.sll_ifindex,
				"fw_version", p_fw) ) {
			NDM_LOG_ERROR("unable to communicate with ndm");
		}
	}

exit:
	;;
}

static void nlldo_loop()
{
	while (!ndm_sys_is_interrupted()) {
		int ret = poll(pfds, NDM_ARRAY_SIZE(pfds), POLL_TIME);
		bool has_error = false;

		if (ndm_sys_is_interrupted())
			return;

		if (ret < 0) {
			const int err = errno;

			if (err == EINTR || err == EAGAIN) {
				return;
			}

			NDM_LOG_ERROR("poll error: %s", strerror(err));

			ndm_sys_sleep_msec(NDM_SYS_SLEEP_GRANULARITY_MSEC);

			goto reinit;
		}

		if (ret == 0) {
			continue;
		}

		for (unsigned long i = 0; i < NDM_ARRAY_SIZE(pfds); ++i) {
			if ((pfds[i].revents & POLLERR) || (pfds[i].revents & POLLHUP)) {
				has_error = true;
			}

			if (pfds[i].fd != -1 && (pfds[i].revents & POLLNVAL)) {
				has_error = true;
			}
		}

		if (has_error) {
			NDM_LOG_ERROR("socket was unexpectedly closed");

			return;
		}

		for (unsigned long i = 0; i < NDM_ARRAY_SIZE(pfds); ++i) {
			if ((pfds[i].revents & POLLIN) && pfds[i].fd == fd_recv) {
				nlldo_handle_packet();
			}
		}

reinit:
		pfds[0].fd = fd_recv;
		pfds[0].events = POLLIN;
		pfds[0].revents = 0;
	}
}

static void nlldo_main()
{
	fd_recv = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_LLDP));

	if (fd_recv == -1) {
		const int err = errno;

		NDM_LOG_ERROR("unable to open recv socket: %s", strerror(err));

		goto cleanup;
	}

	if (!nlldo_set_nonblock(fd_recv)) {
		goto cleanup;
	}

	if (!nlldo_drop_privileges()) {
		goto cleanup;
	}

	memset(&pfds, 0, sizeof(pfds));

	pfds[0].fd = fd_recv;
	pfds[0].events = POLLIN;

	nlldo_loop();

cleanup:

	if (fd_recv != -1)
		close(fd_recv);
}

int main(int argc, char *argv[])
{
	int ret_code = EXIT_FAILURE;
	const char *const ident = ndm_log_get_ident(argv);
	int c;

	for (;;) {
		c = getopt(argc, argv, "u:");

		if (c < 0)
			break;

		switch (c) {

		case 'u':
			user = optarg;
			break;


		default:
			NDM_LOG_ERROR("unknown option \"%c\"", (char) optopt);

			return ret_code;
		}
	}

	if (!ndm_log_init(ident, NULL, false, true)) {
		fprintf(stderr, "%s: failed to initialize a log\n", ident);

		return ret_code;
	}

	if (!ndm_sys_init()) {
		NDM_LOG_ERROR("unable to init libndm");

		return ret_code;
	}

	if (!ndm_sys_set_default_signals()) {
		NDM_LOG_ERROR("unable set signal handlers");

		return ret_code;
	}

	nlldo_main();

	return EXIT_SUCCESS;
}
