#ifndef P2P_H
#define P2P_H

#include <stdint.h>
#include <stdbool.h>
#include <enet/enet.h>

#if _WIN32
// TODO: test these some more once the other compile errors are fixed
#include <Ws2tcpip.h> /* inet_pton() */
#include <iphlpapi.h> /* GetBestInterfaceEx(), GetAdaptersInfo() */
// TODO: remove libs from build.bat and use these instead?
//#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "IPHLPAPI.lib")
#endif /* _WIN32 */

#define ARRAY_LEN(ARR) (sizeof ((ARR)) / sizeof ((ARR)[0]))
#ifndef ASSERT
#define ASSERT(EXP)                                                           \
  if (!(EXP))                                                                 \
    {                                                                         \
      printf ("<Assertion Failed> %s() (%s:%d) \n", __func__, __FILE__, __LINE__);      \
      *(volatile int *) 0 = 0; \
    }
#if _WIN32
// TODO: ASSERT_FP() from win32-assertions.patch
#define ASSERT_FP ASSERT
#else /* LINUX */
#define ASSERT_FP ASSERT
#endif /* _WIN32 */
#endif /* ASSERT */

#define ptr_from_u32(u) (void *) ((char *) 0 + (u))
#define u32_from_ptr(p) (unsigned long) ((char *) p - (char *) 0)

#define P2P_SERVER_IP "127.0.0.1"
#define P2P_MAGIC 117
#define P2P_VERSION 1
#define P2P_IPSTRLEN (16 + 1 + 5) // 255.255.255.255:65535\n
#define P2P_REG_PACKET_LEN (sizeof (struct p2p_header) + sizeof (struct p2p_registration_packet))

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef void connect_f (u32 id, void *user_data);
typedef void receive_f (u32 id, u8 *data, size_t len, void *user_data);
typedef void disconnect_f (u32 id, void *user_data);

typedef enum p2p_enum
{
    P2P_ENUM_INVALID = 0,

    P2P_OP_MODE_MIN = 1000,
    P2P_OP_MODE_NONE,
    P2P_OP_MODE_CLIENT,
    P2P_OP_MODE_SERVER,
    P2P_OP_MODE_MATCH_MAKING_SERVER,
    P2P_OP_MODE_MAX,

    P2P_JOIN_MODE_MIN = 2000,
    P2P_JOIN_MODE_PASSIVE,
    P2P_JOIN_MODE_ACTIVE,
    P2P_JOIN_MODE_MAX,

    P2P_REGISTER_STATE_IN_PROGRESS,
    P2P_REGISTER_STATE_DONE,

    P2P_PEER_STATE_MIN = 3000,
    P2P_PEER_STATE_UNINITIALISED,
    P2P_PEER_STATE_REGISTERED,
    P2P_PEER_STATE_LOOKING_FOR_PEER,
    P2P_PEER_STATE_FOUND_PEER,
    P2P_PEER_STATE_MAX,

    P2P_CONNECTION_STATE_MIN = 4000,
    P2P_CONNECTION_STATE_IDLE,
    P2P_CONNECTION_STATE_IN_PROGRESS,
    P2P_CONNECTION_STATE_MAX,

    P2P_EVENT_TYPE_MIN = 5000,
    P2P_EVENT_TYPE_CONNECT,
    P2P_EVENT_TYPE_RECEIVE,
    P2P_EVENT_TYPE_DISCONNECT,
    P2P_EVENT_TYPE_MAX,

    P2P_PACKET_DIRECTION_MIN = 000,
    P2P_PACKET_DIRECTION_IN,
    P2P_PACKET_DIRECTION_OUT,
    P2P_PACKET_DIRECTION_MAX,

    P2P_PACKET_TYPE_MIN = 7000,
    P2P_PACKET_TYPE_REGISTRATION,
    P2P_PACKET_TYPE_REGISTRATION_ACK,
    P2P_PACKET_TYPE_SERVER_LIST_REQUEST,
    P2P_PACKET_TYPE_SERVER_LIST_SEND,
    P2P_PACKET_TYPE_JOIN,
    P2P_PACKET_TYPE_DATA, // user data
    P2P_PACKET_TYPE_MAX,
} p2p_enum;

/*
 * TYPE - p2p_enum definition prefix
 * VALUE - p2p_enum value
 *
 * For example:
 *
 *   P2P_ENUM_VALID(P2P_PACKET_TYPE, pkt->type);
 *
 * would expand to
 *
 *   (P2P_PACKET_TYPE_MIN < pkt->type && pkt->type < P2P_PACKET_TYPE_MAX);
 */
#define P2P_ENUM_VALID(TYPE, VALUE) (TYPE ## _MIN < (VALUE) && (VALUE) < TYPE ## _MAX)
#define P2P_ENUM_CHECK(FLAGS, VALUE) (((FLAGS) & (VALUE)) == (VALUE))

#define P2P_NAME_LEN 32 // TODO: probs a bit too large - maybe 16?

struct p2p_connection
{
    u32 id;

    p2p_enum state;
    p2p_enum mode;
    ENetAddress address;

    ENetPeer *enet_peer;

    struct p2p_peer *parent;
};

struct p2p_peer
{
    char name[P2P_NAME_LEN];

    struct p2p_connection pending_connections[8];
    u32 pending_count;

    ENetPeer *active_connection; // TODO: enum indicating which one?
};

struct p2p
{
    char name[P2P_NAME_LEN];
    p2p_enum mode;
    p2p_enum state;
    float dt;

    // Local host
    ENetHost *host;

    // Match-making server
    struct p2p_peer *mm_server;

    u32 peer_count;
    struct p2p_peer peers[32];

    connect_f *connect;
    receive_f *receive;
    disconnect_f *disconnect;

    void *connect_data;
    void *receive_data;
    void *disconnect_data;
};

struct p2p_header
{
    u32 magic;
    u32 version;
    p2p_enum packet_type;
    size_t len;
};

struct p2p_registration_packet
{
    p2p_enum mode;
    char name[P2P_NAME_LEN];
    ENetAddress private; // u8 *private_ip;
};

struct p2p_registration_ack
{
    char msg[32];
};

struct p2p_join_packet
{
    u32 id;
    char name[P2P_NAME_LEN];

    p2p_enum join_mode;

    ENetAddress public; // u8 *public;
    ENetAddress private; // u8 *private;
};

struct p2p_join_ack
{
    u32 id;
    bool ok;
};

static const struct p2p_peer P2P_PEER_ZERO = {0};
static const struct p2p_connection P2P_CONNECTION_ZERO = {0};

char *
p2p_enum_str (p2p_enum val)
{
    switch (val)
    {
        case P2P_OP_MODE_NONE:                 return "P2P_OpMode_None";
        case P2P_OP_MODE_CLIENT:               return "P2P_OpMode_Client";
        case P2P_OP_MODE_SERVER:               return "P2P_OpMode_Server";
        case P2P_OP_MODE_MATCH_MAKING_SERVER:  return "P2P_OpMode_MatchMakingServer";
        case P2P_JOIN_MODE_PASSIVE:            return "P2P_JoinMode_Passive";
        case P2P_JOIN_MODE_ACTIVE:             return "P2P_JoinMode_Active";
        case P2P_PEER_STATE_UNINITIALISED:     return "P2P_PeerState_Uninitialised";
        case P2P_PEER_STATE_REGISTERED:        return "P2P_PeerState_Registered";
        case P2P_PEER_STATE_LOOKING_FOR_PEER:  return "P2P_PeerState_LookingForPeer";
        case P2P_PEER_STATE_FOUND_PEER:        return "P2P_PeerState_FoundPeer";
        case P2P_CONNECTION_STATE_IDLE:        return "P2P_ConnectionState_Idle";
        case P2P_CONNECTION_STATE_IN_PROGRESS: return "P2P_ConnectionState_InProgress";
        case P2P_PACKET_TYPE_REGISTRATION:     return "P2P_PacketType_Registration";
        case P2P_PACKET_TYPE_REGISTRATION_ACK: return "P2P_PacketType_RegistrationAck";
        case P2P_PACKET_TYPE_SERVER_LIST_REQUEST: return "P2P_PacketType_ServerListRequest";
        case P2P_PACKET_TYPE_SERVER_LIST_SEND: return "P2P_PacketType_ServerListSend";
        case P2P_PACKET_TYPE_JOIN:             return "P2P_PacketType_Join";
        case P2P_PACKET_TYPE_DATA:             return "P2P_PacketType_Data";
        default:
        {
            fprintf (stderr, "Unknown P2P_Enum value: %d\n", val);
            return "???";
        }
    }
}

char *
p2p_enet_addr_to_str (ENetAddress *addr, char *buf, size_t len)
{
  u8 *octets = (u8 *) &addr->host;

  snprintf (buf, len, "%u.%u.%u.%u:%u", octets[0], octets[1], octets[2],
            octets[3], addr->port);

  return buf;
}

void
p2p_packet_hexdump (u8 *data, size_t len)
{
    int cols = 0;

    printf ("packet hexdump (%zu bytes)\n", len);
    for (u32 i = 0; i < len; i++)
    {
        printf (" %02X", data[i]);
        ++cols;
        if (cols == 4)
        {
            printf (" ");
        }
        else if (cols == 8)
        {
            printf ("\n");
            cols = 0;
        }
    }
    printf ("\n");
}

void
p2p_packet_dump (u8 *data, p2p_enum direction, ENetAddress *addr)
{
    char ipstr[P2P_IPSTRLEN];

    switch (direction)
    {
        case P2P_PACKET_DIRECTION_IN:
        {
            printf ("Packet [IN] from [%s]:\n", p2p_enet_addr_to_str (addr, ipstr, sizeof (ipstr)));
        } break;
        case P2P_PACKET_DIRECTION_OUT:
        {
            printf ("Packet [OUT] to [%s]:\n", p2p_enet_addr_to_str (addr, ipstr, sizeof (ipstr)));
        } break;
    }

    struct p2p_header *hdr = (struct p2p_header *) data;

    printf ("Header (%zu bytes)\n", sizeof (struct p2p_header));
    printf ("  Magic   : %u\n", hdr->magic);
    printf ("  Version : %u\n", hdr->version);
    printf ("  Type    : %s (%u)\n", p2p_enum_str (hdr->packet_type), hdr->packet_type);
    printf ("  Length  : %zu\n", hdr->len);

    switch (hdr->packet_type)
    {
        case P2P_PACKET_TYPE_REGISTRATION:
        {
            struct p2p_registration_packet *payload = (struct p2p_registration_packet *) (data + sizeof (struct p2p_header));

            printf ("Payload (%zu bytes)\n", sizeof (struct p2p_registration_packet));
            printf ("  Name    : %s\n", payload->name);
            printf ("  Mode    : %s (%u)\n", p2p_enum_str (payload->mode), payload->mode);
            printf ("  Private : %s\n", p2p_enet_addr_to_str (&payload->private, ipstr, sizeof (ipstr)));
        } break;
        case P2P_PACKET_TYPE_REGISTRATION_ACK:
        {
            struct p2p_registration_ack *payload = (struct p2p_registration_ack *) (data + sizeof (struct p2p_header));

            printf ("Payload (%zu bytes)\n", sizeof (struct p2p_registration_ack));
            printf ("  Msg     : %s\n", payload->msg);
        } break;
        case P2P_PACKET_TYPE_JOIN:
        {
            struct p2p_join_packet *payload = (struct p2p_join_packet *) (data + sizeof (struct p2p_header));

            printf ("Payload (%zu bytes)\n", sizeof (struct p2p_join_packet));
            printf ("  ID      : %u\n", payload->id);
            printf ("  Name    : %s\n", payload->name);
            printf ("  Mode    : %s (%u)\n", p2p_enum_str (payload->join_mode), payload->join_mode);
            printf ("  Public  : %s\n", p2p_enet_addr_to_str (&payload->public, ipstr, sizeof (ipstr)));
            printf ("  Private : %s\n", p2p_enet_addr_to_str (&payload->private, ipstr, sizeof (ipstr)));
        } break;
        case P2P_PACKET_TYPE_DATA:
        {
            u8 *payload = (u8 *) (data + sizeof (struct p2p_header));
	    p2p_packet_hexdump (payload, hdr->len);
        } break;
    }
}

u32
hash_string (char *string, u32 hash)
{
  while (*string)
    {
      char c = *string++;

      if ((c >= 'a') && (c <= 'z'))
        {
          c = (c - 'a') + 'A';
        }

      hash += c;
      hash += (hash << 10);
      hash ^= (hash >> 6);
    }

  return hash;
}

u32
p2p_generate_id (ENetPeer *peer)
{
  // TODO: ENDIANESS???
    return peer->address.host ^ peer->address.port;
}

ENetPeer *
p2p_get_enet_peer_by_id (ENetHost *host, u32 id)
{
  ENetPeer *peer = NULL;

  for (peer = host->peers; peer < &host->peers[host->peerCount]; ++peer)
    {
      if (peer->state == ENET_PEER_STATE_CONNECTED)
        {
          u32 peer_id = p2p_generate_id (peer);
          if (peer_id == id)
            {
              return peer;
            }
        }
    }

  return NULL;
}

void
DEBUG_peer_dump (struct p2p *p2p)
{
  char ipstr[P2P_IPSTRLEN] = {0};

    for (u32 i = 0; i < p2p->peer_count; i++)
    {
        struct p2p_peer *peer = &p2p->peers[i];

        printf ("<peer: name=%s pending_count=%u active(enet_id)=%u (0x%p)>\n",
                 peer->name, peer->pending_count,
                 (peer->active_connection ? peer->active_connection->incomingPeerID : 1337),
                 peer->active_connection);

        for (u32 j = 0; j < peer->pending_count; j++)
        {
            struct p2p_connection *conn = &peer->pending_connections[j];
            printf ("  <conn: id=%u address=%s state=%s>\n",
                    conn->id, p2p_enet_addr_to_str (&conn->address, ipstr, sizeof (ipstr)), p2p_enum_str (conn->state));
        }
    }
}

u32
push_pending_connection (struct p2p_peer *peer, u32 ip, u16 port, p2p_enum join_mode)
{
    bool found = false;
    u32 id = 0;

    for (u32 i = 0; i < peer->pending_count; i++)
    {
        struct p2p_connection *conn = &peer->pending_connections[i];

        if (P2P_ENUM_VALID (P2P_CONNECTION_STATE, conn->state) &&
            conn->id == (ip ^ port))
        {
            found = true;
            printf ("[conn:PENDING] found existing connection (%u) for peer [%s]\n", conn->id, peer->name);
            break;
        }
    }

    if (!found)
    {
        if (peer->pending_count + 1 < ARRAY_LEN (peer->pending_connections))
        {
            struct p2p_connection *conn = &peer->pending_connections[peer->pending_count++];
            *conn = P2P_CONNECTION_ZERO;

            id = conn->id = (ip ^ port);
            conn->address.host = ip;
            conn->address.port = port;
            conn->state = P2P_CONNECTION_STATE_IDLE;
            conn->mode = join_mode;
            conn->parent = peer;

            printf ("[conn:PENDING] pushed pending connection (%u) for [%s]\n", id, peer->name);
        }
        else
        {
            fprintf (stderr, "[conn:PENDING] Max connections reached for [%s]\n", peer->name);
        }
    }

    return id;
}

int
send_hello (struct p2p *p2p, struct p2p_connection *conn)
{
    const char buf[] = "hello";
    int len = sizeof (buf);
    struct sockaddr_in sin = {0};

    sin.sin_family = AF_INET;
    sin.sin_port = ENET_HOST_TO_NET_16 (conn->address.port);
    sin.sin_addr.s_addr = conn->address.host;

    int ret = sendto (p2p->host->socket, buf, len, 0, (struct sockaddr *) &sin, sizeof (sin));
#if _WIN32
    if (ret == SOCKET_ERROR)
    {
        if (WSAGetLastError () == WSAEWOULDBLOCK)
        {
            ret = 0; // retry?
        }
        else
        {
            ret = -1; // error?
        }
    }
    // TODO: linux else?
#endif

    return ret;
}

// TODO: need to step through this logic again to make sure it makes sense - same with complete_pending_connections()
// TODO: this only works for public endpoints, and not within a LAN.
//  - maybe try first over LAN (private endpoints), and after a timeout try WAN (public endpoints)
void
process_pending_connections (struct p2p *p2p)
{
    u32 processed = 0;

    for (u32 i = 0; i < p2p->peer_count; i++)
    {
        struct p2p_peer *peer = &p2p->peers[i];

        for (u32 j = 0; j < peer->pending_count; j++)
        {
            struct p2p_connection *conn = &peer->pending_connections[j];

            if (conn->mode == P2P_JOIN_MODE_ACTIVE)
            {
                if (conn->state == P2P_CONNECTION_STATE_IDLE)
                {
                    // TODO: can we eventually collapse the connection structure into just a ENetPeer?
                    conn->enet_peer = enet_host_connect (p2p->host, &conn->address, 2, 0);
                    ASSERT (conn->enet_peer);
                    conn->parent = peer;
                    conn->state = P2P_CONNECTION_STATE_IN_PROGRESS;

                    printf ("[conn:PROCESS] initiating connection (%u) for peer [%s]\n", conn->id, peer->name);

                    processed++;
                }
            }
            else if (conn->mode == P2P_JOIN_MODE_PASSIVE)
            {
                if (conn->state == P2P_CONNECTION_STATE_IDLE)
                {
                    conn->parent = peer;
                    conn->state = P2P_CONNECTION_STATE_IN_PROGRESS;
                }
                else if (conn->state == P2P_CONNECTION_STATE_IN_PROGRESS)
                {
                    // TODO: don't send every frame - 
		    // once we have a timer working, also add a timeout
		    static float t = 0.0f;
		    t += p2p->dt;
		    if (t >= 5000)
		    {
			    t = 0.0f;
			    int ret = send_hello (p2p, conn);

			    printf ("[conn:PROCESS] sending hello to [%s] (ret=%d)\n", conn->parent->name, ret);
			    ASSERT (ret > 0);
		    }
                }
                processed++;
            }
        }
    }

#if 1
    if (processed > 0)
    {
        DEBUG_peer_dump (p2p);
    }
#endif
}

void
complete_pending_connection (struct p2p *p2p, u32 id, ENetPeer *enet_peer)
{
    for (u32 i = 0; i < p2p->peer_count; i++)
    {
        struct p2p_peer *peer = &p2p->peers[i];
        u32 pending = peer->pending_count;
        u32 completed = 0;

        for (u32 j = 0; j < pending; j++)
        {
            char ipstr[P2P_IPSTRLEN];
            struct p2p_connection *conn = &peer->pending_connections[j];

            p2p_enet_addr_to_str (&conn->address, ipstr, sizeof (ipstr));

            // TODO: this would be where we compare multiple connections for the same peer
            // and chose one!
            if (conn->id == id)
            {
                ASSERT (conn->state == P2P_CONNECTION_STATE_IN_PROGRESS);

                if (conn->mode == P2P_JOIN_MODE_ACTIVE)
                {
                    if (!peer->active_connection)
                    {
                        peer->active_connection = conn->enet_peer;
                        printf ("[conn:COMPLETE] Peer [%s] setting active connection to [%s]\n",
                                peer->name,
                                p2p_enet_addr_to_str (&peer->active_connection->address, ipstr, sizeof (ipstr)));
                        completed++;
                    }
                    else
                    {
                        // TODO: not sure if we need this branch anymore
                        printf ("[conn:COMPLETE] Peer [%s] has existing active connection to [%s]\n",
                                peer->name,
                                p2p_enet_addr_to_str (&peer->active_connection->address, ipstr, sizeof (ipstr)));
                    }
                }
                else if (conn->mode == P2P_JOIN_MODE_PASSIVE)
                {
                    ASSERT (!conn->enet_peer);
                    conn->enet_peer = enet_peer;
                    conn->parent->active_connection = enet_peer;
                    completed++;
                }

                if (completed > 0)
                {
                    u32 last_index = peer->pending_count - 1;
                    if (j == last_index)
                    {
                        /* If this connection was the last in the list, zero it out */
                        memset (conn, 0, sizeof (struct p2p_connection));
                    }
                    else
                    {
                        /* otherwise, copy the last one into this slot */
                        struct p2p_connection *last = &peer->pending_connections[last_index];

                        memcpy (conn, last, sizeof (struct p2p_connection));
                    }

                    peer->pending_count--;
                }
            }
        }

        if (completed > 0)
        {
            printf ("[conn:COMPLETE] completed %u of %u connections for %s\n", completed, pending, peer->name);
        }
    }

#if 1
    DEBUG_peer_dump (p2p);
#endif
}

static void
__get_mm_server_address (ENetAddress *address)
{
  // TODO: get from a config file maybe??
  address->host = inet_addr ("127.0.0.1");
  address->port = 1717;
}

struct p2p_peer *
p2p_peer_create (struct p2p *p2p, char *name, char *ip, u16 port)
{
    struct p2p_peer *p = NULL;

    if (p2p->peer_count + 1 < ARRAY_LEN (p2p->peers))
    {
        p = &p2p->peers[p2p->peer_count++];
        *p = P2P_PEER_ZERO;

        if (name)
        {
            snprintf (p->name, sizeof (p->name), "%s", name);
        }

        if (ip && port > 0)
        {
          push_pending_connection (p, inet_addr (ip), port, P2P_JOIN_MODE_ACTIVE);
        }
    }
    else
    {
        fprintf (stderr, "Max peers reached\n");
    }

#if 1
    DEBUG_peer_dump (p2p);
#endif

    return p;
}

u16
get_port (ENetHost *host)
{
    struct sockaddr_in sin;
    int addrlen = sizeof (struct sockaddr_in);
    u16 port = 0;

    if (getsockname (host->socket, (struct sockaddr *) &sin, &addrlen) == 0 &&
        sin.sin_family == AF_INET &&
        addrlen == sizeof (struct sockaddr_in))
    {
        port = ntohs (sin.sin_port);
    }

    ASSERT (port > 0);

    return port;
}

#if _WIN32
static DWORD
get_best_ifindex (char *dest_ip)
{
    struct sockaddr_in saddr = {0};
    DWORD ret = 0;

    unsigned long addr = inet_addr (dest_ip); // TODO: inet_pton ()
    saddr.sin_addr.s_addr = addr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons (9);

    DWORD ifindex;
    if (GetBestInterfaceEx ((struct sockaddr *) &saddr, &ifindex) == NO_ERROR)
    {
        ret = ifindex;
    }

    return ret;
}

static bool
get_ip_from_interface (DWORD ifindex, char *ip, size_t ip_len)
{
    IP_ADAPTER_INFO *adapter_info;
    IP_ADAPTER_INFO *adapter = NULL;
    ULONG len = sizeof (IP_ADAPTER_INFO);
    DWORD ret = 0;
    bool ok = false;

    adapter_info = (IP_ADAPTER_INFO *) malloc (sizeof (IP_ADAPTER_INFO));
    ASSERT_FP (adapter_info);

    if (GetAdaptersInfo (adapter_info, &len) == ERROR_BUFFER_OVERFLOW)
    {
        free (adapter_info);

        adapter_info = (IP_ADAPTER_INFO *) malloc (len);
        ASSERT_FP (adapter_info);
    }

    if ((ret = GetAdaptersInfo (adapter_info, &len)) == NO_ERROR)
    {
        adapter = adapter_info;
        while (adapter)
        {
            if (adapter->ComboIndex == ifindex)
            {
                snprintf (ip, ip_len, "%s", adapter->IpAddressList.IpAddress.String);
                ok = true;
                break;
            }
            adapter = adapter->Next;
        }
    }

    if (adapter_info)
    {
        free (adapter_info);
    }

    return ok;
}
#endif /* _WIN32 */

bool
get_local_private_ip (char *target_ip, char *ipstr, size_t len)
{
    bool ok = false;

#if _WIN32
    /* If we can't get the interface for the default route then it's
     * likely the target IP is the loopback, but it is less likely
     * that the target IP is unreachable. In that case, try Google.
     * If THAT fails then we'll just set the IP as the loopback. */
    if (get_ip_from_interface (get_best_ifindex (target_ip), ipstr, len) ||
        get_ip_from_interface (get_best_ifindex ("8.8.8.8"), ipstr, len) ||
        snprintf (ipstr, len, "127.0.0.1") > 0)
    {
        ok = true;
    }
#else /* _LINUX_ */
    // TODO: win32 version tries to connect to target_ip first, then
    //       tries google.

    int sock = socket (AF_INET, SOCK_DGRAM, 0);
    if (sock > -1)
    {
        struct sockaddr_in sin = {0};
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = inet_addr ("8.8.8.8"); // google
        sin.sin_port = htons (53); // dns
        int ret = connect (sock, (struct sockaddr *) &sin, sizeof (sin));
        // TODO: if (ret > ..)
        {
            struct sockaddr_in name;
            socklen_t namelen = sizeof (name);
            if (getsockname (sock, (struct sockaddr *) &name, &namelen) == 0 &&
                inet_ntop (AF_INET, &name.sin_addr, ipstr, len))
            {
                // TODO: maybe we return .sin_addr here intead of
                // converting to string and back again?
                // Can we also get the port here to eliminate the
                // need for get_port()???
                // Also does this work on windows???
                ok = true;
            }
        }

        close (sock);
    }
#endif /* _WIN32 */

    // printf ("Using [%s] as private IP\n", ipstr);

    return ok;
}

ENetPeer *
get_enet_peer_by_id (struct p2p *p2p, u32 id)
{
    ENetPeer *ret = NULL;

    for (u32 i = 0; i < p2p->peer_count; i++)
    {
        struct p2p_peer *peer = &p2p->peers[i];

        if (peer->active_connection)
        {
            u32 host = peer->active_connection->address.host;
            u16 port = peer->active_connection->address.port;

            if ((host ^ port) == id)
            {
                ret = peer->active_connection;
                break;
            }
        }
    }

    return ret;
}

void
send_registration_packet (struct p2p *p2p, u32 id)
{
    u8 buf[P2P_REG_PACKET_LEN] = {0};
    char local_private_ip[32] = {0};

    u8 *ptr = buf;

    struct p2p_header *hdr = (struct p2p_header *) ptr;
    hdr->magic = P2P_MAGIC;
    hdr->version = P2P_VERSION;
    hdr->packet_type = P2P_PACKET_TYPE_REGISTRATION;
    hdr->len = sizeof (struct p2p_registration_packet);

    struct p2p_registration_packet *reg = (struct p2p_registration_packet *) (ptr + sizeof (struct p2p_header));
    reg->mode = p2p->mode;
    reg->private.port = get_port (p2p->host);

    ASSERT (get_local_private_ip (P2P_SERVER_IP, local_private_ip, sizeof (local_private_ip)));

    inet_pton (AF_INET, local_private_ip, &reg->private.host);
    snprintf (reg->name, sizeof (reg->name), "%s", p2p->name);

    ENetPacket *packet = enet_packet_create (buf, sizeof (buf), ENET_PACKET_FLAG_RELIABLE);
    ENetPeer *dest = get_enet_peer_by_id (p2p, id);
    enet_peer_send (dest, 0, packet);

#if 1
    p2p_packet_dump (buf, P2P_PACKET_DIRECTION_OUT, &dest->address);
    p2p_packet_hexdump (buf, sizeof (buf));
#endif
}

static void
request_server_list (struct p2p *p2p)
{
    ASSERT (p2p->mm_server);

    u8 buf[sizeof (struct p2p_header)] = {0};

    struct p2p_header *hdr = (struct p2p_header *) buf;
    hdr->magic = P2P_MAGIC;
    hdr->version = P2P_VERSION;
    hdr->packet_type = P2P_PACKET_TYPE_SERVER_LIST_REQUEST;
    hdr->len = sizeof (struct p2p_header);

    ENetPacket *packet = enet_packet_create (buf, sizeof (buf), ENET_PACKET_FLAG_RELIABLE);
    ENetPeer *dest = p2p->mm_server->active_connection;
    enet_peer_send (dest, 0, packet);

#if 1
    p2p_packet_dump (buf, P2P_PACKET_DIRECTION_OUT, &dest->address);
    p2p_packet_hexdump (buf, sizeof (buf));
#endif
}

static void
send_server_list (struct p2p *p2p, u32 id)
{
    u8 buf[sizeof (struct p2p_header) + (8 * sizeof (u8))] = {0};

    struct p2p_header *hdr = (struct p2p_header *) buf;
    hdr->magic = P2P_MAGIC;
    hdr->version = P2P_VERSION;
    hdr->packet_type = P2P_PACKET_TYPE_SERVER_LIST_SEND;

    u8 *ptr = (u8 *) (buf + sizeof (struct p2p_header));
    u32 i = 0;
    ptr[i++] = 1;
    ptr[i++] = (u8) 'b';
    ptr[i++] = (u8) 'o';
    ptr[i++] = (u8) 'b';
    ptr[i++] = (u8) '\0';
    ptr[i++] = 7;
    ptr[i++] = 16;
    ptr[i++] = 117;

    hdr->len = sizeof (struct p2p_header) + i;

    ENetPacket *packet = enet_packet_create (buf, sizeof (buf), ENET_PACKET_FLAG_RELIABLE);
    ENetPeer *dest = p2p->mm_server->active_connection;
    enet_peer_send (dest, 0, packet);

#if 1
    p2p_packet_dump (buf, P2P_PACKET_DIRECTION_OUT, &dest->address);
    p2p_packet_hexdump (buf, sizeof (buf));
#endif
}

static void
send_data_packet (struct p2p *p2p, u32 id)
{
    char *data = "hello!";
    u8 buf[sizeof (struct p2p_header) + 7] = {0};

    struct p2p_header *hdr = (struct p2p_header *) buf;
    hdr->magic = P2P_MAGIC;
    hdr->version = P2P_VERSION;
    hdr->packet_type = P2P_PACKET_TYPE_DATA;

    u8 *ptr = (buf + sizeof (struct p2p_header));
    memcpy (ptr, data, 7);

    hdr->len = 7;

    ENetPacket *packet = enet_packet_create (buf, sizeof (buf), ENET_PACKET_FLAG_RELIABLE);
    ENetPeer *peer = get_enet_peer_by_id (p2p, id);
    enet_peer_send (peer, 0, packet);

    p2p_packet_dump (buf, P2P_PACKET_DIRECTION_OUT, &peer->address);
    p2p_packet_hexdump (buf, sizeof (buf));
}

static void
p2p_process_packet (struct p2p *p2p, u32 id, u8 *data, size_t datalen)
{
    ASSERT (datalen >= sizeof (struct p2p_header));

    struct p2p_header *hdr = (struct p2p_header *) data;

    p2p_packet_dump (data, P2P_PACKET_DIRECTION_IN, &get_enet_peer_by_id (p2p, id)->address);
    ASSERT (hdr->magic == P2P_MAGIC);
    ASSERT (hdr->version == P2P_VERSION);
    ASSERT (hdr->packet_type > P2P_PACKET_TYPE_MIN);
    ASSERT (hdr->packet_type < P2P_PACKET_TYPE_MAX);
    ASSERT (hdr->len > 0);

    switch (hdr->packet_type)
    {
        case P2P_PACKET_TYPE_REGISTRATION:
        {
            ASSERT (P2P_ENUM_CHECK (p2p->mode, P2P_OP_MODE_MATCH_MAKING_SERVER));

            // p2p_peer_set (&p2p, );
        } break;
        case P2P_PACKET_TYPE_REGISTRATION_ACK:
        {
            ASSERT (P2P_ENUM_CHECK (p2p->mode, P2P_OP_MODE_CLIENT));
            ASSERT (id == p2p_generate_id (p2p->mm_server->active_connection));

            request_server_list (p2p);
        } break;
        case P2P_PACKET_TYPE_SERVER_LIST_REQUEST:
        {
            ASSERT (P2P_ENUM_CHECK (p2p->mode, P2P_OP_MODE_MATCH_MAKING_SERVER));

            send_server_list (p2p, id);
        } break;
        case P2P_PACKET_TYPE_JOIN:
        {
            struct p2p_join_packet *join = (struct p2p_join_packet *) (data + sizeof (struct p2p_header));

            // TODO: passing NULL here means we can manually push a connection below
            // - maybe we doing something about that.. ?
            struct p2p_peer *peer = p2p_peer_create (p2p, join->name, NULL, 0);

	    // TODO: we want to try LAN first, then try WAN?
            push_pending_connection (peer, join->private.host, join->private.port, join->join_mode);
            // push_pending_connection (peer, join->public.host, join->public.port, join->join_mode);

        } break;
        case P2P_PACKET_TYPE_DATA:
        {
            // TODO:
            // * set return buffer to the start of the packet data
            // * set the return buffer length to the length of the
            //   packet data
            u8 *ptr = (u8 *) (data + sizeof (struct p2p_header));
            p2p->receive (id, ptr, hdr->len, p2p->receive_data);
        } break;
    }
}

// TODO: do we need to deal with multiple events/packets?
// this may have to be an even thinner wrapper around enet_host_service()!
// TODO: rename this to p2p_peer_service or something, and only handle the client/peer interactions
// - we will have a separate p2p_mmserver_service or something.
void
p2p_service (struct p2p *p2p)
{
    process_pending_connections (p2p);

    enet_host_service (p2p->host, 0, 0);

    ENetEvent event;
    while (enet_host_check_events (p2p->host, &event) > 0)
    {
        char ipstr[P2P_IPSTRLEN];
        u32 id = p2p_generate_id (event.peer);

        p2p_enet_addr_to_str (&event.peer->address, ipstr, sizeof (ipstr));

        switch (event.type)
        {
            case ENET_EVENT_TYPE_CONNECT:
            {
                /*
                 * - someone has connected
                 * - we have an address and maybe a generated number
                 * - we know the address/port of the MM server, so we can see if it's them
                 */
                printf ("[service:CONNECT] from %s (%u)\n", ipstr, id);

                complete_pending_connection (p2p, id, event.peer);

                ASSERT (p2p->mode != P2P_OP_MODE_MATCH_MAKING_SERVER);

                // is this the MMServer connection completing
                if (id == p2p_generate_id (p2p->mm_server->active_connection))
                {
                    // if so, we register
                    send_registration_packet (p2p, id);
                }

                p2p->connect (id, p2p->connect_data);
            } break;
            case ENET_EVENT_TYPE_RECEIVE:
            {
                printf ("[service:RECEIVE] from %s (%u)\n", ipstr, id);

                p2p_process_packet (p2p, id, (u8 *) event.packet->data, event.packet->dataLength);
            } break;
            case ENET_EVENT_TYPE_DISCONNECT:
            {
                printf ("[service:DISCONNECT] from %s (%u)\n", ipstr, id);

                // TODO: think about reconnection functionality
                p2p->disconnect (id, p2p->disconnect_data);
            } break;
        }
    }
}

void
p2p_set_connect_callback (struct p2p *p2p, connect_f *connect, void *data)
{
    p2p->connect = connect;
    p2p->connect_data = data;
}

void
p2p_set_receive_callback (struct p2p *p2p, receive_f *receive, void *data)
{
    p2p->receive = receive;
    p2p->receive_data = data;
}

void
p2p_set_disconnect_callback (struct p2p *p2p, disconnect_f *disconnect, void *data)
{
    p2p->disconnect = disconnect;
    p2p->disconnect_data = data;
}

void
p2p_mode_set (struct p2p *p2p, p2p_enum mode, char *mm_server_ip, u16 mm_server_port)
{
    ENetAddress my_addr = {
        .host = ENET_HOST_ANY,
        .port = 0,
    };

    switch (mode)
    {
        case P2P_OP_MODE_MATCH_MAKING_SERVER:
        {
            my_addr.port = mm_server_port;
        } break;
        case P2P_OP_MODE_SERVER:
        case P2P_OP_MODE_CLIENT:
        {
            p2p->mm_server = p2p_peer_create (p2p, "Match-Making Server", mm_server_ip, mm_server_port);
        } break;
    }
}

static bool
p2p_params_valid (char *name, p2p_enum mode, char *ip)
{
    struct in_addr dummy = {0};
    bool ok = false;

    if (!name)
    {
        fprintf (stderr, "Name not specified\n");
    }
    else if (!(0 < strlen (name) && strlen (name) < P2P_NAME_LEN))
    {
        fprintf (stderr, "Invalid name length (max=%d)\n", P2P_NAME_LEN);
    }
    else if (!P2P_ENUM_VALID (P2P_OP_MODE, mode))
    {
        fprintf (stderr, "Bad enum value %d\n", mode);
    }
    else if (ip && inet_pton (AF_INET, ip, &dummy) != 1)
    {
        fprintf (stderr, "Invalid IPv4 address\n");
    }
    else
    {
        ok = true;
    }

    return ok;
}

static void
read_server_config (u16 *port)
{
    FILE *fp = fopen ("p2p-server.conf", "r");
    if (fp)
    {
        if (fscanf (fp, "%hu", port) == 1)
        {
            /* ok */
        }
        else
        {
            fprintf (stderr, "Failed to read p2p-server.conf\n");
        }

        fclose (fp);
    }
}

static void
read_client_config (char *ip4, u16 *port)
{
    FILE *fp = fopen ("p2p-client.conf", "r");

    if (fp)
    {
        if (fscanf (fp, "%s %hu", ip4, port) == 2)
        {
            /* ok */
        }
        else
        {
            fprintf (stderr, "Failed to read p2p-client.conf\n");
        }

        fclose (fp);
    }
}

bool
p2p_setup (struct p2p *p2p, char *name, p2p_enum mode)
{
    ENetHost *host = NULL;
    ENetAddress addr = {
        .host = ENET_HOST_ANY,
        .port = 0,
    };
    bool ok = false;
    char mm_server_ip[P2P_IPSTRLEN] = {0};
    u16 mm_server_port = 0;

    if (p2p->mode == P2P_OP_MODE_MATCH_MAKING_SERVER)
    {
        read_server_config (&mm_server_port);
        addr.port = mm_server_port;
    }
    else
    {
        read_client_config (mm_server_ip, &mm_server_port);
    }

    if (p2p_params_valid (name, mode, mm_server_ip))
    {
        if (enet_initialize () == 0)
        {
            host = enet_host_create (&addr, 32, 2, 0, 0);
            if (host)
            {
                snprintf (p2p->name, sizeof (p2p->name), "%s", name);
                p2p->mode = mode;
                p2p->host = host;

                if (p2p->mode == P2P_OP_MODE_MATCH_MAKING_SERVER)
                {
                    printf ("Starting [%s] port:%u (%s)\n", p2p->name, mm_server_port, p2p_enum_str (p2p->mode));

                    ok = true;
                }
                else
                {
                    printf ("Starting [%s] (%s)\n", p2p->name, p2p_enum_str (p2p->mode));

                    p2p->mm_server = p2p_peer_create (p2p, "Match-Making Server", mm_server_ip, mm_server_port);

                    ok = (p2p->mm_server != NULL);
                }
            }
            else
            {
                fprintf (stderr, "Failed to create local ENet host\n");
            }
        }
        else
        {
            fprintf (stderr, "Failed to initialise ENet\n");
        }
    }

    ASSERT (ok);
    return ok;
}
#endif
