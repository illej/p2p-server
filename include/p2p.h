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
      printf ("%s:%d> assertion failed\n", __func__, __LINE__);      \
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
#define P2P_IPSTRLEN (16 + 1 + 5) // 255.255.255.255:65535\n
#define P2P_REG_PACKET_LEN (sizeof (struct p2p_header) + sizeof (struct p2p_registration_packet))

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef enum p2p_enum
{
    P2P_OP_MODE_MIN = 1000,
    P2P_OP_MODE_CLIENT,
    P2P_OP_MODE_SERVER,
    P2P_OP_MODE_MATCH_MAKING_SERVER,
    P2P_OP_MODE_MAX,

    P2P_JOIN_MODE_MIN = 2000,
    P2P_JOIN_MODE_PASSIVE,
    P2P_JOIN_MODE_ACTIVE,
    P2P_JOIN_MODE_MAX,

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

    P2P_PACKET_TYPE_MIN = 7000,
    P2P_PACKET_TYPE_REGISTRATION,
    P2P_PACKET_TYPE_REGISTRATION_ACK,
    P2P_PACKET_TYPE_JOIN,
    P2P_PACKET_TYPE_DATA, // user data
    P2P_PACKET_TYPE_MAX,
} p2p_enum;

struct p2p_pending_connection
{
    u32 id;
    p2p_enum state;
    ENetAddress address;

    ENetPeer *enet_peer;
};

struct p2p_peer
{
    char name[32];

    struct p2p_pending_connection pending_connections[8];
    u32 pending_count;

    ENetPeer *wan;
    ENetPeer *lan;
    ENetPeer *dev;

    ENetPeer *active_connection;
};

struct p2p
{
    char name[32];
    p2p_enum mode;

    ENetHost *host;

    u32 server_id;

    struct p2p_peer peers[32];
    u32 peer_count;

    p2p_enum event;
};

struct p2p_header
{
    u32 magic;
    p2p_enum packet_type;
    size_t len;
};

struct p2p_registration_packet
{
    p2p_enum mode;
    char name[32];
    ENetAddress private; // u8 *private_ip;
};

struct p2p_registration_ack
{
    char msg[32];
};

struct p2p_join_packet
{
    u32 id;
    char name[32];

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

char *
p2p_enum_str (p2p_enum val)
{
    switch (val)
    {
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
        default:
        {
            fprintf (stderr, "Unknown P2P_Enum value: %d\n", val);
            return "Unknown P2P_Enum value";
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
p2p_packet_dump (u8 *data, char *direction, ENetAddress *addr)
{
    char ipstr[P2P_IPSTRLEN];

    printf ("Packet [%s] to [%s]:\n", direction, p2p_enet_addr_to_str (addr, ipstr, sizeof (ipstr)));

    struct p2p_header *hdr = (struct p2p_header *) data;
    printf ("Header (%zu bytes)\n", sizeof (struct p2p_header));
    printf ("  Magic   : %u\n", hdr->magic);
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
            printf ("  Msg    : %s\n", payload->msg);
        } break;
    }
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
  char addr[P2P_IPSTRLEN];

  return hash_string (p2p_enet_addr_to_str (&peer->address, addr, sizeof (addr)), 0);
}

u32
p2p_generate_id_from_addr (ENetAddress *address)
{
  char addr[P2P_IPSTRLEN];

  return hash_string (p2p_enet_addr_to_str (address, addr, sizeof (addr)), 0);
}

u32
p2p_get_peer_id (ENetPeer *peer)
{
    if (!peer->data)
    {
        peer->data = ptr_from_u32 (p2p_generate_id (peer));
    }

    return u32_from_ptr (peer->data);
}

ENetPeer *
p2p_get_enet_peer_by_id (ENetHost *host, u32 id)
{
  ENetPeer *peer = NULL;

  for (peer = host->peers; peer < &host->peers[host->peerCount]; ++peer)
    {
      if (peer->state == ENET_PEER_STATE_CONNECTED)
        {
          u32 peer_id = p2p_get_peer_id (peer);
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
    for (u32 i = 0; i < p2p->peer_count; i++)
    {
        struct p2p_peer *peer = &p2p->peers[i];

        printf ("<peer: name=%s pending_count=%u active(enet_id)=%u (%p)>\n",
                 peer->name, peer->pending_count,
                 (peer->active_connection ? peer->active_connection->incomingPeerID : UINT32_MAX),
                 peer->active_connection);

        for (u32 j = 0; j < peer->pending_count; j++)
        {
            struct p2p_pending_connection *conn = &peer->pending_connections[j];
            char ipstr[P2P_IPSTRLEN];
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
        struct p2p_pending_connection *conn = &peer->pending_connections[i];

        if (conn->id == (ip ^ port))
        {
            found = true;
            break;
        }
    }

    if (!found)
    {
        if (peer->pending_count + 1 < ARRAY_LEN (peer->pending_connections))
        {
            struct p2p_pending_connection *conn = &peer->pending_connections[peer->pending_count++];

            id = conn->id = (ip ^ port);
            conn->address.host = ip;
            conn->address.port = port;
            conn->state = P2P_CONNECTION_STATE_IDLE;
        }
        else
        {
            fprintf (stderr, "Max connections reached for [%s]\n", peer->name);
        }
    }

    return id;
}

void
process_pending_connections (struct p2p *p2p)
{
    for (u32 i = 0; i < p2p->peer_count; i++)
    {
        struct p2p_peer *peer = &p2p->peers[i];

        for (u32 j = 0; j < peer->pending_count; j++)
        {
            struct p2p_pending_connection *conn = &peer->pending_connections[j];

            if (conn->state == P2P_CONNECTION_STATE_IDLE)
            {
                conn->enet_peer = enet_host_connect (p2p->host, &conn->address, 2, 0);
                ASSERT (conn->enet_peer);
                conn->enet_peer->data = peer;
                conn->state = P2P_CONNECTION_STATE_IN_PROGRESS;
            }
        }
    }
}

void
complete_pending_connection (struct p2p *p2p, u32 id, u8 *data)
{
    for (u32 i = 0; i < p2p->peer_count; i++)
    {
        struct p2p_peer *peer = &p2p->peers[i];

        for (u32 j = 0; j < peer->pending_count; j++)
        {
            char ipstr[P2P_IPSTRLEN];
            struct p2p_pending_connection *conn = &peer->pending_connections[j];

            p2p_enet_addr_to_str (&conn->address, ipstr, sizeof (ipstr));

            if (conn->id == id &&
                conn->state == P2P_CONNECTION_STATE_IN_PROGRESS)
            {
                if (!peer->active_connection)
                {
                    peer->active_connection = conn->enet_peer;
                }
                else
                {
                    printf ("Peer [%s] has existing active connection to [%s]\n", peer->name, p2p_enet_addr_to_str (&peer->active_connection->address, ipstr, sizeof (ipstr)));
                }

                u32 last_index = peer->pending_count - 1;
                if (j != last_index)
                {
                    struct p2p_pending_connection *last = &peer->pending_connections[last_index];

                    memcpy (conn, last, sizeof (struct p2p_pending_connection));
                }
                else
                {
                    memset (conn, 0, sizeof (struct p2p_pending_connection));
                }
                --peer->pending_count;
            }
        }
    }

#if 1
    DEBUG_peer_dump (p2p);
#endif
}

u32
p2p_peer_create (struct p2p *p2p, char *name, char *ip, u16 port)
{
    u32 id = 0;

    if (p2p->peer_count + 1 < ARRAY_LEN (p2p->peers))
    {
        struct p2p_peer *p = &p2p->peers[p2p->peer_count++];
        *p = P2P_PEER_ZERO;

        snprintf (p->name, sizeof (p->name), "%s", name);

        if (ip && port > 0)
        {
            id = push_pending_connection (p, inet_addr (ip), port, P2P_JOIN_MODE_ACTIVE);
        }
    }
    else
    {
        fprintf (stderr, "Max peers reached\n");
    }

#if 1
    DEBUG_peer_dump (p2p);
#endif

    return id;
}

void
p2p_server_set (struct p2p *p2p, char *ip, u16 port)
{
    if (p2p->server_id > 0)
    {
        fprintf (stderr, "P2P Server already set %u\n",  p2p->server_id);
    }

    p2p->server_id = p2p_peer_create (p2p, "P2P-Server", ip, port);
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
    else
    {
        printf ("Failed to get ifindex\n");
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

    if (adapter_info) free (adapter_info);

    if (!ok)
    {
        printf ("Failed to get IP from ifindex %d\n", ifindex);
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

    printf ("Using [%s] as private IP\n", ipstr);

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
    p2p_packet_dump (buf, "Out", &dest->address);
    p2p_packet_hexdump (buf, sizeof (buf));
#endif
}

/**
 * @param p2p - main P2P state structure
 * @param id - connection ID
 * @param data - incoming packet data
 * @param datalen - length of incoming packet
 * @param buf - return buffer for application payload
 * @param buflen - length of return buffer
 */
static void
p2p_process_packet (struct p2p *p2p, u32 id, u8 *data, size_t datalen, u8 *buf, size_t *buflen)
{
    ASSERT (datalen >= sizeof (struct p2p_header));

    struct p2p_header *hdr = (struct p2p_header *) data;

    ASSERT (hdr->magic == P2P_MAGIC);
    ASSERT (hdr->packet_type > P2P_PACKET_TYPE_MIN);
    ASSERT (hdr->packet_type < P2P_PACKET_TYPE_MAX);
    ASSERT (hdr->len > 0);
    p2p_packet_dump (data, "In", &get_enet_peer_by_id (p2p, id)->address);

    switch (hdr->packet_type)
    {
        case P2P_PACKET_TYPE_REGISTRATION:
        {

        } break;
        case P2P_PACKET_TYPE_JOIN:
        {
            p2p->event = P2P_EVENT_TYPE_CONNECT;
        } break;
        case P2P_PACKET_TYPE_DATA:
        {
            p2p->event = P2P_EVENT_TYPE_RECEIVE;
            // TODO:
            // * set return buffer to the start of the packet data
            // * set the return buffer length to the length of the
            //   packet data
            // buf = (u8 *) (data + sizeof (struct p2p_header));
        } break;
    }
}

// TODO: do we need to deal with multiple events/packets?
// this may have to be an even thinner wrapper around enet_host_service()!
void
p2p_service (struct p2p *p2p, u8 *buf, size_t *buflen)
{
    process_pending_connections (p2p);

    enet_host_service (p2p->host, 0, 0);

    ENetEvent event;
    while (enet_host_check_events (p2p->host, &event) > 0)
    {
        char ipstr[P2P_IPSTRLEN];
        u32 id = (event.peer->address.host ^ event.peer->address.port);

        p2p_enet_addr_to_str (&event.peer->address, ipstr, sizeof (ipstr));

        switch (event.type)
        {
            case ENET_EVENT_TYPE_CONNECT:
            {
                printf ("[service:CONNECT] from %s (%u)\n", ipstr, id);
                complete_pending_connection (p2p, id, event.peer->data);

                // TODO: how do we want to figure out which ENet Peer
                // to send to?? Do we rely on the id, or store the
                // pointer in ->data and use that??
                if (id == p2p->server_id)
                {
                    send_registration_packet (p2p, id);
                }
            } break;
            case ENET_EVENT_TYPE_RECEIVE:
            {
                printf ("[service:RECEIVE] from %s (%u)\n", ipstr, id);

                p2p_process_packet (p2p, id, (u8 *) event.packet->data, event.packet->dataLength, buf, buflen);
            } break;
            case ENET_EVENT_TYPE_DISCONNECT:
            {
                printf ("[service:DISCONNECT] from %s (%u)\n", ipstr, id);

                // TODO: think about reconnection functionality
            } break;
        }
    }
}

bool
p2p_setup (struct p2p *p2p, char *name, p2p_enum mode)
{
    ENetHost *host = NULL;
    ENetAddress address = {
        .host = ENET_HOST_ANY,
        .port = 0
    };
    bool ok = false;

    if (!name)
    {
        fprintf (stderr, "Name not specified\n");
    }
    else if (mode < P2P_OP_MODE_MIN || mode > P2P_OP_MODE_MAX)
    {
        fprintf (stderr, "Bad enum value %d\n", mode);
    }
    else if (enet_initialize () != 0)
    {
        fprintf (stderr, "Failed to initialise ENet\n");
    }
    else if ((host = enet_host_create (&address, 32, 2, 0, 0)) == NULL)
    {
        fprintf (stderr, "Failed to create local ENet host\n");
    }
    else
    {
        snprintf (p2p->name, sizeof (p2p->name), "%s", name);
        p2p->mode = mode;
        p2p->host = host;

        printf ("Starting P2P-Client as [%s] (%s)\n", p2p->name, p2p_enum_str (p2p->mode));

        ok = p2p_peer_create (p2p, "P2P-Server", "203.86.199.79", 1717) > 0;
    }

    ASSERT (ok);
    return ok;
}
#endif
