#ifndef P2P_H
#define P2P_H

#include <stdint.h>
#include <stdbool.h>
#include <enet/enet.h>

#ifndef assert
#define assert(EXP)                                                           \
  if (!(EXP))                                                                 \
    {                                                                         \
      fprintf (stdout, "%s:%d> assertion failed\n", __func__, __LINE__);      \
    }
#endif /* assert */

#define ptr_from_u32(u) (void *) ((char *) 0 + (u))
#define u32_from_ptr(p) (unsigned long) ((char *) p - (char *) 0)


#define P2P_MAGIC 117
#define P2P_IP_STR_LEN (16 + 1 + 5) // 255.255.255.255:65535\n

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef enum p2p_enum
{
    P2P_OP_MODE_MIN = 1000,
    P2P_OP_MODE_CLIENT,
    P2P_OP_MODE_SERVER,
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

    P2P_PACKET_TYPE_MIN = 7000,
    P2P_PACKET_TYPE_REGISTRATION,
    P2P_PACKET_TYPE_REGISTRATION_ACK,
    P2P_PACKET_TYPE_MAX,
} p2p_enum;

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

static char *
p2p_enum_str (p2p_enum val)
{
    switch (val)
    {
        case P2P_OP_MODE_SERVER:               return "P2P_OpMode_Server";
        case P2P_OP_MODE_CLIENT:               return "P2P_OpMode_Client";
        case P2P_JOIN_MODE_PASSIVE:            return "P2P_JoinMode_Passive";
        case P2P_JOIN_MODE_ACTIVE:             return "P2P_JoinMode_Active";
        case P2P_PEER_STATE_UNINITIALISED:     return "P2P_PeerState_Uninitialised";
        case P2P_PEER_STATE_REGISTERED:        return "P2P_PeerState_Registered";
        case P2P_PEER_STATE_LOOKING_FOR_PEER:  return "P2P_PeerState_LookingForPeer";
        case P2P_PEER_STATE_FOUND_PEER:        return "P2P_PeerState_FoundPeer";
        case P2P_PACKET_TYPE_REGISTRATION:     return "P2P_PacketType_Registration";
        case P2P_PACKET_TYPE_REGISTRATION_ACK: return "P2P_PacketType_RegistrationAck";
        default:                               return "Unknown P2P_enum value";
    }
}

static void
p2p_packet_hexdump (u8 *data, size_t len)
{
    int cols = 0;

    printf ("packet hexdump (%zu bytes)\n", len);
    for (u32 i = 0; i < len; i++)
    {
        printf (" %02X", data[i]);
        if (++cols == 4)
        {
            printf ("\n");
            cols = 0;
        }
    }
    printf ("\n");
}

static char *
p2p_enet_addr_to_str (ENetAddress *addr, char *buf, size_t len)
{
  u8 *octets = (u8 *) &addr->host;

  snprintf (buf, len, "%u.%u.%u.%u:%u", octets[0], octets[1], octets[2],
            octets[3], addr->port);

  return buf;
}

static u32
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

static u32
p2p_generate_id (ENetPeer *peer)
{
  char addr[P2P_IP_STR_LEN];

  return hash_string (p2p_enet_addr_to_str (&peer->address, addr, sizeof (addr)), 0);
}

static u32
p2p_generate_id_from_addr (ENetAddress *address)
{
  char addr[P2P_IP_STR_LEN];

  return hash_string (p2p_enet_addr_to_str (address, addr, sizeof (addr)), 0);
}

static u32
p2p_get_peer_id (ENetPeer *peer)
{
    if (!peer->data)
    {
        peer->data = ptr_from_u32 (p2p_generate_id (peer));
    }

    return u32_from_ptr (peer->data);
}

static ENetPeer *
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

#endif