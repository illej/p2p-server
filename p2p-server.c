#include <enet/enet.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define debug(fmt, ...) __debug (__func__, __LINE__, fmt, ##__VA_ARGS__)
#define log(fmt, ...) fprintf (stdout, fmt, ##__VA_ARGS__)
#define assert(EXP)                                                           \
  if (!(EXP))                                                                 \
    {                                                                         \
      fprintf (stdout, "%s:%d> assertion failed\n", __func__, __LINE__);      \
      *(int *)0 = 0;                                                          \
    }
#define ptr_from_u32(u) (void *)((char *)0 + (u))
#define u32_from_ptr(p) (unsigned long)((char *)p - (char *)0)

#define IPSTR_LEN (16 + 1 + 5)
#define MAX_CLIENTS 32

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef enum p2p_enum
{
    /* client state */
    UNINITIALISED = 1000,
    REGISTERED,
    LOOKING_FOR_PEER,
    FOUND_PEER,

    /* join mode */
    PASSIVE = 2000,
    ACTIVE,

    /* packet type */
    P2P_PACKET_TYPE_INVALID = 7000,
    P2P_PACKET_TYPE_REGISTRATION,
    P2P_PACKET_TYPE_REGISTRATION_ACK,
    P2P_PACKET_TYPE_MAX
} p2p_enum;

struct client
{
  u32 id;
  p2p_enum state;
  char name[32];

  ENetPeer *peer;
  ENetAddress priv;
  ENetAddress pub;

  bool is_server;
  u32 current_players;
  u32 max_players;
};

struct join_packet
{
  u32 id;

  p2p_enum mode;

  ENetAddress priv;
  ENetAddress pub;
};

struct p2p_header
{
    u8 magic;           // 1
#define P2P_MAGIC 117
    p2p_enum type;      // 4
    size_t len;         // 8
};
struct p2p_registration_packet
{
    bool is_server;     // 4
    ENetAddress private;
    char name[32];
};

struct p2p_registration_ack
{
    char msg[256];
};

static volatile sig_atomic_t g__running = false;
static volatile sig_atomic_t g__dump_client_state = false;
static volatile sig_atomic_t g__dump_enet_peer_state = false;

static struct client clients[MAX_CLIENTS] = {};
static u32 client_count = 0;

static void
__debug (const char *func, int line, char *fmt, ...)
{
  va_list args;
  char msg[256];

  va_start (args, fmt);
  vsprintf (msg, fmt, args);
  va_end (args);

  fprintf (stdout, "%s:%d> %s", func, line, msg);
}

static char *
client_state_str (struct client *c)
{
  switch (c->state)
    {
    case UNINITIALISED:
      return "Uninitialised";
    case REGISTERED:
      return "Registered";
    case LOOKING_FOR_PEER:
      return "Looking for Peer";
    case FOUND_PEER:
      return "Found Peer";
    default:
      return "Unknown client state";
    }
}

static char *
enet_state_str (ENetPeerState state)
{
    switch (state)
    {
        case ENET_PEER_STATE_DISCONNECTED: return "ENetPeer_Disconnected";
        case ENET_PEER_STATE_CONNECTING: return "ENetPeer_Connecting";
        case ENET_PEER_STATE_ACKNOWLEDGING_CONNECT: return "ENetPeer_AcknowledgingConnect";
        case ENET_PEER_STATE_CONNECTION_PENDING: return "ENetPeer_ConnectionPending";
        case ENET_PEER_STATE_CONNECTION_SUCCEEDED: return "ENetPeer_Succeeded";
        case ENET_PEER_STATE_CONNECTED: return "ENetPeer_Connected";
        case ENET_PEER_STATE_DISCONNECT_LATER: return "ENetPeer_DisconnectLater";
        case ENET_PEER_STATE_DISCONNECTING: return "ENetPeer_Disconnecting";
        case ENET_PEER_STATE_ACKNOWLEDGING_DISCONNECT: return "ENetPeer_AcknowledgingDisconnected";
        case ENET_PEER_STATE_ZOMBIE: return "ENetPeer_Zombie";
    }
}

static char *
enet_addr_to_str (ENetAddress *addr, char *buf, size_t len)
{
  uint8_t *octets = (uint8_t *)&addr->host;

  snprintf (buf, len, "%u.%u.%u.%u:%u", octets[0], octets[1], octets[2],
            octets[3], addr->port);

  return buf;
}

static u32
hash_string (char *string, u32 hash)
{
  assert (string);

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
generate_id (ENetPeer *peer)
{
  char addr[IPSTR_LEN];

  return hash_string (enet_addr_to_str (&peer->address, addr, sizeof (addr)), 0);
}

static ENetHost *
setup (int port, int num_clients)
{
  ENetHost *server;
  ENetAddress address;

  address.host = ENET_HOST_ANY;
  address.port = port;
  server = enet_host_create (
      &address,
      num_clients,
      2,          /* allow up to 2 channels to be used, 0 and 1 */
      0,          /* assume any amount of incoming bandwidth */
      0);         /* assume any amount of outgoing bandwidth */
  assert (server);

  return server;
}

static struct client *
get_free_client_slot (void)
{
  struct client *new = NULL;

  if (client_count + 1 < MAX_CLIENTS)
    {
      new = &clients[client_count++];
    }
  else
    {
      debug ("client list is full\n");
    }

  return new;
}

static void
remove_client (struct client *cln)
{
  cln->id = 0;
  cln->state = UNINITIALISED;
  cln->name[0] = '\0';
  cln->peer = 0;
  cln->priv.host = 0;;
  cln->priv.port = 0;;
  cln->pub.host = 0;;
  cln->pub.port= 0;;

  client_count--;
}

static struct client *
get_client_by_id (u32 id)
{
  struct client *client = NULL;

  for (u32 i = 0; i < client_count; i++)
    {
      client = &clients[i];
      if (client->id == id)
        {
          break;
        }
      else
        {
          client = NULL;
        }
    }

  return client;
}

static ENetPeer *
get_enet_peer_by_id (ENetHost *host, u32 id)
{
  ENetPeer *peer = NULL;

  for (peer = host->peers; peer < &host->peers[host->peerCount]; ++peer)
    {
      if (peer->state == ENET_PEER_STATE_CONNECTED)
        {
          u32 peer_id = generate_id (peer);
          if (peer_id == id)
            {
              return peer;
            }
        }
    }

  return NULL;
}

static void
dump_enet_peers (ENetHost *host)
{
  ENetPeer *peer = NULL;

  debug ("ENet Peers:\n");
  debug ("-----------\n");
  debug ("peers:%p, peerCount:%d, connectedPeers:%d\n", host->peers,
       host->peerCount, host->connectedPeers);

  for (peer = host->peers; peer < &host->peers[host->peerCount]; ++peer)
    {
      debug ("  peer:%p id:%d state:%d\n", peer, peer->incomingPeerID,
           peer->state);
    }
}

static void
signal_handler (int signal)
{
  switch (signal)
    {
    case SIGINT:
      g__running = false;
      break;
    case SIGUSR1:
      g__dump_client_state = true;
      break;
    case SIGUSR2:
      g__dump_enet_peer_state = true;
      break;
    }
}

static void
match_clients (float dt)
{
  static float t = 0;

  if (t > 500)
    {
      t = 0;
      u32 lfp[32] = {};
      u32 num_lfp = 0;

      if (g__dump_client_state)
        debug ("clients: %u\n", client_count);

      for (u32 i = 0; i < client_count; i++)
        {
          struct client *c = &clients[i];

          char pu[32];
          char pr[32];

          enet_addr_to_str (&c->pub, pu, sizeof (pu));
          enet_addr_to_str (&c->priv, pr, sizeof (pr));

          if (g__dump_client_state)
            {
              debug ("[%u] id=%u name=%s pub=%s priv=%s state=%s\n",
                      i, c->id, c->name, pu, pr, client_state_str (c));
            }

          if (c->state == LOOKING_FOR_PEER)
            {
              lfp[num_lfp++] = c->id;
            }
        }

      if (g__dump_client_state)
        g__dump_client_state = false;

      if (num_lfp >= 2)
        {
          u32 aid = lfp[0];
          u32 bid = lfp[1];

          struct client *a = get_client_by_id (aid);
          struct client *b = get_client_by_id (bid);

          assert (a && b);
          debug ("matching %u clients\n", num_lfp);
          debug ("  a: %u\n", a->id);
          debug ("  b: %u\n", b->id);

          ENetPeer *peer_a = a->peer;
          assert (peer_a);

          // pack b's data
          struct join_packet p = {};
          p.id = b->id;
          p.mode = ACTIVE;
          p.priv.host = b->priv.host;
          p.priv.port = b->priv.port;
          p.pub.host = b->pub.host;
          p.pub.port = b->pub.port;
          ENetPacket *to_a
              = enet_packet_create ((void *)&p, sizeof (struct join_packet),
                                    ENET_PACKET_FLAG_RELIABLE);
          enet_peer_send (peer_a, 0, to_a);

          debug ("sending %u\'s details to %u\n", b->id, a->id);

          ENetPeer *peer_b = b->peer;
          assert (peer_b);

          // pack a's data
          p.id = a->id;
          p.mode = PASSIVE;
          p.priv.host = a->priv.host;
          p.priv.port = a->priv.port;
          p.pub.host = a->pub.host;
          p.pub.port = a->pub.port;
          ENetPacket *to_b
              = enet_packet_create ((void *)&p, sizeof (struct join_packet),
                                    ENET_PACKET_FLAG_RELIABLE);
          enet_peer_send (peer_b, 0, to_b);

          debug ("sending %u\'s details to %u\n", a->id, b->id);

          a->state = FOUND_PEER;
          b->state = FOUND_PEER;
        }
    }

  t += dt;
}

static void
match_clients_v2 (float dt)
{
    static float t = 0;

    if (g__dump_client_state)
    {
        debug ("DEBUG clients:\n");
        debug ("--------------\n");
        for (u32 i = 0; i < client_count; i++)
        {
            struct client *c = &clients[i];

            char pu[32];
            char pr[32];

            enet_addr_to_str (&c->pub, pu, sizeof (pu));
            enet_addr_to_str (&c->priv, pr, sizeof (pr));

            debug ("[%u] id=%u name=%s pub=%s priv=%s state=%s is_server=%d players=%u/%u\n",
                      i, c->id, c->name, pu, pr, client_state_str (c), c->is_server, c->current_players, c->max_players);

        }

        g__dump_client_state = false;
    }

    if (t >= 500.0f)
    {
        t = 0.0f;

        if (client_count > 0)
        {
            // see if we can find a server with free slots
            struct client *s = NULL;
            for (u32 i = 0; i < client_count; i++)
            {
                struct client *c = &clients[i];

                if (c->is_server &&
                    c->state == REGISTERED &&
                    c->current_players < c->max_players)
                {
                    s = c;
                    break;
                }
                else
                {
                    s = NULL;
                }
            }

            if (s)
            {
                // if we found a server, tell all of the connected clients to
                // attempt to connect to it
                for (u32 i = 0; i < client_count; i++)
                {
                    struct client *c = &clients[i];

                    if (!c->is_server && c->state == REGISTERED)
                    {
                        debug ("matching server(%u) and client(%u)\n", s->id, c->id);
                        ENetPeer *peer_c = c->peer;
                        ENetPeer *peer_s = s->peer;
                        assert (peer_c);
                        assert (peer_s);

                        char pu[32];
                        char pr[32];

                        enet_addr_to_str (&c->pub, pu, sizeof (pu));
                        enet_addr_to_str (&c->priv, pr, sizeof (pr));

                        // send server details to client
                        struct join_packet p = {};
                        p.id = s->id;
                        p.mode = ACTIVE;
                        p.priv.host = s->priv.host;
                        p.priv.port = s->priv.port;
                        p.pub.host = s->pub.host;
                        p.pub.port = s->pub.port;
                        ENetPacket *to_c
                            = enet_packet_create ((void *)&p, sizeof (struct join_packet),
                                    ENET_PACKET_FLAG_RELIABLE);
                        enet_peer_send (peer_c, 0, to_c);

                        debug ("sending server\'s(%u) details to client(%u)\n", s->id, c->id);

                        // send client's details to server
                        p.id = c->id;
                        p.mode = PASSIVE;
                        p.priv.host = c->priv.host;
                        p.priv.port = c->priv.port;
                        p.pub.host = c->pub.host;
                        p.pub.port = c->pub.port;
                        ENetPacket *to_s = enet_packet_create ((void *) &p, sizeof (struct join_packet),
                                ENET_PACKET_FLAG_RELIABLE);
                        enet_peer_send (peer_s, 0, to_s);

                        debug ("sending client\'s(%u) details to server(%u)\n", c->id, s->id);

                        s->current_players++;
                        c->state = FOUND_PEER;
                    }
                }
            }
        }
    }

    t += dt;
}

static u32
get_peer_id (ENetPeer *peer)
{
    if (!peer->data)
    {
        peer->data = ptr_from_u32 (generate_id (peer));
    }

    return u32_from_ptr (peer->data);
}

static bool 
parse_input (int argc, char *argv[], int *port)
{
    bool ret = false;

    if (argc == 2)
    {
        *port = atoi (argv[1]);
        ret = true;
    }
    else
    {
        log ("Usage: server <port>\n");
    }

    return ret;
}

static bool
sig_init (void)
{
    return (signal (SIGINT, signal_handler) != SIG_ERR &&
            signal (SIGUSR1, signal_handler) != SIG_ERR &&
            signal (SIGUSR2, signal_handler) != SIG_ERR);
}

static void
packet_hexdump (u8 *data, size_t len)
{
    int cols = 0;

    printf ("packet hexdump (%d bytes)\n", len);
    for (u32 i = 0; i < len; i++)
    {
        printf ("  %02x ", data[i]);
        if (++cols == 4)
        {
            printf ("\n");
            cols = 0;
        }
    }
    printf ("\n");
}

static void
process_packet (u32 id, u8 *data, size_t len)
{
    assert (len >= sizeof (struct p2p_header));

    struct p2p_header *hdr = (struct p2p_header *) data;

    assert (hdr->magic == P2P_MAGIC);
    assert (hdr->type > P2P_PACKET_TYPE_INVALID);
    assert (hdr->type < P2P_PACKET_TYPE_MAX);
    assert (hdr->len > 0);

    u8 *payload = data + sizeof (struct p2p_header);

    packet_hexdump (data, len);
    
    switch (hdr->type)
    {
        case P2P_PACKET_TYPE_REGISTRATION:
        {
            char ip[IPSTR_LEN];

            struct p2p_registration_packet *reg = (struct p2p_registration_packet *) payload;

            assert (hdr->len == sizeof (struct p2p_registration_packet));

            debug ("reg packet received\n");
            debug ("  is_server : %d\n", reg->is_server);
            debug ("  private   : %s\n", enet_addr_to_str (&reg->private, ip, sizeof (ip)));
            debug ("  name      : %s\n", reg->name);

            // TODO(17-dec-2021):
            // 1. register peer
            struct client *client = get_client_by_id (id);
            client->state = REGISTERED;
            client->is_server = reg->is_server;
            client->max_players = 32;
            client->priv.host = reg->private.host;
            client->priv.port = reg->private.port;
            snprintf (client->name, sizeof (client->name), "%s", reg->name);

            // 2. send ack
#define REG_ACK_LEN sizeof (struct p2p_header) + sizeof (struct p2p_registration_ack)
            u8 buf[REG_ACK_LEN] = {};

            struct p2p_header *hdr = (struct p2p_header *) buf;
            hdr->magic = P2P_MAGIC;
            hdr->type = P2P_PACKET_TYPE_REGISTRATION_ACK;

            struct p2p_registration_ack *reg_ack = (struct p2p_registration_ack *) (buf + sizeof (struct p2p_header));
            snprintf (reg_ack->msg, sizeof (reg_ack->msg), "%u is now registered in %s mode", id, (client->is_server ? "server" : "client"));

            hdr->len = REG_ACK_LEN;

            ENetPacket *ack_pkt = enet_packet_create ((void *) &buf,
                                                      REG_ACK_LEN,
                                                      ENET_PACKET_FLAG_RELIABLE);
            enet_peer_send (client->peer, 0, ack_pkt);
        } break;
    }
}

int
main (int argc, char *argv[])
{
    float dt = 1000.0f / 60.0f;
    int port;

    if (parse_input (argc, argv, &port) &&
        sig_init () &&
        enet_initialize () == 0)
    {
      ENetHost *server = setup (port, MAX_CLIENTS);
      if (server)
        {
          g__running = true;
          log ("Starting NAT punch-through server [%d]\n", port);

          while (g__running)
            {
              if (g__dump_enet_peer_state)
              {
                dump_enet_peers (server);
                g__dump_enet_peer_state = false;
              }

              match_clients_v2 (dt);

              enet_host_service (server, 0, 0);

              ENetEvent event;
              while (enet_host_check_events (server, &event) > 0)
                {
                  char addr[IPSTR_LEN];
                  u32 id = get_peer_id (event.peer);
                  enet_addr_to_str (&event.peer->address, addr, sizeof (addr));

                  switch (event.type)
                    {
                    case ENET_EVENT_TYPE_CONNECT:
                      {
                        log ("client [%u-%s] connected\n", id, addr);

                        struct client *new = get_free_client_slot ();
                        assert (new);

                        new->id = id;
                        new->peer = event.peer;
                        new->state = UNINITIALISED;
                        new->pub.host = event.peer->address.host;
                        new->pub.port = event.peer->address.port;

                        debug ("enet peer %p state: %d (%s)\n", event.peer,
                               event.peer->state, enet_state_str (event.peer->state));
                        debug ("enet peers: %d\n", server->connectedPeers);
                        debug ("p2p-client_count: %d\n", client_count);
                      }
                      break;
                    case ENET_EVENT_TYPE_RECEIVE:
                      {
                        log ("packet from [%u-%s]\n", id, addr);

                        process_packet (id, (u8 *) event.packet->data, event.packet->dataLength);
                      }
                      break;
                    case ENET_EVENT_TYPE_DISCONNECT:
                      {
                        log ("client [%u-%s] disconnected\n", id, addr);

                        struct client *client = get_client_by_id (id);

                        client->id = 0;
                        client->peer = NULL;
                        client->priv.host = 0;
                        client->priv.port = 0;
                        client->pub.host = 0;
                        client->pub.port = 0;
                        client->state = UNINITIALISED;
                        client_count--;
                      }
                      break;
                    }
                }
              usleep (dt * 1000);
            }

          log ("exiting\n");
          enet_host_destroy (server);
        }
      else
        {
          debug ("An error occurred while trying to create an ENet server "
                 "host.\n");
        }
    }

  enet_deinitialize ();

  return 0;
}

