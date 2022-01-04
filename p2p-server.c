#include <enet/enet.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if 0 // linux
#include <unistd.h>
#endif

#include <p2p.h>

#ifdef DEBUG
  #define debug(fmt, ...) __debug (__func__, __LINE__, fmt, ##__VA_ARGS__)
#else
  #define debug
#endif
#define log(fmt, ...) fprintf (stdout, fmt, ##__VA_ARGS__)

#define MAX_CLIENTS 32

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;


static char *
packet_type_str (int type)
{
  switch (type)
  {
    case P2P_PACKET_TYPE_REGISTRATION:
      return "Registration Packet";
    case P2P_PACKET_TYPE_REGISTRATION_ACK:
      return "Registration Ack Packet";
    default:
      return "Unknown packet type";
  }
}

// TODO: rename to peer
struct client
{
  u32 id;
  p2p_enum state;
  char name[32];

  ENetPeer *peer;
  ENetAddress private;
  ENetAddress public;

  bool is_server;
  u32 current_players;
  u32 max_players;
};


static volatile sig_atomic_t g__running = false;
static volatile sig_atomic_t g__dump_client_state = false;
static volatile sig_atomic_t g__dump_enet_peer_state = false;

static struct client clients[MAX_CLIENTS] = {0};
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
peer_state_str (struct client *c)
{
  switch (c->state)
    {
    case P2P_PEER_STATE_UNINITIALISED:
      return "Uninitialised";
    case P2P_PEER_STATE_REGISTERED:
      return "Registered";
    case P2P_PEER_STATE_LOOKING_FOR_PEER:
      return "Looking for Peer";
    case P2P_PEER_STATE_FOUND_PEER:
      return "Found Peer";
    default:
      return "Unknown peer state";
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

    return "Unknown state";
}

static ENetHost *
setup (u16 port, int num_clients)
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
  cln->state = P2P_PEER_STATE_UNINITIALISED;
  cln->name[0] = '\0';
  cln->peer = 0;
  cln->private.host = 0;
  cln->private.port = 0;
  cln->public.host = 0;
  cln->public.port= 0;

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

static void
dump_enet_peers (ENetHost *host)
{
  ENetPeer *peer = NULL;

  debug ("ENet Peers:\n");
  debug ("-----------\n");
  debug ("peers:%p, peerCount:%zu, connectedPeers:%zu\n", host->peers,
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
#if 0 // linux
    case SIGUSR1:
      g__dump_client_state = true;
      break;
    case SIGUSR2:
      g__dump_enet_peer_state = true;
      break;
#endif
    }
}

static void
match_clients (float dt)
{
  static float t = 0;

  if (t > 500)
    {
      t = 0;
      u32 lfp[32] = {0};
      u32 num_lfp = 0;

      if (g__dump_client_state)
        debug ("clients: %u\n", client_count);

      for (u32 i = 0; i < client_count; i++)
        {
          struct client *c = &clients[i];

          char pu[P2P_IP_STR_LEN];
          char pr[P2P_IP_STR_LEN];

          p2p_enet_addr_to_str (&c->public, pu, sizeof (pu));
          p2p_enet_addr_to_str (&c->private, pr, sizeof (pr));

          if (g__dump_client_state)
            {
              debug ("[%u] id=%u name=%s pub=%s priv=%s state=%s\n",
                      i, c->id, c->name, pu, pr, peer_state_str (c));
            }

          if (c->state == P2P_PEER_STATE_LOOKING_FOR_PEER)
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
          struct p2p_join_packet p = {0};
          p.id = b->id;
          p.join_mode = P2P_JOIN_MODE_ACTIVE;
          p.private.host = b->private.host;
          p.private.port = b->private.port;
          p.public.host = b->public.host;
          p.public.port = b->public.port;
          ENetPacket *to_a
              = enet_packet_create ((void *)&p, sizeof (struct p2p_join_packet),
                                    ENET_PACKET_FLAG_RELIABLE);
          enet_peer_send (peer_a, 0, to_a);

          debug ("sending %u\'s details to %u\n", b->id, a->id);

          ENetPeer *peer_b = b->peer;
          assert (peer_b);

          // pack a's data
          p.id = a->id;
          p.join_mode = P2P_JOIN_MODE_PASSIVE;
          p.private.host = a->private.host;
          p.private.port = a->private.port;
          p.public.host = a->public.host;
          p.public.port = a->public.port;
          ENetPacket *to_b
              = enet_packet_create ((void *)&p, sizeof (struct p2p_join_packet),
                                    ENET_PACKET_FLAG_RELIABLE);
          enet_peer_send (peer_b, 0, to_b);

          debug ("sending %u\'s details to %u\n", a->id, b->id);

          a->state = P2P_PEER_STATE_FOUND_PEER;
          b->state = P2P_PEER_STATE_FOUND_PEER;
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
      FILE *fp = fopen (".debug_dump", "w");
      if (fp)
      {
        fprintf (fp, "DEBUG clients:\n");
        fprintf (fp, "--------------\n");
        for (u32 i = 0; i < client_count; i++)
        {
          struct client *c = &clients[i];

          char pu[P2P_IP_STR_LEN];
          char pr[P2P_IP_STR_LEN];

          p2p_enet_addr_to_str (&c->public, pu, sizeof (pu));
          p2p_enet_addr_to_str (&c->private, pr, sizeof (pr));

          fprintf (fp, "[%u] id=%u name=%s pub=%s priv=%s state=%s is_server=%d players=%u/%u\n",
                 i, c->id, c->name, pu, pr, peer_state_str (c), c->is_server, c->current_players, c->max_players);
        }

        fclose (fp);
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
                    c->state == P2P_PEER_STATE_REGISTERED &&
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

                    if (!c->is_server && c->state == P2P_PEER_STATE_REGISTERED)
                    {
                        log ("matching server(%s) and client(%s)\n", s->name, c->name);
                        ENetPeer *peer_c = c->peer;
                        ENetPeer *peer_s = s->peer;
                        assert (peer_c);
                        assert (peer_s);

                        char pu[P2P_IP_STR_LEN];
                        char pr[P2P_IP_STR_LEN];

                        p2p_enet_addr_to_str (&c->public, pu, sizeof (pu));
                        p2p_enet_addr_to_str (&c->private, pr, sizeof (pr));

                        // send server details to client
                        struct p2p_join_packet p = {0};
                        p.id = s->id;
                        snprintf (p.name, sizeof (p.name), "%s", s->name);
                        p.join_mode = P2P_JOIN_MODE_ACTIVE;
                        p.private.host = s->private.host;
                        p.private.port = s->private.port;
                        p.public.host = s->public.host;
                        p.public.port = s->public.port;
                        ENetPacket *to_c
                            = enet_packet_create ((void *)&p, sizeof (struct p2p_join_packet),
                                    ENET_PACKET_FLAG_RELIABLE);
                        enet_peer_send (peer_c, 0, to_c);

                        log ("  sending server(%s) details to client(%s)\n", s->name, c->name);

                        // send client's details to server
                        p.id = c->id;
                        memset (p.name, 0, sizeof (p.name));
                        snprintf (p.name, sizeof (p.name), "%s", c->name);
                        p.join_mode = P2P_JOIN_MODE_PASSIVE;
                        p.private.host = c->private.host;
                        p.private.port = c->private.port;
                        p.public.host = c->public.host;
                        p.public.port = c->public.port;
                        ENetPacket *to_s = enet_packet_create ((void *) &p, sizeof (struct p2p_join_packet),
                                ENET_PACKET_FLAG_RELIABLE);
                        enet_peer_send (peer_s, 0, to_s);

                        log ("  sending client(%s) details to server(%s)\n", c->name, s->name);

                        s->current_players++;
                        c->state = P2P_PEER_STATE_FOUND_PEER;
                    }
                }
            }
        }
    }

    t += dt;
}

static bool
parse_input (int argc, char *argv[], u16 *port)
{
    bool ret = false;

    if (argc == 2)
    {
        *port = (u16) atoi (argv[1]);
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
#if 0 // linux
    return (signal (SIGINT, signal_handler) != SIG_ERR &&
            signal (SIGUSR1, signal_handler) != SIG_ERR &&
            signal (SIGUSR2, signal_handler) != SIG_ERR);
#else
    return (signal (SIGINT, signal_handler) != SIG_ERR);
#endif
}

static BOOL
file_exists (LPCTSTR szPath)
{
  DWORD dwAttrib = GetFileAttributes (szPath);

  return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
         !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

static void
packet_hexdump (u8 *data, size_t len)
{
#ifdef DEBUG
    int cols = 0;

    printf ("packet hexdump (%zu bytes)\n", len);
    for (u32 i = 0; i < len; i++)
    {
        printf (" %02x", data[i]);
        if (++cols == 4)
        {
            printf ("\n");
            cols = 0;
        }
    }
    printf ("\n");
#endif
}

static void
process_packet (u32 id, u8 *data, size_t len)
{
    assert (len >= sizeof (struct p2p_header));

    struct p2p_header *hdr = (struct p2p_header *) data;

    assert (hdr->magic == P2P_MAGIC);
    assert (hdr->packet_type > P2P_PACKET_TYPE_MIN);
    assert (hdr->packet_type < P2P_PACKET_TYPE_MAX);
    assert (hdr->len > 0);

    u8 *payload = data + sizeof (struct p2p_header);

    struct client *cln = get_client_by_id (id);
    assert (cln);

    packet_hexdump (data, len);
    
    switch (hdr->packet_type)
    {
        case P2P_PACKET_TYPE_REGISTRATION:
        {
            char ip[P2P_IP_STR_LEN];

            struct p2p_registration_packet *reg = (struct p2p_registration_packet *) payload;

            assert (hdr->len == sizeof (struct p2p_registration_packet));

            debug ("reg packet received\n");
            debug ("  mode      : %d\n", reg->mode);
            debug ("  private   : %s\n", p2p_enet_addr_to_str (&reg->private, ip, sizeof (ip)));
            debug ("  name      : %s\n", reg->name);

            // TODO(17-dec-2021):
            // 1. register peer
            struct client *client = get_client_by_id (id);
            client->state = P2P_PEER_STATE_REGISTERED;
            client->is_server = reg->mode == P2P_OP_MODE_SERVER;
            client->max_players = 32;
            client->private.host = reg->private.host;
            client->private.port = reg->private.port;
            snprintf (client->name, sizeof (client->name), "%s", reg->name);

            // 2. send ack
#define REG_ACK_LEN sizeof (struct p2p_header) + sizeof (struct p2p_registration_ack)
            u8 buf[REG_ACK_LEN] = {0};

            struct p2p_header *send_hdr = (struct p2p_header *) buf;
            send_hdr->magic = P2P_MAGIC;
            send_hdr->packet_type = P2P_PACKET_TYPE_REGISTRATION_ACK;

            struct p2p_registration_ack *reg_ack = (struct p2p_registration_ack *) (buf + sizeof (struct p2p_header));
            snprintf (reg_ack->msg, sizeof (reg_ack->msg), "%u registered in %s mode", id, (client->is_server ? "server" : "client"));

            send_hdr->len = REG_ACK_LEN;

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
    u16 port;

    if (parse_input (argc, argv, &port) &&
        sig_init () &&
        enet_initialize () == 0)
    {
      ENetHost *server = setup (port, MAX_CLIENTS);
      if (server)
        {
          g__running = true;
          log ("Starting NAT punch-through server [%d]\n", port);

          while (g__running && file_exists (".network_test.run"))
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
                  u32 id = p2p_get_peer_id (event.peer);
                  char addr[P2P_IP_STR_LEN];

                  p2p_enet_addr_to_str (&event.peer->address, addr, sizeof (addr));

                  switch (event.type)
                    {
                    case ENET_EVENT_TYPE_CONNECT:
                      {
                        log ("client [%u-%s] connected\n", id, addr);

                        struct client *new = get_free_client_slot ();
                        assert (new);

                        new->id = id;
                        new->peer = event.peer;
                        new->state = P2P_PEER_STATE_UNINITIALISED;
                        new->public.host = event.peer->address.host;
                        new->public.port = event.peer->address.port;

                        debug ("enet peer %p state: %d (%s)\n", event.peer,
                               event.peer->state, enet_state_str (event.peer->state));
                        debug ("enet peers: %zu\n", server->connectedPeers);
                        debug ("p2p-client_count: %d\n", client_count);
                      }
                      break;
                    case ENET_EVENT_TYPE_RECEIVE:
                      {
                        // log ("packet from [%u-%s]\n", id, addr);

                        process_packet (id, (u8 *) event.packet->data, event.packet->dataLength);
                      }
                      break;
                    case ENET_EVENT_TYPE_DISCONNECT:
                      {
                        log ("client [%u-%s] disconnected\n", id, addr);

                        struct client *client = get_client_by_id (id);

                        client->id = 0;
                        client->peer = NULL;
                        client->private.host = 0;
                        client->private.port = 0;
                        client->public.host = 0;
                        client->public.port = 0;
                        client->state = P2P_PEER_STATE_UNINITIALISED;
                        client_count--;
                      }
                      break;
                    }
                }
#if 0 // linux
              usleep (dt * 1000);
#else
              Sleep ((DWORD) dt);
#endif
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

