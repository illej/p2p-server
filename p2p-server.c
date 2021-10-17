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
#define CLIENT_MAX 16

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

enum client_state
{
  UNINITIALISED = 0,
  LOOKING_FOR_PEER,
  FOUND_PEER
};

struct client
{
  u32 id;
  enum client_state state;
  char name[32];

  ENetPeer *peer;
  ENetAddress priv;
  ENetAddress pub;
};

enum join_mode
{
  PASSIVE = 0,
  ACTIVE
};

struct join_packet
{
  u32 id;

  enum join_mode mode;

  ENetAddress priv;
  ENetAddress pub;
};

static volatile sig_atomic_t g__running = false;
static volatile sig_atomic_t g__dump_state = false;
static struct client clients[CLIENT_MAX] = {};
static u32 client_count = 0;

/*
TODO: show server state

 *ctl app that sends a SIGUSR1 to the NAT server.
 The NAT server receives the signal and toggles a flag.
 Each loop iteration, the flag is checked, and if it has been
 toggled then we dump state to STDOUT!.. and then toggle the
 flag off again.

TODO: client corraling

First user to join becomes the server.
Clients joining are told to join the server until it
becomes full, then the first IDLE client is chosen to be a server
and so on.
*/

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
    case LOOKING_FOR_PEER:
      return "Looking for Peer";
    case FOUND_PEER:
      return "Found Peer";
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

  enet_addr_to_str (&peer->address, addr, sizeof (addr));
  return hash_string (addr, 0);
}

static ENetHost *
setup (int port)
{
  ENetHost *server;
  ENetAddress address;

  address.host = ENET_HOST_ANY;
  address.port = port;
  server = enet_host_create (
      &address,   /* the address to bind the server host to */
      CLIENT_MAX, /* allow up to 32 clients and/or outgoing connections */
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

  if (client_count + 1 < CLIENT_MAX)
    {
      new = &clients[client_count++];
    }
  else
    {
      debug ("client list is full\n");
    }

  return new;
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
  ENetPeer *peer;

  log ("ENet Peers:\n");
  log ("-----------\n");
  log ("peers:%p, peerCount:%d, connectedPeers:%d\n", host->peers,
       host->peerCount, host->connectedPeers);

  for (peer = host->peers; peer < &host->peers[host->peerCount]; ++peer)
    {
      log ("  peer:%p id:%d state:%d\n", peer, peer->incomingPeerID,
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
      g__dump_state = true;
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

      if (g__dump_state)
        debug ("clients: %u\n", client_count);

      for (u32 i = 0; i < client_count; i++)
        {
          struct client *c = &clients[i];

          char pu[32];
          char pr[32];

          enet_addr_to_str (&c->pub, pu, sizeof (pu));
          enet_addr_to_str (&c->priv, pr, sizeof (pr));

          if (g__dump_state)
            {
              debug ("id      : %u\n", c->id);
              debug ("  pub   : %s\n", pu);
              debug ("  priv  : %s\n", pr);
              debug ("  state : %s\n", client_state_str (c));
            }

          if (c->state == LOOKING_FOR_PEER)
            {
              lfp[num_lfp++] = c->id;
            }
        }

      if (g__dump_state)
        g__dump_state = false;

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

static u32
get_peer_id (ENetPeer *peer)
{
  u32 id = 0;

  if (peer->data)
    {
      id = u32_from_ptr (peer->data);
    }
  else
    {
      id = generate_id (peer);
      peer->data = ptr_from_u32 (id);
    }

  return id;
}

static void
usage (void)
{
  log ("Usage: server <port>\n");
}

int
main (int argc, char *argv[])
{
  if (argc != 2)
    {
      usage ();
      return -1;
    }

  int port = atoi (argv[1]);
  float dt = 1000.0f / 60.0f;

  if (signal (SIGINT, signal_handler) != SIG_ERR
      && signal (SIGUSR1, signal_handler) != SIG_ERR
      && enet_initialize () == 0)
    {
      ENetHost *server = setup (port);
      if (server)
        {
          //			dump_enet_peers (server);

          g__running = true;
          log ("Starting NAT punch-through server [%d]\n", port);

          while (g__running)
            {
              match_clients (dt);

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
                        log ("client [%u] connected from [%s]\n", id, addr);

                        struct client *new = get_free_client_slot ();
                        new->id = id;
                        new->peer = event.peer;
                        new->state = UNINITIALISED;
                        new->pub.host = event.peer->address.host;
                        new->pub.port = event.peer->address.port;

                        //                			event.peer->data =
                        //                ptr_from_u32 (id);
                        debug ("enet peer %p state: %d\n", event.peer,
                               event.peer->state);
                        debug ("enet peers: %d\n", server->connectedPeers);
                      }
                      break;
                    case ENET_EVENT_TYPE_RECEIVE:
                      {
                        // dump_enet_peers (server);

                        u32 id = generate_id (event.peer);
                        debug ("packet from [%u]\n", id);

                        ENetAddress *priv = (ENetAddress *)event.packet->data;
                        char ip[32];

                        enet_addr_to_str (priv, ip, sizeof (ip));

                        debug ("priv: %s\n", ip);

                        struct client *client = get_client_by_id (id);
                        assert (client);

                        if (client->state == UNINITIALISED)
                          {
                            client->priv.host = priv->host;
                            client->priv.port = priv->port;
                            client->state = LOOKING_FOR_PEER;
                          }
                      }
                      break;
                    case ENET_EVENT_TYPE_DISCONNECT:
                      {
                        u32 id = generate_id (event.peer);

                        debug ("client [%u] disconnected\n", id);

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
