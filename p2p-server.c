#include <enet/enet.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <p2p.h>
#define DEBUG
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


/* Match-Making Client */
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

  u32 current_map_hash;
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
  ASSERT (server);

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

#ifdef _WIN32
// TODO: move all this debug stuff into a library (single-header?)
// * assert
// * log helpers
// * backtrace
// https://stackoverflow.com/questions/11040133/what-does-defining-win32-lean-and-mean-exclude-exactly
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>
#pragma comment (lib, "dbghelp.lib")

void
stack_trace (void)
{
    struct sym_pack
    {
        SYMBOL_INFO sym;
        char name[255];
    } sym_pack;
    void *stack[64] = {0};

    SYMBOL_INFO *symbol = &sym_pack.sym;
    symbol->MaxNameLen = 255;
    symbol->SizeOfStruct = sizeof (SYMBOL_INFO);

    IMAGEHLP_LINE64 line;
    line.SizeOfStruct = sizeof (IMAGEHLP_LINE64);

    HANDLE process = GetCurrentProcess ();
    SymInitialize (process, NULL, true);
    SymSetOptions (SYMOPT_LOAD_LINES);

    unsigned short frame_count = CaptureStackBackTrace (0, 100, stack, NULL);

    printf ("----------------------------------------\n");
    printf ("Call Stack:\n");
    printf ("----------------------------------------\n");
    for (int i = 1; i < frame_count; i++)
    {
        DWORD dwDisplacement;

        SymFromAddr (process, (DWORD64) (stack[i]), 0, symbol);
        SymGetLineFromAddr (process, (DWORD64) (stack[i]), &dwDisplacement, &line);

        printf ("0x%0llX %i: %s\t(%s:%d)\n",
                symbol->Address, frame_count - i - 1,
                symbol->Name, line.FileName, line.LineNumber);
    }
    printf ("----------------------------------------\n");
}
#endif /* _WIN32 */

static void
signal_handler (int signal)
{
  switch (signal)
    {
    case SIGINT:
      g__running = false;
      break;
#if _WIN32
    case SIGSEGV:
      printf ("SEGMENTATION FAULT\n");
      stack_trace ();
      g__running = false;
      break;
#else /* linux */
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
DEBUG_dump_clients (void)
{
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

          char pu[P2P_IPSTRLEN];
          char pr[P2P_IPSTRLEN];

          p2p_enet_addr_to_str (&c->public, pu, sizeof (pu));
          p2p_enet_addr_to_str (&c->private, pr, sizeof (pr));

          fprintf (fp, "[%u] id=%u name=%s pub=%s priv=%s state=%s is_server=%d players=%u/%u\n",
                 i, c->id, c->name, pu, pr, peer_state_str (c), c->is_server, c->current_players, c->max_players);
        }

        fclose (fp);
      }

        g__dump_client_state = false;
    }
}

static void
match_clients_v2 (float dt)
{
    static float t = 0;

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
                        log ("[MMServer] matching server(%s) and client(%s)\n", s->name, c->name);
                        ENetPeer *peer_c = c->peer;
                        ENetPeer *peer_s = s->peer;
                        ASSERT (peer_c);
                        ASSERT (peer_s);

                        char pu[P2P_IPSTRLEN];
                        char pr[P2P_IPSTRLEN];

                        p2p_enet_addr_to_str (&c->public, pu, sizeof (pu));
                        p2p_enet_addr_to_str (&c->private, pr, sizeof (pr));

                        // send server details to client
                        u8 buf[sizeof (struct p2p_header) + sizeof (struct p2p_join_packet)] = {0};

                        struct p2p_header *hdr = (struct p2p_header *) buf;
                        hdr->magic = P2P_MAGIC;
                        hdr->version = P2P_VERSION;
                        hdr->packet_type = P2P_PACKET_TYPE_JOIN;
                        hdr->len = sizeof (struct p2p_join_packet);

                        struct p2p_join_packet *j = (struct p2p_join_packet *) (buf + sizeof (struct p2p_header));
                        j->id = s->id;
                        snprintf (j->name, sizeof (j->name), "%s", s->name);
                        j->join_mode = P2P_JOIN_MODE_ACTIVE;
                        j->private.host = s->private.host;
                        j->private.port = s->private.port;
                        j->public.host = s->public.host;
                        j->public.port = s->public.port;

                        ENetPacket *to_c
                            = enet_packet_create (buf, sizeof (buf),
                                    ENET_PACKET_FLAG_RELIABLE);
                        enet_peer_send (peer_c, 0, to_c);

                        log ("[MMServer] sending server(%s) details to client(%s)\n", s->name, c->name);
                        p2p_packet_dump (buf, P2P_PACKET_DIRECTION_OUT, &peer_c->address);

                        // send client's details to server
                        memset (buf, 0, sizeof (buf));
                        hdr = (struct p2p_header *) buf;
                        hdr->magic = P2P_MAGIC;
                        hdr->version = P2P_VERSION;
                        hdr->packet_type = P2P_PACKET_TYPE_JOIN;
                        hdr->len = sizeof (struct p2p_join_packet);

                        j = (struct p2p_join_packet *) (buf + sizeof (struct p2p_header));
                        j->id = c->id;
                        snprintf (j->name, sizeof (j->name), "%s", c->name);
                        j->join_mode = P2P_JOIN_MODE_PASSIVE;
                        j->private.host = c->private.host;
                        j->private.port = c->private.port;
                        j->public.host = c->public.host;
                        j->public.port = c->public.port;

                        ENetPacket *to_s = enet_packet_create (buf, sizeof (buf),
                                ENET_PACKET_FLAG_RELIABLE);
                        enet_peer_send (peer_s, 0, to_s);

                        log ("[MMServer] sending client(%s) details to server(%s)\n", c->name, s->name);
                        p2p_packet_dump (buf, P2P_PACKET_DIRECTION_OUT, &peer_s->address);

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
#if _WIN32
  return (signal (SIGINT, signal_handler) != SIG_ERR &&
          signal (SIGSEGV, signal_handler) != SIG_ERR);

#else /* linux */
  return (signal (SIGINT, signal_handler) != SIG_ERR &&
          signal (SIGUSR1, signal_handler) != SIG_ERR &&
          signal (SIGUSR2, signal_handler) != SIG_ERR);
#endif
}

static bool
check_network_test_file (void)
{
    char *file = ".network_test.run";
    bool running = false;

    FILE *fp = fopen (file, "r");
    if (fp)
    {
      int val = -1;
      int n = fscanf (fp, "%d", &val);
      if (n == 1 && val > -1)
      {
        running = (val == 1);
      }

      fclose (fp);
    }
    else
    {
      running = true;
    }

    return running;
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
    ASSERT (len >= sizeof (struct p2p_header));

    struct p2p_header *hdr = (struct p2p_header *) data;

    ASSERT (hdr->magic == P2P_MAGIC);
    ASSERT (hdr->version == P2P_VERSION);
    ASSERT (hdr->packet_type > P2P_PACKET_TYPE_MIN);
    ASSERT (hdr->packet_type < P2P_PACKET_TYPE_MAX);
    ASSERT (hdr->len > 0);

    u8 *payload = data + sizeof (struct p2p_header);

    struct client *cln = get_client_by_id (id);
    ASSERT (cln);

    packet_hexdump (data, len);
    
    switch (hdr->packet_type)
    {
        case P2P_PACKET_TYPE_REGISTRATION:
        {
            char ip[P2P_IPSTRLEN];

            struct p2p_registration_packet *reg = (struct p2p_registration_packet *) payload;

            ASSERT (hdr->len == sizeof (struct p2p_registration_packet));

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
            send_hdr->version = P2P_VERSION;
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

// TODO: move this into the library as p2p_matchmaking_server_service() or something
static void
__service (ENetHost *server)
{
    enet_host_service (server, 0, 0);

    ENetEvent event;
    while (enet_host_check_events (server, &event) > 0)
    {
        u32 id = p2p_generate_id (event.peer);
        char addr[P2P_IPSTRLEN];

        p2p_enet_addr_to_str (&event.peer->address, addr, sizeof (addr));

        switch (event.type)
        {
            case ENET_EVENT_TYPE_CONNECT:
            {
                log ("client [%u-%s] connected\n", id, addr);

                struct client *new = get_free_client_slot ();
                ASSERT (new);

                new->id = id;
                new->peer = event.peer;
                new->state = P2P_PEER_STATE_UNINITIALISED;
                new->public.host = event.peer->address.host;
                new->public.port = event.peer->address.port;

                debug ("enet peer %p state: %d (%s)\n", event.peer,
                       event.peer->state, enet_state_str (event.peer->state));
                debug ("enet peers: %zu\n", server->connectedPeers);
                debug ("p2p-client_count: %d\n", client_count);
            } break;
            case ENET_EVENT_TYPE_RECEIVE:
            {
                        // log ("packet from [%u-%s]\n", id, addr);

                process_packet (id, (u8 *) event.packet->data, event.packet->dataLength);
            } break;
            case ENET_EVENT_TYPE_DISCONNECT:
            {
                log ("client [%u-%s] disconnected\n", id, addr);

                struct client *client = get_client_by_id (id);
                log ("  client: %p\n", client);

                if (client)
                {
                    client->id = 0;
                    client->peer = NULL;
                    client->private.host = 0;
                    client->private.port = 0;
                    client->public.host = 0;
                    client->public.port = 0;
                    client->state = P2P_PEER_STATE_UNINITIALISED;
                    client_count--;
                }
            } break;
        }
    }
}

static void
connect_cb (u32 id, void *data)
{
    printf ("connect_cb() id=%u\n", id);
}

static void
receive_cb (u32 id, u8 *data, size_t len, void *user_data)
{
    printf ("receive_cb() id=%u data=%p len=%zu\n", id, data, len);
}

static void
disconnect_cb (u32 id, void *data)
{
    printf ("disconnect_cb() id=%u\n", id);
}

int
main (int argc, char *argv[])
{
    float dt = 1000.0f / 60.0f;
    u16 port;

    if (parse_input (argc, argv, &port) && sig_init ())
    {
        struct p2p p2p = {0};

        FILE *fp  = fopen ("p2p-server.conf", "w");
        if (fp)
        {
            fprintf (fp, "%u", port);
            fclose (fp);
        }

        p2p_setup (&p2p, "NAT punch-through server", P2P_OP_MODE_MATCH_MAKING_SERVER);
        p2p_set_connect_callback (&p2p, connect_cb, NULL);
        p2p_set_receive_callback (&p2p, receive_cb, NULL);
        p2p_set_disconnect_callback (&p2p, disconnect_cb, NULL);

        g__running = true;
        while (g__running)
        {
            match_clients_v2 (dt);

            __service (p2p.host);

#if _WIN32
            Sleep ((DWORD) dt);
#else
            usleep (dt * 1000);
#endif
            if (g__running)
            {
                g__running = check_network_test_file ();
            }
        }
    }

    return 0;
}
