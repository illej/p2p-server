#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif
#ifndef __USE_GNU
  #define __USE_GNU
#endif

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <execinfo.h>
#include <ucontext.h>
#include <signal.h>

#include <p2p.h>

typedef struct _sig_ucontext {
    unsigned long uc_flags;
    ucontext_t *uc_link;
    stack_t uc_stack;
    struct sigcontext uc_mcontext;
    sigset_t uc_sigmask;
} sig_ucontext_t;

static bool g__running = true;

bool
parse_args (int argc, char **argv, char **name, p2p_enum *mode)
{
    bool ok = false;

    for (u32 i = 1; i < argc; i++)
    {
        if (strcmp (argv[i], "--server") == 0)
        {
            *mode = P2P_OP_MODE_SERVER;
        }
        else if (!*name)
        {
            *name = argv[i];
            ok = true;
        }
    }

    if (!ok)
    {
        fprintf (stdout, "Usage: %s NAME [--server]\n", argv[0]);
    }

    return ok;
}

void
crit_err_handler (int sig_num, siginfo_t * info, void * ucontext)
{
    void *             array[50];
    void *             caller_address;
    char **            messages;
    int                size, i;
    sig_ucontext_t *   uc;

    uc = (sig_ucontext_t *)ucontext;

    /* Get the address at the time the signal was raised */
#if defined(__i386__) // gcc specific
    caller_address = (void *) uc->uc_mcontext.eip; // EIP: x86 specific
#elif defined(__x86_64__) // gcc specific
    caller_address = (void *) uc->uc_mcontext.rip; // RIP: x86_64 specific
#else
#error Unsupported architecture. // TODO: Add support for other arch.
#endif

#if 0
    FILE *fp = fopen ("core.dump", "w");
    if (fp)
    {
        fprintf(fp, "signal %d (%s), address is %p from %p\n", 
                sig_num, strsignal(sig_num), info->si_addr, 
                (void *)caller_address);

        size = backtrace(array, 50);

        /* overwrite sigaction with caller's address */
        array[1] = caller_address;

        messages = backtrace_symbols(array, size);

        /* skip first stack frame (points here) */
        for (i = 1; i < size && messages != NULL; ++i)
        {
            fprintf(fp, "[bt]: (%d) %s\n", i, messages[i]);
        }

        free(messages);

        fclose (fp);
    }
    else
#endif
    {
        fprintf(stderr, "signal %d (%s), address is %p from %p\n", 
                sig_num, strsignal(sig_num), info->si_addr, 
                (void *)caller_address);

        size = backtrace(array, 50);

        /* overwrite sigaction with caller's address */
        array[1] = caller_address;

        messages = backtrace_symbols(array, size);

        /* skip first stack frame (points here) */
        for (i = 1; i < size && messages != NULL; ++i)
        {
            fprintf(stderr, "[bt]: (%d) %s\n", i, messages[i]);
        }

        free(messages);
    }

    exit(EXIT_FAILURE);
}

bool
sig_init (void)
{
    struct sigaction sigact = {0};
    sigact.sa_sigaction = crit_err_handler;
    sigact.sa_flags = SA_RESTART | SA_SIGINFO;
    bool ok = false;

    if (sigaction (SIGSEGV, &sigact, (struct sigaction *) NULL) == 0)
    {
        ok = true;
    }
    else
    {
        fprintf (stderr, "Failed to set signal handler\n");
    }

    return ok;
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
main (int argc, char ** argv)
{
    float dt = 1000.0f / 60.0f;
    struct p2p p2p = {0};
    char *name = NULL;
    p2p_enum mode = P2P_OP_MODE_CLIENT;

    if (!parse_args (argc, argv, &name, &mode))
    {
        return 1;
    }

    if (!sig_init ())
    {
        return 1;
    }
    
    p2p_setup (&p2p, name, mode, 0);
    // p2p_server_set (&p2p, "203.86.199.79", 1717);
    p2p_set_connect_callback (&p2p, connect_cb, NULL);
    p2p_set_receive_callback (&p2p, receive_cb, NULL);
    p2p_set_disconnect_callback (&p2p, disconnect_cb, NULL);

    while (g__running)
    {
        p2p_service (&p2p);

        usleep (dt * 1000);
    }

    return 0;
}
