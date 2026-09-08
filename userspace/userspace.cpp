#include <map>
#include <signal.h>
#include <net/if.h>
#include <iostream>
#include <bpf/bpf.h>
#include "blocklist.h"
#include <arpa/inet.h>
#include <bpf/libbpf.h>

using namespace std;

#define IFACE "wlp2s0"
static volatile sig_atomic_t running = 1;


static void handle_signal(int sig)
{
    running = 0;
}

int main(void)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    map<uint32_t, uint8_t> blocklist = get_ip_blocklist();


    int map_fd;
    int ifindex;
    int err;

    // Stop cleanly with Ctrl+C.
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    //wlp2s0.    
    ifindex = if_nametoindex(IFACE);

    if (ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }

    printf("Interface: %s (ifindex %d)\n", IFACE, ifindex);

    obj = bpf_object__open_file("../bpf/xdp_firewall.o", NULL);

    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);

    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }


    prog = bpf_object__find_program_by_name(
        obj,
        "xdp_parser_func"
    );

    if (!prog) {
        fprintf(stderr, "Could not find xdp_parser_func\n");
        err = 1;
        goto cleanup;
    }

    /*
     * Attach XDP to wlp2s0.
     */
    link = bpf_program__attach_xdp(prog, ifindex);

    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach XDP\n");
        link = NULL;
        err = 1;
        goto cleanup;
    }

    printf("XDP attached to %s\n", IFACE);

    /*
     * Get the blocked_ips map.
     */
    map_fd = bpf_object__find_map_fd_by_name(
        obj,
        "blocked_ips"
    );

    if (map_fd < 0) {
        fprintf(stderr, "Could not find blocked_ips map\n");
        err = 1;
        goto cleanup;
    }

    for (auto ip: blocklist) {

        

        err = bpf_map_update_elem(
            map_fd,
            &ip.first,
            &ip.second,
            BPF_ANY
        );

        if (err) {
            fprintf(
                stderr,
                "Failed to insert %d: %s\n",
                ip.first,
                strerror(errno)
            );
            continue;
        }

        printf("Blocked: %d\n", ip.first);
    }

    printf("\nFirewall running on %s\n", IFACE);
    printf("Press Ctrl+C to stop.\n");

    while (running) {
        sleep(1);
    }

    printf("\nStopping XDP...\n");

cleanup:


    //   Detach XDP from wlp2s0.
    if (link)
        bpf_link__destroy(link);

    if (obj)
        bpf_object__close(obj);

    return err ? 1 : 0;
}