// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <linux/if_link.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <argparse.h>
#include <net/if.h>

#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <signal.h>

#include "log.h"

#include <cyaml/cyaml.h>

// Load the compiled bpf skeleton
#include "l4_lb.skel.h"

static int ifindex_iface = 0;
static __u32 xdp_flags = 0;

static const char *const usages[] = {
    "packet_rewriting [options] [[--] args]",
    "packet_rewriting [options]",
    NULL,
};

struct backend {
    const char *ip;
};

struct ips {
    const char *vip;
    struct backend *backends;
    uint64_t backends_count;
};

static const cyaml_config_t config = {
    .log_fn = cyaml_log,            /* Use the default logging function. */
    .mem_fn = cyaml_mem,            /* Use the default memory allocator. */
    .log_level = CYAML_LOG_WARNING, /* Logging errors and warnings only. */
};

static const cyaml_schema_field_t backend_entry[] = {
    CYAML_FIELD_STRING_PTR("ip", CYAML_FLAG_POINTER, struct backend, ip, 0, CYAML_UNLIMITED),
};

static const cyaml_schema_value_t backend_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct backend, backend_entry),
};

static const cyaml_schema_field_t top_mapping_schema[] = {
    CYAML_FIELD_STRING_PTR("vip", CYAML_FLAG_POINTER, struct ips, vip, 0, CYAML_UNLIMITED),
    CYAML_FIELD_SEQUENCE("backends", CYAML_FLAG_POINTER, struct ips, backends, &backend_schema, 0,
                         CYAML_UNLIMITED),
    CYAML_FIELD_END};

static const cyaml_schema_value_t top_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, struct ips, top_mapping_schema),
};

static void cleanup_ifaces() {
    __u32 curr_prog_id = 0;

    if (ifindex_iface != 0) {
        if (!bpf_xdp_query_id(ifindex_iface, xdp_flags, &curr_prog_id)) {
            if (curr_prog_id) {
                bpf_xdp_detach(ifindex_iface, xdp_flags, NULL);
                log_trace("Detached XDP program from interface %d", ifindex_iface);
            }
        }
    }
}

void sigint_handler(int sig_no) {
    log_debug("Closing program...");
    cleanup_ifaces();
    exit(0);
}

int load_map_configuration(const char *config_file, struct l4_lb_bpf *skel) {
    struct ips *ips;
    cyaml_err_t err;
    int ret = EXIT_SUCCESS;

    // Load the input YAML file
    err = cyaml_load_file(config_file, &config, &top_schema, (void **)&ips, NULL);

    // Check loading result
    if (err != CYAML_OK) {
        log_debug("Error loading YAML file: %s\n", config_file);
        ret = EXIT_FAILURE;
    }

    // Get the map file descriptor
    int ips_map_fd = bpf_map__fd(skel->maps.server_ips);

    // Check the retrieved map file descriptor
    if(ips_map_fd < 0)
    {
        log_error("Failed to get file descriptor of BPF server IPS map %s", strerror(errno));
        ret = EXIT_FAILURE;
        goto cleanup_yaml;
    }

    // For every ip in the backend, add an entry into the map
    // TODO add check for max server number
    for (int i = 0; i < ips->backends_count; i++)
    {
        // Convert the IPv4 IP to a 32bit integer
        struct in_addr ip;
        int result = inet_pton(AF_INET, ips->backends[i].ip, &ip);

        // Check the coversion result
        if(result != 1)
        {
            log_error("Failed converting the backend IP %s to 32bit integer", ips->backends[i].ip);
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }

        // Select index and content of the map entry
        uint32_t index = i;
        uint32_t address = ip.s_addr;

        // Insert the value into the map
        result = bpf_map_update_elem(ips_map_fd, &index, &address, BPF_ANY);

        // Check the operation result
        if(result != 0)
        {
            log_error("Failed to add backend IP %s to the map", strerror(errno));
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }

        log_info("Loaded IP %s as %d", ips->backends[i].ip, ip.s_addr);
    }

cleanup_yaml:
    // Free the memory for the yaml configuration file
    cyaml_free(&config, &top_schema, ips, 0);

    return ret;
}

int main(int argc, const char **argv) {
    struct l4_lb_bpf *skel = NULL;
    int err;
    const char *iface = NULL;
    const char *config_file = NULL;

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_STRING('c', "config", &config_file,
                   "Path to the YAML configuration file (it specifies VIP and server IPs)", NULL, 0,
                   0),
        OPT_STRING('i', "iface", &iface, "Interface where to attach the BPF program", NULL, 0, 0),
        OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(
        &argparse,
        "\n[Exercise 1] This software attaches an XDP program to the interface specified in the "
        "input parameter",
        "\nIf '-p' argument is specified, the interface will be put in promiscuous mode");
    argc = argparse_parse(&argparse, argc, argv);

    if (iface != NULL) {
        log_info("XDP program will be attached to %s interface", iface);
        ifindex_iface = if_nametoindex(iface);
        if (!ifindex_iface) {
            log_fatal("Error while retrieving the ifindex of %s", iface);
            exit(1);
        } else {
            log_info("Got ifindex for iface: %s, which is %d", iface, ifindex_iface);
        }
    } else {
        log_error("Error, you must specify the interface where to attach the XDP program");
        exit(1);
    }

    // Check if the user inserted a configuration file
    if (config_file == NULL) {
        log_warn("Using default configuration file: %s", "config.yaml");
        config_file = "config.yaml";
    }

    // Check that the file actually exists
    if (access(config_file, F_OK) == -1) {
        log_fatal("Configuration file %s does not exist", config_file);
        exit(1);
    }

    // Open BPF application
    skel = l4_lb_bpf__open();
    if (!skel) {
        log_fatal("Error while opening BPF skeleton");
        exit(1);
    }

    // Set program type to XDP
    bpf_program__set_type(skel->progs.l4_lb, BPF_PROG_TYPE_XDP);

    // Load and verify BPF programs
    if (l4_lb_bpf__load(skel)) {
        log_fatal("Error while loading BPF skeleton");
        exit(1);
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = &sigint_handler;

    if (sigaction(SIGINT, &action, NULL) == -1) {
        log_error("sigation failed");
        goto cleanup;
    }

    if (sigaction(SIGTERM, &action, NULL) == -1) {
        log_error("sigation failed");
        goto cleanup;
    }

    // Before attaching the BPF program, load the YAML configuration file for VIP and Server IPs
    err = load_map_configuration(config_file, skel);
    if (err) {
        log_fatal("Eror while loading the YAML configuration file");
        goto cleanup;
    }

    xdp_flags = 0;
    xdp_flags |= XDP_FLAGS_DRV_MODE;

    // Attach the XDP program to the interface
    err = bpf_xdp_attach(ifindex_iface, bpf_program__fd(skel->progs.l4_lb), xdp_flags, NULL);

    if (err) {
        log_fatal("Error while attaching the XDP program to the interface");
        goto cleanup;
    }

    log_info("Successfully attached!");

    sleep(1);

    // Infinite loop to make the load balancer run
    while (1) {
        sleep(1);
    }

cleanup:
    cleanup_ifaces();
    l4_lb_bpf__destroy(skel);
    log_info("Program stopped correctly");
    return -err;
}