/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>
***/

#include <inttypes.h>
#include <stdbool.h>

#include "in-addr-util.h"

typedef struct Address Address;

#include "networkd-link.h"
#include "networkd-network.h"

#define CACHE_INFO_INFINITY_LIFE_TIME 0xFFFFFFFFU

typedef struct Network Network;
typedef struct Link Link;
typedef struct NetworkConfigSection NetworkConfigSection;

struct Address {
        Network *network;
        NetworkConfigSection *section;

        Link *link;

        int family;
        unsigned char prefixlen;
        unsigned char scope;
        uint32_t flags;
        char *label;

        struct in_addr broadcast;
        struct ifa_cacheinfo cinfo;

        union in_addr_union in_addr;
        union in_addr_union in_addr_peer;

        bool ip_masquerade_done:1;
        bool duplicate_address_detection;
        bool manage_temporary_address;
        bool home_address;
        bool prefix_route;
        bool autojoin;

        LIST_FIELDS(Address, addresses);
};

int address_new_static(Network *network, const char *filename, unsigned section, Address **ret);
int address_new(Address **ret);
void address_free(Address *address);
int address_add_foreign(Link *link, int family, const union in_addr_union *in_addr, unsigned char prefixlen, Address **ret);
int address_add(Link *link, int family, const union in_addr_union *in_addr, unsigned char prefixlen, Address **ret);
int address_get(Link *link, int family, const union in_addr_union *in_addr, unsigned char prefixlen, Address **ret);
int address_update(Address *address, unsigned char flags, unsigned char scope, const struct ifa_cacheinfo *cinfo);
int address_drop(Address *address);
int address_configure(Address *address, Link *link, sd_netlink_message_handler_t callback, bool update);
int address_remove(Address *address, Link *link, sd_netlink_message_handler_t callback);
bool address_equal(Address *a1, Address *a2);
bool address_is_ready(const Address *a);

DEFINE_TRIVIAL_CLEANUP_FUNC(Address*, address_free);

int config_parse_address(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_broadcast(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_label(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_lifetime(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_address_flags(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_address_scope(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
