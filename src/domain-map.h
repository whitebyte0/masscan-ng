#ifndef DOMAIN_MAP_H
#define DOMAIN_MAP_H

#include "massip-addr.h"
#include <stddef.h>

/*
 * domain-map: read-only ipaddress -> domain name table, loaded once at
 * config time from a file of "<ip> <domain>" lines (one domain per IP —
 * the scan orchestrator fans out one invocation per domain, so a single
 * map never carries two domains for the same address). IPv4 and IPv6 are
 * both supported: entries sort by (version, address bytes) and lookups
 * binary-search. Consulted per connection by the HTTP Host rewrite and
 * the dynamic-SSL SNI setter, so lookup stays O(log n) with no locks —
 * the table is frozen before scan threads start.
 */

struct DomainMapEntry {
  ipaddress ip;
  char *domain;
};

struct DomainMap {
  size_t count;
  struct DomainMapEntry *entries; /* sorted, unique by ip */
};

/* Parse the whole file; returns NULL on any unreadable/bad line (fail
 * closed: a typo'd IP must not silently narrow the map). */
struct DomainMap *domainmap_parse_file(const char *filename);

/* Add one "<ip> <domain>" line; returns 0 on success. Used by the parser
 * and the selftests. */
int domainmap_add_line(struct DomainMap *map, const char *line);

/* Domain for the address, or NULL when unmapped. */
const char *domainmap_lookup(const struct DomainMap *map,
                             const ipaddress *ip);

void domainmap_free(struct DomainMap *map);

int domainmap_selftest(void);

#endif /* DOMAIN_MAP_H */
