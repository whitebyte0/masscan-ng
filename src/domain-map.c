#include "domain-map.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "massip-parse.h"
#include "massip.h"
#include "logger.h"

/*
 * See domain-map.h for the design notes. Everything here runs at config
 * time except domainmap_lookup, which runs per connection on the transmit
 * path — it is a plain binary search over an immutable sorted array.
 */

static int entry_cmp(const void *pa, const void *pb) {
  const struct DomainMapEntry *a = (const struct DomainMapEntry *)pa;
  const struct DomainMapEntry *b = (const struct DomainMapEntry *)pb;

  if (a->ip.version != b->ip.version)
    return (int)a->ip.version - (int)b->ip.version;
  if (a->ip.version == 4) {
    if (a->ip.ipv4 == b->ip.ipv4)
      return 0;
    return (a->ip.ipv4 < b->ip.ipv4) ? -1 : 1;
  }
  if (a->ip.ipv6.hi != b->ip.ipv6.hi)
    return (a->ip.ipv6.hi < b->ip.ipv6.hi) ? -1 : 1;
  if (a->ip.ipv6.lo != b->ip.ipv6.lo)
    return (a->ip.ipv6.lo < b->ip.ipv6.lo) ? -1 : 1;
  return 0;
}

/*
 * The stock massip parsers are lenient (they are built to skip junk in
 * target lists), but a domain-map file is operator-written and small —
 * strict validation here turns typos into a startup error instead of a
 * silently narrowed map.
 */
static int valid_ipv4_literal(const char *s) {
  int octets = 0;

  while (*s) {
    long v = 0;
    int digits = 0;
    while (isdigit((unsigned char)*s)) {
      v = v * 10 + (*s - '0');
      digits++;
      if (digits > 3 || v > 255)
        return 0;
      s++;
    }
    if (digits == 0)
      return 0;
    octets++;
    if (*s == '.') {
      s++;
      if (*s == '\0') /* trailing dot */
        return 0;
      continue;
    }
    break;
  }
  return *s == '\0' && octets == 4;
}

static int valid_ipv6_literal(const char *s) {
  int groups = 0;
  int double_colons = 0;
  int digits;

  if (*s == '\0')
    return 0;
  if (s[0] == ':' && s[1] == ':') {
    double_colons++;
    s += 2;
    if (*s == '\0')
      return 1; /* "::" alone */
  }
  while (*s) {
    digits = 0;
    while (isxdigit((unsigned char)*s)) {
      s++;
      if (++digits > 4)
        return 0;
    }
    if (digits > 0)
      groups++;
    if (*s == '\0')
      break;
    if (*s != ':')
      return 0; /* hex digits and colons only (v4-in-v6 tail not
                   accepted — write those as 6 groups + v4 counts as 2) */
    s++;
    if (*s == ':') {
      if (double_colons)
        return 0; /* second "::" */
      double_colons++;
      s++;
      if (*s == '\0')
        return 1;
      continue;
    }
    if (*s == '\0')
      return 0; /* trailing single colon */
  }
  if (double_colons)
    return groups <= 7;
  return groups == 8;
}

int domainmap_add_line(struct DomainMap *map, const char *line) {
  const char *p = line;
  char ipbuf[64];
  size_t i = 0;
  ipaddress ip;
  const char *domain;
  char *copy;
  size_t domain_len;

  /* skip leading whitespace and comment/blank lines */
  while (*p && isspace((unsigned char)*p))
    p++;
  if (*p == '\0' || *p == '#')
    return 0;

  /* first token: the IP (v4 or v6 literal) */
  while (*p && !isspace((unsigned char)*p)) {
    if (i + 1 >= sizeof(ipbuf))
      return -1;
    ipbuf[i++] = *p++;
  }
  ipbuf[i] = '\0';
  if (strchr(ipbuf, ':') != NULL) {
    ipv6address_t v6;
    if (!valid_ipv6_literal(ipbuf) || massip_parse_ipv6(&v6, ipbuf) == NULL)
      return -1;
    ip.ipv6 = v6;
    ip.version = 6;
  } else {
    ipv4address_t v4;
    if (!valid_ipv4_literal(ipbuf) || massip_parse_ipv4(&v4, ipbuf) == NULL)
      return -1;
    ip.ipv4 = v4;
    ip.version = 4;
  }

  /* second token: the domain name */
  while (*p && isspace((unsigned char)*p))
    p++;
  if (*p == '\0')
    return -1;
  domain = p;
  while (*p && !isspace((unsigned char)*p))
    p++;
  domain_len = (size_t)(p - domain);
  if (domain_len == 0 || domain_len > 253)
    return -1;
  copy = (char *)malloc(domain_len + 1);
  if (copy == NULL)
    return -1;
  memcpy(copy, domain, domain_len);
  copy[domain_len] = '\0';

  /* grow and append; sorted after loading */
  {
    struct DomainMapEntry *grown = (struct DomainMapEntry *)realloc(
        map->entries, (map->count + 1) * sizeof(*map->entries));
    if (grown == NULL) {
      free(copy);
      return -1;
    }
    map->entries = grown;
    map->entries[map->count].ip = ip;
    map->entries[map->count].domain = copy;
    map->count++;
  }
  return 0;
}

static void domainmap_sort(struct DomainMap *map) {
  size_t i;

  if (map->count > 1)
    qsort(map->entries, map->count, sizeof(*map->entries), entry_cmp);

  /* duplicate IPs would be an orchestrator bug; last line wins */
  for (i = 1; i < map->count; i++) {
    if (entry_cmp(&map->entries[i - 1], &map->entries[i]) == 0) {
      LOG(LEVEL_WARNING, "domain-map: duplicate IP, keeping the last\n");
      free(map->entries[i - 1].domain);
      memmove(&map->entries[i - 1], &map->entries[i],
              (map->count - i) * sizeof(*map->entries));
      map->count--;
    }
  }
}

struct DomainMap *domainmap_parse_file(const char *filename) {
  FILE *fp;
  char line[512];
  struct DomainMap *map;

  fp = fopen(filename, "rt");
  if (fp == NULL)
    return NULL;

  map = (struct DomainMap *)calloc(1, sizeof(*map));
  if (map == NULL) {
    fclose(fp);
    return NULL;
  }

  while (fgets(line, sizeof(line), fp)) {
    if (domainmap_add_line(map, line) == -1) {
      LOG(LEVEL_ERROR, "domain-map: bad line: %s", line);
      domainmap_free(map);
      fclose(fp);
      return NULL;
    }
  }
  fclose(fp);

  domainmap_sort(map);
  return map;
}

const char *domainmap_lookup(const struct DomainMap *map,
                             const ipaddress *ip) {
  size_t lo = 0;
  size_t hi = map->count;

  if (map == NULL || map->count == 0)
    return NULL;

  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    int c = entry_cmp(&map->entries[mid], ip);
    if (c == 0)
      return map->entries[mid].domain;
    if (c < 0)
      lo = mid + 1;
    else
      hi = mid;
  }
  return NULL;
}

void domainmap_free(struct DomainMap *map) {
  size_t i;

  if (map == NULL)
    return;
  for (i = 0; i < map->count; i++)
    free(map->entries[i].domain);
  free(map->entries);
  free(map);
}

int domainmap_selftest(void) {
  struct DomainMap *map;
  ipaddress ip;
  const char *d;
  int x = 0;

  map = (struct DomainMap *)calloc(1, sizeof(*map));

  /* valid v4 + v6 lines, plus comment/blank noise */
  if (domainmap_add_line(map, "# comment") != 0)
    x++;
  if (domainmap_add_line(map, "   ") != 0)
    x++;
  if (domainmap_add_line(map, "192.0.2.10 one.example.com") != 0)
    x++;
  if (domainmap_add_line(map, "2001:db8::1 six.example.com") != 0)
    x++;
  if (domainmap_add_line(map, "192.0.2.3 three.example.com") != 0)
    x++;
  {
    /* sort manually: file parser sorts, add_line does not */
    struct DomainMap wrapper = *map;
    qsort(wrapper.entries, wrapper.count, sizeof(*wrapper.entries),
          entry_cmp);
    *map = wrapper;
  }

  ip.version = 4;
  ip.ipv4 = 0xC000020A; /* 192.0.2.10 */
  d = domainmap_lookup(map, &ip);
  if (d == NULL || strcmp(d, "one.example.com") != 0) {
    LOG(LEVEL_ERROR, "domainmap: v4 lookup failed\n");
    x++;
  }

  ip.version = 4;
  ip.ipv4 = 0xC0000203; /* 192.0.2.3 */
  d = domainmap_lookup(map, &ip);
  if (d == NULL || strcmp(d, "three.example.com") != 0) {
    LOG(LEVEL_ERROR, "domainmap: v4 sorted lookup failed\n");
    x++;
  }

  ip.version = 6;
  ip.ipv6.hi = 0x20010db800000000ULL;
  ip.ipv6.lo = 1;
  d = domainmap_lookup(map, &ip);
  if (d == NULL || strcmp(d, "six.example.com") != 0) {
    LOG(LEVEL_ERROR, "domainmap: v6 lookup failed\n");
    x++;
  }

  ip.version = 4;
  ip.ipv4 = 0xC0000299; /* 192.0.2.153 — absent */
  if (domainmap_lookup(map, &ip) != NULL) {
    LOG(LEVEL_ERROR, "domainmap: absent address matched\n");
    x++;
  }

  /* rejections */
  {
    struct DomainMap *bad = (struct DomainMap *)calloc(1, sizeof(*bad));
    if (domainmap_add_line(bad, "999.1.2.3 x.example.com") == 0) {
      LOG(LEVEL_ERROR, "domainmap: accepted bad ipv4\n");
      x++;
    }
    if (domainmap_add_line(bad, "2001:zz::1 x.example.com") == 0) {
      LOG(LEVEL_ERROR, "domainmap: accepted bad ipv6\n");
      x++;
    }
    if (domainmap_add_line(bad, "192.0.2.1") == 0) {
      LOG(LEVEL_ERROR, "domainmap: accepted missing domain\n");
      x++;
    }
    domainmap_free(bad);
  }

  domainmap_free(map);
  return x;
}
