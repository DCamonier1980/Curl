/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
/* <DESC>
 * Show how CURLOPT_OPENSOCKETFUNCTION can be used to block IP addresses.
 * </DESC>
 */
/* This is an advanced example that defines a whitelist or a blacklist to
 * filter IP addresses.
 */

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#include <curl/curl.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

struct ip {
  /* The user-provided IP network (use CIDL) or host to filter */
  char *str;
  /* IP address family AF_INET (IPv4) or AF_INET6 (IPv6) */
  int family;
  /* IP in network byte format */
  union netaddr {
    struct in_addr ipv4;
#ifdef AF_INET6
    struct in6_addr ipv6;
#endif
  } netaddr;
  /* IP bits to match against.
   * This is equal to the CIDR notation or max bits if no CIDR.
   * For example if ip->str is 127.0.0.0/8 then ip->maskbits is 8.
   */
  int maskbits;
  struct ip *next;
};

enum connection_filter_t {
  CONNECTION_FILTER_BLACKLIST,
  CONNECTION_FILTER_WHITELIST
};

struct connection_filter {
  struct ip *list;
  enum connection_filter_t type;
  int verbose;
};

struct ip *ip_list_append(struct ip *list, const char *data)
{
  struct ip *ip, *last;
  char *cidr;

  ip = (struct ip *)calloc(1, sizeof(*ip));
  if(!ip)
    return NULL;

  if(strchr(data, ':')) {
#ifdef AF_INET6
    ip->family = AF_INET6;
#else
    free(ip);
    return NULL;
#endif
  }
  else
    ip->family = AF_INET;

  ip->str = strdup(data);
  if(!ip->str) {
    free(ip);
    return NULL;
  }

  /* determine the number of bits that this IP will match against */
  cidr = strchr(ip->str, '/');
  if(cidr) {
    ip->maskbits = atoi(cidr + 1);
    if(ip->maskbits <= 0 ||
#ifdef AF_INET6
       (ip->family == AF_INET6 && ip->maskbits > 128) ||
#endif
       (ip->family == AF_INET && ip->maskbits > 32)) {
      free(ip->str);
      free(ip);
      return NULL;
    }
    /* ignore the CIDR notation when converting ip->str to ip->netaddr */
    *cidr = '\0';
  }
  else if(ip->family == AF_INET)
    ip->maskbits = 32;
#ifdef AF_INET6
  else if(ip->family == AF_INET6)
    ip->maskbits = 128;
#endif

  if(1 != inet_pton(ip->family, ip->str, &ip->netaddr)) {
    free(ip->str);
    free(ip);
    return NULL;
  }

  if(cidr)
    *cidr = '/';

  if(!list)
    return ip;
  for(last = list; last->next; last = last->next)
    ;
  last->next = ip;
  return list;
}

void ip_list_free_all(struct ip *list)
{
  struct ip *next;
  while(list) {
    next = list->next;
    free(list->str);
    free(list);
    list = next;
  }
}

void free_connection_filter(struct connection_filter *filter)
{
  if(filter) {
    ip_list_free_all(filter->list);
    free(filter);
  }
}

int ip_match(struct ip *ip, void *netaddr)
{
  int bytes, tailbits;
  const unsigned char *x, *y;

  x = (unsigned char *)&ip->netaddr;
  y = (unsigned char *)netaddr;

  for(bytes = ip->maskbits / 8; bytes; --bytes) {
    if(*x++ != *y++)
      return FALSE;
  }

  tailbits = ip->maskbits % 8;
  if(tailbits) {
    unsigned char tailmask = (0xFF << (8 - tailbits)) & 0xFF;
    if((*x & tailmask) != (*y & tailmask))
      return FALSE;
  }

  return TRUE;
}

static curl_socket_t opensocket(void *clientp,
                                curlsocktype purpose,
                                struct curl_sockaddr *address)
{
  /* filter the address */
  if(address && purpose == CURLSOCKTYPE_IPCXN) {
    void *cinaddr = NULL;

    if(address->family == AF_INET)
      cinaddr = &((struct sockaddr_in *)&address->addr)->sin_addr;
#ifdef AF_INET6
    else if(address->family == AF_INET6)
      cinaddr = &((struct sockaddr_in6 *)&address->addr)->sin6_addr;
#endif

    if(cinaddr) {
      struct ip *ip;
      struct connection_filter *filter = (struct connection_filter *)clientp;

      for(ip = filter->list; ip; ip = ip->next) {
        if(ip->family == address->family && ip_match(ip, cinaddr))
          break;
      }

      if(ip && filter->type == CONNECTION_FILTER_BLACKLIST) {
        if(filter->verbose) {
          char buf[128] = {0};
          inet_ntop(address->family, cinaddr, buf, sizeof(buf));
          fprintf(stderr, "* Rejecting IP %s due to blacklist entry %s.\n",
                  buf, ip->str);
        }
        return CURL_SOCKET_BAD;
      }
      else if(!ip && filter->type == CONNECTION_FILTER_WHITELIST) {
        if(filter->verbose) {
          char buf[128] = {0};
          inet_ntop(address->family, cinaddr, buf, sizeof(buf));
          fprintf(stderr,
            "* Rejecting IP %s due to missing whitelist entry.\n", buf);
        }
        return CURL_SOCKET_BAD;
      }
    }
  }

  return socket(address->family, address->socktype, address->protocol);
}

int main()
{
  CURL *curl;
  CURLcode res;
  int verbose = FALSE;
  struct connection_filter *filter;

  filter = (struct connection_filter *)calloc(1, sizeof(*filter));
  if(!filter)
    exit(1);

  if(curl_global_init(CURL_GLOBAL_DEFAULT))
    exit(1);

  curl = curl_easy_init();
  if(!curl)
    exit(1);

  /* Set the target URL */
  curl_easy_setopt(curl, CURLOPT_URL, "http://localhost");

  /* Define an IP connection filter.
   * If an address has CIDR notation then it matches the network.
   * For example 74.6.143.25/24 matches 74.6.143.0 - 74.6.143.255.
   */
  filter->type = CONNECTION_FILTER_BLACKLIST;
  filter->list = ip_list_append(filter->list, "98.137.11.164");
  filter->list = ip_list_append(filter->list, "127.0.0.0/8");
#ifdef AF_INET6
  filter->list = ip_list_append(filter->list, "::1");
#endif

  /* Set the socket function which does the filtering */
  curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, opensocket);
  curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, filter);

  /* Allow insecure connections (not recommended) */
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

  verbose = TRUE;
  if(verbose) {
    filter->verbose = TRUE;
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  }

  /* Perform the request */
  res = curl_easy_perform(curl);

  /* Check for errors */
  if(res != CURLE_OK) {
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
  }

  /* Clean up */
  curl_easy_cleanup(curl);
  free_connection_filter(filter);

  /* Clean up libcurl */
  curl_global_cleanup();

  return 0;
}
