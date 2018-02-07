/*
 * Copyright (c) 2016-2018, OARC, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include "endpoint.h"
#include "args.h"
#include "iaddr.h"

void endpoint_arg(endpoint_list* list, const char* arg)
{
    struct addrinfo* ai;
    iaddr            ia;
    void*            p;

    if (inet_pton(AF_INET6, arg, &ia.u.a6) > 0) {
        ia.af = AF_INET6;
        endpoint_add(list, ia);
    } else if (inet_pton(AF_INET, arg, &ia.u.a4) > 0) {
        ia.af = AF_INET;
        endpoint_add(list, ia);
    } else if (getaddrinfo(arg, NULL, NULL, &ai) == 0) {
        struct addrinfo* a;

        for (a = ai; a != NULL; a = a->ai_next) {
            if (a->ai_socktype != SOCK_DGRAM)
                continue;
            switch (a->ai_family) {
            case PF_INET:
                ia.af = AF_INET;
                p     = &((struct sockaddr_in*)a->ai_addr)
                         ->sin_addr;
                memcpy(&ia.u.a4, p, sizeof ia.u.a4);
                break;
            case PF_INET6:
                ia.af = AF_INET6;
                p     = &((struct sockaddr_in6*)a->ai_addr)
                         ->sin6_addr;
                memcpy(&ia.u.a6, p, sizeof ia.u.a6);
                break;
            default:
                continue;
            }
            endpoint_add(list, ia);
        }
        freeaddrinfo(ai);
    } else
        usage("invalid host address");
}

void endpoint_add(endpoint_list* list, iaddr ia)
{
    endpoint_ptr ep;

    ep = calloc(1, sizeof *ep);
    assert(ep != NULL);
    INIT_LINK(ep, link);
    ep->ia = ia;
    APPEND(*list, ep, link);
}

int ep_present(const endpoint_list* list, iaddr ia)
{
    endpoint_ptr ep;

    for (ep = HEAD(*list);
         ep != NULL;
         ep = NEXT(ep, link))
        if (ia_equal(ia, ep->ia))
            return TRUE;
    return (FALSE);
}
