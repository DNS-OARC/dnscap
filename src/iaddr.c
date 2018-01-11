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

#include "iaddr.h"

const char* ia_str(iaddr ia)
{
    static char inet[INET_ADDRSTRLEN], inet6[INET6_ADDRSTRLEN];

    switch (ia.af) {
    case AF_INET:
        if (inet_ntop(ia.af, &ia.u, inet, sizeof(inet)))
            return inet;
        return "255.255.255.255";
    case AF_INET6:
        if (inet_ntop(ia.af, &ia.u, inet6, sizeof(inet6)))
            return inet6;
        return "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
    }

    return "UNKNOWN";
}

int ia_equal(iaddr x, iaddr y)
{
    if (x.af != y.af)
        return FALSE;
    switch (x.af) {
    case AF_INET:
        return (x.u.a4.s_addr == y.u.a4.s_addr);
    case AF_INET6:
        return (memcmp(&x.u.a6, &y.u.a6, sizeof x.u.a6) == 0);
    }
    return FALSE;
}
