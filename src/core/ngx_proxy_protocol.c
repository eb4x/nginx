
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


u_char *
ngx_proxy_protocol_read(ngx_connection_t *c, u_char *buf, u_char *last)
{
    /* Store offset and length into proxy protocol header,
     * because we're just gonna memcpy the whole shebang */

    size_t len;
    int i;
    u_char ch, *p;

    struct {
        size_t off;
        size_t len;
    } item[4];


    len = last - buf;

    /* Handle this special usecase, sizeof should be 15 */
    if (len >= 15 && ngx_strncmp(buf, "PROXY UNKNOWN" CRLF, 15) == 0) {
        c->proxy_protocol_header.data = ngx_pnalloc(c->pool, 15);
        if (c->proxy_protocol_header.data == NULL) {
            return NULL;
        }

        c->proxy_protocol_header.len = 15;
        ngx_memcpy(c->proxy_protocol_header.data, buf, len);
        return buf + 15;
    }

    /* Smallest "valid" headers.
     * "PROXY TCP4 1.1.1.1 2.2.2.2 1 2\r\n" 32 bytes
     * "PROXY TCP6 :: :: 1 2\r\n"           22 bytes
     */

    if (len <= 11 || ngx_strncmp(buf, "PROXY TCP", 9) != 0 ||
        (buf[9] != '4' && buf[9] != '6') || buf[10] != ' ') {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "proxy protocol header mismatch: \"%.*s\"", (int) (last - buf), buf);

        return NULL;
    }

    p = buf + 11;

    /* Here we'll parse src_addr, dst_addr, src_port and dst_port.
     * They're all separated by a space (' '), and ends on a CR. */

    item[0].off = 11; /* p - buf */
    item[0].len = 0;

    for (i = 0, ch = *p++; ch != CR; ch = *p++) {
        if (p >= last) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "proxy protocol header ended unexpectedly: \"%.*s\"", (int) (last - buf), buf);
            return NULL;
        }

        if (ch == ' ') {
            i += 1;
            item[i].off = p - buf;
            item[i].len = 0;
            continue;
        }

        if (ch != ':' && ch != '.'
            && (ch < 'a' || ch > 'f')
            && (ch < 'A' || ch > 'F')
            && (ch < '0' || ch > '9'))
        {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "proxy protocol header invalid character: \"%.*s\"", (int) (p - buf), buf);
            return NULL;
        }

        item[i].len++;
    }

    if (*p++ != LF) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "proxy protocol header missing LF: \"%.*s\"", (int) (p - buf), buf);
        return NULL;
    }

    len = p - buf;

    c->proxy_protocol_header.data = ngx_pnalloc(c->pool, len);
    if (c->proxy_protocol_header.data == NULL) {
        return NULL;
    }

    c->proxy_protocol_header.len = len;
    ngx_memcpy(c->proxy_protocol_header.data, buf, len);

    c->proxy_protocol_src_addr.data = c->proxy_protocol_header.data + item[0].off;
    c->proxy_protocol_dst_addr.data = c->proxy_protocol_header.data + item[1].off;
    c->proxy_protocol_src_port.data = c->proxy_protocol_header.data + item[2].off;
    c->proxy_protocol_dst_port.data = c->proxy_protocol_header.data + item[3].off;

    c->proxy_protocol_src_addr.len = item[0].len;
    c->proxy_protocol_dst_addr.len = item[1].len;
    c->proxy_protocol_src_port.len = item[2].len;
    c->proxy_protocol_dst_port.len = item[3].len;

    /* <legacy code> */
    c->proxy_protocol_addr.data = c->proxy_protocol_header.data + item[0].off;
    c->proxy_protocol_addr.len = item[0].len;
    c->proxy_protocol_port = ngx_atoi(c->proxy_protocol_src_port.data, c->proxy_protocol_src_port.len);
    /* </legacy code> */

    return p;
}

u_char *
ngx_proxy_protocol_write(ngx_connection_t *c, u_char *buf, u_char *last)
{
    ngx_uint_t  port, lport;

    if (last - buf < NGX_PROXY_PROTOCOL_MAX_HEADER) {
        return NULL;
    }

    if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
        return NULL;
    }

    /* The header is all there, just waiting to be passed on. */
    if (c->proxy_protocol_header.data) {
        return ngx_cpymem(buf, c->proxy_protocol_header.data, c->proxy_protocol_header.len);
    }

    switch (c->sockaddr->sa_family) {

    case AF_INET:
        buf = ngx_cpymem(buf, "PROXY TCP4 ", sizeof("PROXY TCP4 ") - 1);
        break;

#if (NGX_HAVE_INET6)
    case AF_INET6:
        buf = ngx_cpymem(buf, "PROXY TCP6 ", sizeof("PROXY TCP6 ") - 1);
        break;
#endif

    default:
        return ngx_cpymem(buf, "PROXY UNKNOWN" CRLF,
                          sizeof("PROXY UNKNOWN" CRLF) - 1);
    }

    buf += ngx_sock_ntop(c->sockaddr, c->socklen, buf, last - buf, 0);

    *buf++ = ' ';

    buf += ngx_sock_ntop(c->local_sockaddr, c->local_socklen, buf, last - buf,
                         0);

    port = ngx_inet_get_port(c->sockaddr);
    lport = ngx_inet_get_port(c->local_sockaddr);

    return ngx_slprintf(buf, last, " %ui %ui" CRLF, port, lport);
}

// vim: et ts=4
