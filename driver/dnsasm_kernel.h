#ifndef _DNSASM_KERNEL_H
#define _DNSASM_KERNEL_H

#include <linux/types.h>

/* DNS Header Constants */
#define DNS_HEADER_SIZE 12

/* DNS Header Structure */
typedef struct {
    u16 id;
    u16 flags;
    u16 qdcount;
    u16 ancount;
    u16 nscount;
    u16 arcount;

    /* Parsed flags */
    u8 qr;
    u8 opcode;
    u8 aa;
    u8 tc;
    u8 rd;
    u8 ra;
    u8 rcode;
} dnsasm_header_t;

/* Error Codes */
#define DNSASM_OK           0
#define DNSASM_ERR_SHORT    1
#define DNSASM_ERR_NAME     2
#define DNSASM_ERR_POINTER  3
#define DNSASM_ERR_LOOP     4
#define DNSASM_ERR_OVERFLOW 5

#endif /* _DNSASM_KERNEL_H */
