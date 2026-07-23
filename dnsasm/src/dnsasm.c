/*
 * DNSASM - C Reference Implementation
 *
 * This is a portable C implementation of the DNSASM functions.
 * It serves as:
 *   1. A fallback when assembly is not available
 *   2. A reference for testing assembly implementations
 *   3. Documentation of the algorithms
 *
 * Performance is optimized but not as fast as hand-tuned assembly.
 */

#include "dnsasm.h"
#include <string.h>

/* Byte swap 16-bit value */
static inline uint16_t bswap16(uint16_t x) {
    return (x >> 8) | (x << 8);
}

/* Byte swap 32-bit value */
static inline uint32_t bswap32(uint32_t x) {
    return ((x >> 24) & 0xff) |
           ((x >> 8) & 0xff00) |
           ((x << 8) & 0xff0000) |
           ((x << 24) & 0xff000000);
}

/*
 * Parse DNS header from packet.
 */
#ifndef DNSASM_ASM_HEADER
int dnsasm_parse_header(const uint8_t *packet, size_t len, dnsasm_header_t *out) {
    if (len < DNS_HEADER_SIZE) {
        return DNSASM_ERR_SHORT;
    }

    /* Parse 16-bit fields with byte swap */
    out->id      = bswap16(*(const uint16_t *)(packet + 0));
    out->flags   = bswap16(*(const uint16_t *)(packet + 2));
    out->qdcount = bswap16(*(const uint16_t *)(packet + 4));
    out->ancount = bswap16(*(const uint16_t *)(packet + 6));
    out->nscount = bswap16(*(const uint16_t *)(packet + 8));
    out->arcount = bswap16(*(const uint16_t *)(packet + 10));

    /* Parse individual flags */
    uint16_t flags = out->flags;
    out->qr     = (flags >> 15) & 1;
    out->opcode = (flags >> 11) & 0x0F;
    out->aa     = (flags >> 10) & 1;
    out->tc     = (flags >> 9) & 1;
    out->rd     = (flags >> 8) & 1;
    out->ra     = (flags >> 7) & 1;
    out->rcode  = flags & 0x0F;

    return DNSASM_OK;
}
#endif

/*
 * Decompress a DNS name.
 * 
 * Returns wire bytes consumed in result.offset (high 32 bits).
 * Returns error code in result.error (low 32 bits).
 */
dnsasm_result_t dnsasm_decompress_name(const uint8_t *packet, size_t len,
                                        size_t offset, uint8_t *out,
                                        uint16_t *out_len) {
    dnsasm_result_t result = {0, 0};
    size_t out_pos = 0;
    size_t wire_len = 0;
    int counting_wire = 1;
    int ptr_count = 0;
    size_t pos = offset;

    while (pos < len) {
        uint8_t label_len = packet[pos];

        /* Check for compression pointer */
        if ((label_len & 0xC0) == 0xC0) {
            if (pos + 1 >= len) {
                result.error = DNSASM_ERR_SHORT;
                return result;
            }

            /* Read 14-bit offset */
            uint16_t ptr = ((label_len & 0x3F) << 8) | packet[pos + 1];

            /* Count wire bytes for first pointer only */
            if (counting_wire) {
                wire_len += 2;
                counting_wire = 0;
            }

            /* Loop detection */
            if (++ptr_count > 127) {
                result.error = DNSASM_ERR_LOOP;
                return result;
            }

            /* Pointers must point backwards */
            if (ptr >= pos) {
                result.error = DNSASM_ERR_POINTER;
                return result;
            }

            pos = ptr;
            continue;
        }

        /* End of name */
        if (label_len == 0) {
            out[out_pos++] = 0;
            if (counting_wire) {
                wire_len++;
            }
            break;
        }

        /* Regular label */
        if (label_len > 63) {
            result.error = DNSASM_ERR_NAME;
            return result;
        }

        /* Check bounds */
        if (pos + 1 + label_len > len) {
            result.error = DNSASM_ERR_SHORT;
            return result;
        }

        /* Check output overflow */
        if (out_pos + 1 + label_len > DNS_MAX_NAME_LEN) {
            result.error = DNSASM_ERR_OVERFLOW;
            return result;
        }

        /* Copy label */
        out[out_pos++] = label_len;
        memcpy(out + out_pos, packet + pos + 1, label_len);
        out_pos += label_len;

        if (counting_wire) {
            wire_len += 1 + label_len;
        }

        pos += 1 + label_len;
    }

    *out_len = (uint16_t)out_pos;
    result.offset = (uint32_t)wire_len;
    result.error = DNSASM_OK;
    return result;
}

/*
 * Parse DNS question section.
 */
dnsasm_result_t dnsasm_parse_question(const uint8_t *packet, size_t len,
                                       size_t offset, dnsasm_question_t *out) {
    dnsasm_result_t result;

    /* Parse name */
    result = dnsasm_decompress_name(packet, len, offset, out->name, &out->name_len);
    if (result.error != DNSASM_OK) {
        return result;
    }

    size_t wire_len = result.offset;
    size_t pos = offset + wire_len;

    /* Check room for qtype + qclass */
    if (pos + 4 > len) {
        result.error = DNSASM_ERR_SHORT;
        result.offset = 0;
        return result;
    }

    /* Parse qtype and qclass */
    out->qtype = bswap16(*(const uint16_t *)(packet + pos));
    out->qclass = bswap16(*(const uint16_t *)(packet + pos + 2));
    out->wire_len = (uint16_t)(wire_len + 4);

    result.error = DNSASM_OK;
    result.offset = (uint32_t)(pos + 4);  /* Offset after question */
    return result;
}

/*
 * Parse DNS resource record.
 */
dnsasm_result_t dnsasm_parse_rr(const uint8_t *packet, size_t len,
                                 size_t offset, dnsasm_rr_t *out) {
    dnsasm_result_t result;

    /* Parse name */
    result = dnsasm_decompress_name(packet, len, offset, out->name, &out->name_len);
    if (result.error != DNSASM_OK) {
        return result;
    }

    size_t wire_len = result.offset;
    size_t pos = offset + wire_len;

    /* Check room for type(2) + class(2) + ttl(4) + rdlength(2) = 10 bytes */
    if (pos + 10 > len) {
        result.error = DNSASM_ERR_SHORT;
        result.offset = 0;
        return result;
    }

    /* Parse fixed fields */
    out->rtype = bswap16(*(const uint16_t *)(packet + pos));
    out->rclass = bswap16(*(const uint16_t *)(packet + pos + 2));
    out->ttl = bswap32(*(const uint32_t *)(packet + pos + 4));
    out->rdlength = bswap16(*(const uint16_t *)(packet + pos + 8));

    pos += 10;

    /* Check room for rdata */
    if (pos + out->rdlength > len) {
        result.error = DNSASM_ERR_SHORT;
        result.offset = 0;
        return result;
    }

    out->rdata = packet + pos;
    out->wire_len = (uint16_t)(wire_len + 10 + out->rdlength);

    result.error = DNSASM_OK;
    result.offset = (uint32_t)(pos + out->rdlength);
    return result;
}

/*
 * Build DNS header.
 */
#ifndef DNSASM_ASM_HEADER
size_t dnsasm_build_header(uint8_t *out, uint16_t id, uint16_t flags,
                            uint16_t qdcount, uint16_t ancount,
                            uint16_t nscount, uint16_t arcount) {
    *(uint16_t *)(out + 0) = bswap16(id);
    *(uint16_t *)(out + 2) = bswap16(flags);
    *(uint16_t *)(out + 4) = bswap16(qdcount);
    *(uint16_t *)(out + 6) = bswap16(ancount);
    *(uint16_t *)(out + 8) = bswap16(nscount);
    *(uint16_t *)(out + 10) = bswap16(arcount);
    return DNS_HEADER_SIZE;
}
#endif

/*
 * Copy question section.
 */
size_t dnsasm_copy_question(uint8_t *out, const uint8_t *packet,
                             size_t offset, size_t qlen) {
    memcpy(out, packet + offset, qlen);
    return qlen;
}

/*
 * Build A record.
 */
size_t dnsasm_build_a_record(uint8_t *out, const uint8_t *name, size_t name_len,
                              uint32_t ttl, const uint8_t *ip) {
    size_t pos = 0;

    /* Copy name */
    memcpy(out, name, name_len);
    pos += name_len;

    /* Type = A (1) */
    *(uint16_t *)(out + pos) = bswap16(DNS_TYPE_A);
    pos += 2;

    /* Class = IN (1) */
    *(uint16_t *)(out + pos) = bswap16(DNS_CLASS_IN);
    pos += 2;

    /* TTL */
    *(uint32_t *)(out + pos) = bswap32(ttl);
    pos += 4;

    /* RDLENGTH = 4 */
    *(uint16_t *)(out + pos) = bswap16(4);
    pos += 2;

    /* RDATA (IP address) */
    memcpy(out + pos, ip, 4);
    pos += 4;

    return pos;
}

/*
 * Compare two DNS names (case-insensitive).
 */
int dnsasm_name_equal(const uint8_t *a, size_t a_len,
                       const uint8_t *b, size_t b_len) {
    if (a_len != b_len) {
        return 1;  /* Not equal */
    }

    for (size_t i = 0; i < a_len; i++) {
        uint8_t ca = a[i];
        uint8_t cb = b[i];

        /* Convert to lowercase if letter */
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;

        if (ca != cb) {
            return 1;  /* Not equal */
        }
    }

    return 0;  /* Equal */
}

/*
 * Find a name in a list.
 */
int dnsasm_name_find(const uint8_t *needle, size_t needle_len,
                      const uint8_t **haystack, size_t count) {
    for (size_t i = 0; i < count; i++) {
        /* Assume each haystack entry has a length prefix or is null-terminated */
        /* For simplicity, we'll compare until null */
        size_t hay_len = 0;
        const uint8_t *hay = haystack[i];
        
        /* Calculate length (wire format - sum of labels) */
        size_t pos = 0;
        while (hay[pos] != 0 && pos < DNS_MAX_NAME_LEN) {
            pos += 1 + hay[pos];
        }
        hay_len = pos + 1;  /* Including null terminator */

        if (dnsasm_name_equal(needle, needle_len, hay, hay_len) == 0) {
            return (int)i;
        }
    }

    return -1;  /* Not found */
}
