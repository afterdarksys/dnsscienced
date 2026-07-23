; DNSASM - Ultra-Fast DNS Packet Processor
; x86_64 NASM Assembly - Header Parsing
;
; This module parses DNS headers using baseline x86_64 SSE2.
;
; Calling Convention: System V AMD64 ABI
;   - Arguments: rdi, rsi, rdx, rcx, r8, r9
;   - Return: rax (int), xmm0 (float)
;   - Caller-saved: rax, rcx, rdx, rsi, rdi, r8-r11, xmm0-xmm15
;   - Callee-saved: rbx, rbp, r12-r15

bits 64
default rel

section .data
    align 16

section .text
    global dnsasm_parse_header
    global dnsasm_build_header

; ============================================================================
; int dnsasm_parse_header(const uint8_t *packet, size_t len, dnsasm_header_t *out)
;
; Arguments:
;   rdi = packet pointer
;   rsi = packet length
;   rdx = output structure pointer
;
; Returns:
;   0 on success, negative error code on failure
;
; Performance: ~5 cycles (single SSE2 load + byte swap)
; ============================================================================
dnsasm_parse_header:
    ; Check minimum length (12 bytes for DNS header)
    cmp     rsi, 12
    jb      .too_short

    ; Load exactly 12 bytes. A 16-byte load is not safe for a caller that
    ; provides a valid 12-byte slice at the end of an accessible page.
    movq    xmm0, [rdi]
    movd    xmm2, [rdi + 8]
    pslldq  xmm2, 8
    por     xmm0, xmm2

    ; Byte swap all 16-bit words using baseline SSE2. This avoids requiring
    ; runtime SSSE3/AVX feature dispatch.
    movdqa  xmm1, xmm0
    psllw   xmm0, 8
    psrlw   xmm1, 8
    por     xmm0, xmm1

    ; Store only the 12 wire bytes to the output structure. A 16-byte store
    ; would temporarily overwrite the parsed-flag fields.
    ; dnsasm_header_t layout:
    ;   0-1:   id
    ;   2-3:   flags  
    ;   4-5:   qdcount
    ;   6-7:   ancount
    ;   8-9:   nscount
    ;   10-11: arcount
    movq    [rdx], xmm0
    psrldq  xmm0, 8
    movd    [rdx + 8], xmm0

    ; Now parse the flags field (bytes 2-3, already byte-swapped)
    movzx   eax, word [rdx + 2]     ; Load flags

    ; Parse individual flag bits
    ; Flags layout (after byte swap, in host order):
    ;   Bit 15:    QR (Query/Response)
    ;   Bits 14-11: Opcode
    ;   Bit 10:    AA (Authoritative Answer)
    ;   Bit 9:     TC (Truncated)
    ;   Bit 8:     RD (Recursion Desired)
    ;   Bit 7:     RA (Recursion Available)
    ;   Bits 6-4:  Z (Reserved)
    ;   Bits 3-0:  RCODE

    ; QR (bit 15)
    mov     ecx, eax
    shr     ecx, 15
    mov     byte [rdx + 12], cl     ; qr

    ; Opcode (bits 14-11)
    mov     ecx, eax
    shr     ecx, 11
    and     ecx, 0x0F
    mov     byte [rdx + 13], cl     ; opcode

    ; AA (bit 10)
    mov     ecx, eax
    shr     ecx, 10
    and     ecx, 1
    mov     byte [rdx + 14], cl     ; aa

    ; TC (bit 9)
    mov     ecx, eax
    shr     ecx, 9
    and     ecx, 1
    mov     byte [rdx + 15], cl     ; tc

    ; RD (bit 8)
    mov     ecx, eax
    shr     ecx, 8
    and     ecx, 1
    mov     byte [rdx + 16], cl     ; rd

    ; RA (bit 7)
    mov     ecx, eax
    shr     ecx, 7
    and     ecx, 1
    mov     byte [rdx + 17], cl     ; ra

    ; RCODE (bits 3-0)
    mov     ecx, eax
    and     ecx, 0x0F
    mov     byte [rdx + 18], cl     ; rcode

    ; Success
    xor     eax, eax
    ret

.too_short:
    mov     eax, -1                 ; DNSASM_ERR_SHORT
    ret


; ============================================================================
; size_t dnsasm_build_header(uint8_t *out, uint16_t id, uint16_t flags,
;                            uint16_t qdcount, uint16_t ancount,
;                            uint16_t nscount, uint16_t arcount)
;
; Arguments:
;   rdi = output buffer
;   si  = id
;   dx  = flags
;   cx  = qdcount
;   r8w = ancount
;   r9w = nscount
;   [rsp+8] = arcount (stack)
;
; Returns:
;   12 (number of bytes written)
;
; Performance: ~10 cycles
; ============================================================================
dnsasm_build_header:
    ; Byte swap and store each field.

    ; ID (bytes 0-1)
    mov     ax, si                  ; id
    xchg    al, ah                  ; byte swap
    mov     [rdi], ax

    mov     ax, dx                  ; flags
    xchg    al, ah
    mov     [rdi + 2], ax

    mov     ax, cx                  ; qdcount
    xchg    al, ah
    mov     [rdi + 4], ax

    mov     ax, r8w                 ; ancount
    xchg    al, ah
    mov     [rdi + 6], ax

    mov     ax, r9w                 ; nscount
    xchg    al, ah
    mov     [rdi + 8], ax

    mov     ax, [rsp + 8]           ; arcount (from stack)
    xchg    al, ah
    mov     [rdi + 10], ax

    mov     eax, 12                 ; Return 12 bytes written
    ret
