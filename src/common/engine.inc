%ifndef ENGINE_INC
%define ENGINE_INC 1

; ============================================================
; Engine IDs  -  stored in engine_id (.bss byte)
; ============================================================
%define ENGINE_SYN      1       ; TCP raw socket, all TCP flag scans
%define ENGINE_UDP      2       ; UDP raw socket scan
%define ENGINE_ICMP     3       ; ICMP Echo Request (ping scan)
%define ENGINE_L2       4       ; AF_PACKET layer-2 send (--iface mode)

; ============================================================
; build_packet
; Central dispatcher. Reads engine_id and jumps to builder.
; All builders expect dst_port_be set before the call.
; ============================================================
build_packet:
    mov  al, [engine_id]
    cmp  al, ENGINE_ICMP
    je   build_icmp_packet
    cmp  al, ENGINE_UDP
    je   build_udp_packet
    jmp  build_syn_packet       ; ENGINE_SYN and ENGINE_L2

; ============================================================
; build_udp_packet
; Minimal UDP datagram in packet_buf. Total: 28 bytes.
; UDP checksum = 0 (legal per RFC 768 for IPv4).
; ============================================================
build_udp_packet:
    mov  byte [packet_buf+9],  17       ; IP protocol = UDP
    mov  word [packet_buf+2],  0x1C00   ; IP total length = 28
    mov  ax, [packet_buf+4]
    inc  ax
    mov  [packet_buf+4], ax             ; Bump IP ID
    mov  word [packet_buf+10], 0
    lea  rdi, [packet_buf]
    call ip_checksum
    mov  [packet_buf+10], ax
    mov  ax, [src_port_be]
    mov  [packet_buf+20], ax            ; UDP src port
    mov  ax, [dst_port_be]
    mov  [packet_buf+22], ax            ; UDP dst port
    mov  [sockaddr_dst+2], ax
    mov  word [packet_buf+24], 0x0800   ; UDP length = 8
    mov  word [packet_buf+26], 0        ; UDP checksum = 0
    ret

; ============================================================
; build_icmp_packet
; ICMP Echo Request in packet_buf. Total: 60 bytes.
; Sequence field reuses dst_port_be for uniqueness in sweeps.
; ============================================================
build_icmp_packet:
    mov  byte [packet_buf+9],  1        ; IP protocol = ICMP
    mov  word [packet_buf+2],  0x3C00   ; IP total length = 60
    mov  byte [packet_buf+33], 0        ; Clear any leftover TCP flags byte
    mov  ax, [packet_buf+4]
    inc  ax
    mov  [packet_buf+4], ax             ; Bump IP ID
    mov  word [packet_buf+10], 0
    lea  rdi, [packet_buf]
    call ip_checksum
    mov  [packet_buf+10], ax
    mov  byte [packet_buf+20], 8        ; ICMP type = Echo Request
    mov  byte [packet_buf+21], 0        ; ICMP code = 0
    mov  word [packet_buf+22], 0        ; ICMP checksum placeholder
    mov  word [packet_buf+24], 0x3412   ; Identifier = 0x1234
    mov  ax, [dst_port_be]
    mov  [packet_buf+26], ax            ; Sequence = dst_port_be
    lea  rdi, [packet_buf+28]           ; Fill 32 bytes data with 'A'
    mov  ecx, 32
    mov  al, 0x41
    rep  stosb
    xor  rax, rax                       ; Compute ICMP checksum
    lea  rsi, [packet_buf+20]
    mov  ecx, 20                        ; 40 bytes / 2
.icmp_sum:
    movzx rbx, byte [rsi]
    shl   rbx, 8
    movzx rdx, byte [rsi+1]
    or    rbx, rdx
    add   rax, rbx
    add   rsi, 2
    loop  .icmp_sum
    mov  rbx, rax
    shr  rbx, 16
    and  eax, 0xFFFF
    add  eax, ebx
    mov  ebx, eax
    shr  ebx, 16
    add  eax, ebx
    not  ax
    xchg al, ah
    mov  [packet_buf+22], ax
    ret

%endif
