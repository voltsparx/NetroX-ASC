%ifndef ICMP_ENGINE_INC
%define ICMP_ENGINE_INC 1

; ============================================================
; build_icmp_packet
; ============================================================
build_icmp_packet:
    mov  byte [packet_buf+9],  1
    mov  word [packet_buf+2],  0x3C00
    mov  byte [packet_buf+33], 0
    mov  ax, [packet_buf+4]
    inc  ax
    mov  [packet_buf+4], ax
    mov  word [packet_buf+10], 0
    lea  rdi, [packet_buf]
    call ip_checksum
    mov  [packet_buf+10], ax
    mov  byte [packet_buf+20], 8
    mov  byte [packet_buf+21], 0
    mov  word [packet_buf+22], 0
    mov  word [packet_buf+24], 0x3412
    mov  ax, [dst_port_be]
    mov  [packet_buf+26], ax
    lea  rdi, [packet_buf+28]
    mov  ecx, 32
    mov  al, 0x41
    rep  stosb
    xor  rax, rax
    lea  rsi, [packet_buf+20]
    mov  ecx, 20
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
