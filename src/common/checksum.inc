%macro ADD_WORD_BE 1
    movzx rbx, byte [%1]
    shl rbx, 8
    movzx rdx, byte [%1+1]
    or rbx, rdx
    add rax, rbx
%endmacro

; ip_checksum
; rdi -> IP header (20 bytes)
; returns ax = checksum (byte-swapped for little-endian store)
ip_checksum:
    xor rax, rax
    mov rcx, 10
    mov rsi, rdi

.ip_sum_loop:
    movzx rbx, byte [rsi]
    shl rbx, 8
    movzx rdx, byte [rsi+1]
    or rbx, rdx
    add rax, rbx
    add rsi, 2
    loop .ip_sum_loop

    mov rbx, rax
    shr rbx, 16
    and eax, 0xFFFF
    add eax, ebx
    mov ebx, eax
    shr ebx, 16
    add eax, ebx
    not ax
    xchg al, ah
    ret

; tcp_checksum
; rdi -> packet buffer (IP header at 0, TCP header at 20)
; returns ax = checksum (byte-swapped for little-endian store)
tcp_checksum:
    xor rax, rax

    ADD_WORD_BE rdi+12
    ADD_WORD_BE rdi+14
    ADD_WORD_BE rdi+16
    ADD_WORD_BE rdi+18
    add rax, 0x0006
    add rax, 0x0014

    mov rcx, 10
    lea rsi, [rdi+20]

.tcp_sum_loop:
    movzx rbx, byte [rsi]
    shl rbx, 8
    movzx rdx, byte [rsi+1]
    or rbx, rdx
    add rax, rbx
    add rsi, 2
    loop .tcp_sum_loop

    mov rbx, rax
    shr rbx, 16
    and eax, 0xFFFF
    add eax, ebx
    mov ebx, eax
    shr ebx, 16
    add eax, ebx
    not ax
    xchg al, ah
    ret