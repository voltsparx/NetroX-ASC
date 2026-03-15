; ============================================================
; NetroX-ASM Hybrid | Windows network helpers (WIP extraction)
; ============================================================
%ifndef NETWORK_WINDOWS_ASM
%define NETWORK_WINDOWS_ASM 1

default rel

%ifndef SOCKET_ERROR
%define SOCKET_ERROR -1
%endif

SECTION .text
global asm_host_probe
global asm_get_local_ip
global setup_sigint_handler
global sigint_handler

asm_get_local_ip:
    xor eax, eax
    ret

asm_host_probe:
    push rbx
    push r12
    mov r12b, [engine_id]
    mov bl, [scan_mode]
    mov byte [engine_id], ENGINE_ICMP
    xor ax, ax
    mov [dst_port_be], ax
    call build_icmp_packet
    call intel_rtt_start

    ; sendto
    mov edx, 60
    sub rsp, 56
    mov rcx, [sock_fd]
    lea rdx, [packet_buf]
    mov r8d, edx
    lea rdx, [packet_buf]
    xor r9d, r9d
    lea rax, [sockaddr_dst]
    mov [rsp+32], rax
    mov qword [rsp+40], 16
    call sendto
    add rsp, 56

    mov byte [host_up_map], 0
    ; recvfrom with timeout (SO_RCVTIMEO)
    sub rsp, 56
    mov rcx, [sock_fd]
    lea rdx, [recv_buf]
    mov r8d, 4096
    xor r9d, r9d
    mov qword [rsp+32], 0
    mov qword [rsp+40], 0
    call recvfrom
    add rsp, 56
    cmp eax, SOCKET_ERROR
    je .restore

    lea rsi, [recv_buf]
    mov al, [rsi+9]
    cmp al, 1
    jne .restore
    mov eax, [rsi+12]
    cmp eax, [target_ip]
    jne .restore
    mov al, [rsi+20]
    cmp al, 0
    jne .restore
    mov byte [host_up_map], 1
    mov al, [rsi+8]
    mov [last_ttl], al
    call intel_rtt_record

.restore:
    mov [engine_id], r12b
    mov [scan_mode], bl
    pop r12
    pop rbx
    ret

setup_sigint_handler:
    lea rcx, [sigint_handler]
    xor edx, edx
    call SetConsoleCtrlHandler
    ret

sigint_handler:
    mov byte [scan_done_flag], 1
    xor eax, eax
    ret

%include "../common/constants.inc"
%include "../common/packet.inc"
%include "../common/checksum.inc"
%include "../common/intelligence.inc"

extern sendto
extern recvfrom
extern SetConsoleCtrlHandler
extern SOCKET_ERROR

%endif
