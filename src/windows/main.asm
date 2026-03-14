BITS 64
DEFAULT REL
GLOBAL _start

extern WSAStartup
extern WSACleanup
extern socket
extern closesocket
extern setsockopt
extern sendto
extern recvfrom
extern connect
extern getsockname
extern GetCommandLineA
extern GetStdHandle
extern WriteFile
extern ExitProcess

%include "../common/parse.inc"
%include "../common/checksum.inc"

%define AF_INET 2
%define SOCK_RAW 3
%define SOCK_DGRAM 2
%define IPPROTO_IP 0
%define IPPROTO_TCP 6
%define IPPROTO_UDP 17
%define IP_HDRINCL 2
%define SOL_SOCKET 0xFFFF
%define SO_RCVTIMEO 0x1006
%define INVALID_SOCKET -1
%define SOCKET_ERROR -1
%define STD_OUTPUT_HANDLE -11

SECTION .data
usage_msg db "Usage: netx-asm.exe <target_ip> [-p port|start-end|-]", 13, 10
usage_len equ $-usage_msg
closed_msg db " CLOSED", 13, 10
closed_len equ $-closed_msg
filtered_msg db " FILTERED", 13, 10
filtered_len equ $-filtered_msg
open_ttl_msg db " OPEN TTL="
open_ttl_len equ $-open_ttl_msg
open_win_msg db " WIN="
open_win_len equ $-open_win_msg
newline_msg db 13, 10
newline_len equ $-newline_msg
error_msg db "ERROR", 13, 10
error_len equ $-error_msg

hdrincl dd 1
timeout_ms dd 1000

src_port dw 40000
start_port dw 1
end_port dw 1000
src_port_be dw 0
dst_port_be dw 0

SECTION .bss
wsa_data resb 512
packet_buf resb 60
recv_buf resb 4096
out_buf resb 16
cmd_buf resb 1024
sockaddr_dst resb 16
sockaddr_tmp resb 16
sockaddr_local resb 16
addrlen resd 1
sock_fd resq 1
stdout_handle resq 1
bytes_written resd 1
target_ip resd 1
source_ip resd 1
last_ttl resb 1
last_win resw 1

SECTION .text
_start:
    mov qword [sock_fd], INVALID_SOCKET
    sub rsp, 40
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    add rsp, 40
    mov [stdout_handle], rax

    sub rsp, 40
    mov ecx, 0x0202
    lea rdx, [wsa_data]
    call WSAStartup
    add rsp, 40
    test eax, eax
    jne .error

    sub rsp, 40
    call GetCommandLineA
    add rsp, 40
    mov rsi, rax
    lea rdi, [cmd_buf]

.copy_cmd:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    test al, al
    jnz .copy_cmd

    lea rdi, [cmd_buf]
    call next_token
    mov rdi, rdx
    call next_token
    test rax, rax
    jz .usage
    mov rdi, rax
    call parse_ip
    test eax, eax
    jz .usage
    mov [target_ip], eax

    mov rdi, rdx
    call next_token
    test rax, rax
    jz .ports_ready
    mov rsi, rax
    cmp byte [rsi], '-'
    jne .ports_ready
    cmp byte [rsi+1], 'p'
    jne .ports_ready
    cmp byte [rsi+2], 0
    jne .ports_ready

    mov rdi, rdx
    call next_token
    test rax, rax
    jz .usage
    mov rdi, rax
    cmp byte [rdi], '-'
    jne .parse_range
    cmp byte [rdi+1], 0
    jne .parse_range
    mov word [start_port], 1
    mov word [end_port], 65535
    jmp .ports_ready

.parse_range:
    call parse_port_range
    test ax, ax
    jz .usage
    mov [start_port], ax
    mov [end_port], dx

.ports_ready:
    mov ax, [src_port]
    xchg al, ah
    mov [src_port_be], ax

    call get_local_ip
    test eax, eax
    jnz .error

    sub rsp, 40
    mov ecx, AF_INET
    mov edx, SOCK_RAW
    mov r8d, IPPROTO_TCP
    call socket
    add rsp, 40
    cmp rax, INVALID_SOCKET
    je .error
    mov [sock_fd], rax

    sub rsp, 40
    mov rcx, [sock_fd]
    mov edx, IPPROTO_IP
    mov r8d, IP_HDRINCL
    lea r9, [hdrincl]
    mov dword [rsp+32], 4
    call setsockopt
    add rsp, 40
    test eax, eax
    jne .error

    sub rsp, 40
    mov rcx, [sock_fd]
    mov edx, SOL_SOCKET
    mov r8d, SO_RCVTIMEO
    lea r9, [timeout_ms]
    mov dword [rsp+32], 4
    call setsockopt
    add rsp, 40

    lea rdi, [packet_buf]
    xor rax, rax
    mov rcx, 60/8
    rep stosq

    mov byte [packet_buf], 0x45
    mov byte [packet_buf+1], 0
    mov word [packet_buf+2], 0x2800
    mov word [packet_buf+4], 0x3412
    mov word [packet_buf+6], 0x0040
    mov byte [packet_buf+8], 64
    mov byte [packet_buf+9], 6
    mov word [packet_buf+10], 0
    mov eax, [source_ip]
    mov [packet_buf+12], eax
    mov eax, [target_ip]
    mov [packet_buf+16], eax

    lea rdi, [packet_buf]
    call ip_checksum
    mov [packet_buf+10], ax

    mov ax, [src_port_be]
    mov [packet_buf+20], ax
    mov dword [packet_buf+24], 0x78563412
    mov dword [packet_buf+28], 0
    mov byte [packet_buf+32], 0x50
    mov byte [packet_buf+33], 0x02
    mov word [packet_buf+34], 0xFFFF
    mov word [packet_buf+36], 0
    mov word [packet_buf+38], 0

    mov word [sockaddr_dst], AF_INET
    mov eax, [target_ip]
    mov [sockaddr_dst+4], eax

    movzx ecx, word [start_port]
    movzx r15d, word [end_port]

.scan_loop:
    cmp ecx, r15d
    ja .exit

    mov ax, cx
    xchg al, ah
    mov [dst_port_be], ax
    mov ax, [dst_port_be]
    mov [packet_buf+22], ax
    mov [sockaddr_dst+2], ax

    mov word [packet_buf+36], 0
    lea rdi, [packet_buf]
    call tcp_checksum
    mov [packet_buf+36], ax

    sub rsp, 56
    mov rcx, [sock_fd]
    lea rdx, [packet_buf]
    mov r8d, 40
    xor r9d, r9d
    lea rax, [sockaddr_dst]
    mov [rsp+32], rax
    mov qword [rsp+40], 16
    call sendto
    add rsp, 56
    cmp eax, SOCKET_ERROR
    je .error

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
    je .report_filtered

    lea rsi, [recv_buf]
    mov al, [rsi+9]
    cmp al, 6
    jne .report_filtered
    mov eax, [rsi+12]
    cmp eax, [target_ip]
    jne .report_filtered
    mov al, [rsi]
    and al, 0x0F
    shl al, 2
    movzx edi, al
    lea rdx, [rsi+rdi]
    mov ax, [rdx]
    cmp ax, [dst_port_be]
    jne .report_filtered
    mov ax, [rdx+2]
    cmp ax, [src_port_be]
    jne .report_filtered
    mov al, [rsi+8]
    mov [last_ttl], al
    mov ax, [rdx+14]
    xchg al, ah
    mov [last_win], ax
    mov al, [rdx+13]
    mov bl, al
    and bl, 0x12
    cmp bl, 0x12
    je .report_open
    test al, 0x04
    jnz .report_closed
    jmp .report_filtered

.report_open:
    mov ax, cx
    call write_open_intel
    jmp .next_port

.report_closed:
    mov ax, cx
    mov r9, closed_msg
    mov r10d, closed_len
    call write_result
    jmp .next_port

.report_filtered:
    mov ax, cx
    mov r9, filtered_msg
    mov r10d, filtered_len
    call write_result
    jmp .next_port

.next_port:
    inc ecx
    jmp .scan_loop

.usage:
    lea rsi, [usage_msg]
    mov edx, usage_len
    call write_stdout
    jmp .exit

.error:
    lea rsi, [error_msg]
    mov edx, error_len
    call write_stdout

.exit:
    mov rax, [sock_fd]
    cmp rax, INVALID_SOCKET
    je .cleanup
    sub rsp, 40
    mov rcx, rax
    call closesocket
    add rsp, 40

.cleanup:
    sub rsp, 40
    call WSACleanup
    add rsp, 40

    sub rsp, 40
    xor ecx, ecx
    call ExitProcess

; rsi=buf, edx=len
write_stdout:
    sub rsp, 40
    mov rcx, [stdout_handle]
    mov r8d, edx
    mov rdx, rsi
    lea r9, [bytes_written]
    mov qword [rsp+32], 0
    call WriteFile
    add rsp, 40
    ret

; inputs: ax=value
write_u16:
    movzx eax, ax
    lea rsi, [out_buf+6]
    xor r8d, r8d

.u16_digits:
    xor edx, edx
    mov r10d, 10
    div r10d
    add dl, '0'
    dec rsi
    mov [rsi], dl
    inc r8d
    test eax, eax
    jnz .u16_digits

    mov edx, r8d
    call write_stdout
    ret

; inputs: ax=port, r9=msg ptr, r10d=msg len
write_result:
    call write_u16
    mov rsi, r9
    mov edx, r10d
    call write_stdout
    ret

; inputs: ax=port
write_open_intel:
    call write_u16
    lea rsi, [open_ttl_msg]
    mov edx, open_ttl_len
    call write_stdout
    movzx ax, byte [last_ttl]
    call write_u16
    lea rsi, [open_win_msg]
    mov edx, open_win_len
    call write_stdout
    mov ax, [last_win]
    call write_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call write_stdout
    ret

; rdi -> command line string
; returns rax=token start or 0, rdx=next position
next_token:
.skip:
    mov al, [rdi]
    cmp al, 0
    je .none
    cmp al, ' '
    jne .start
    inc rdi
    jmp .skip

.start:
    cmp al, '"'
    jne .noquote
    inc rdi
    mov rax, rdi

.scan_quote:
    mov al, [rdi]
    cmp al, 0
    je .done_quote
    cmp al, '"'
    je .term_quote
    inc rdi
    jmp .scan_quote

.term_quote:
    mov byte [rdi], 0
    inc rdi
    mov rdx, rdi
    ret

.done_quote:
    mov rdx, rdi
    ret

.noquote:
    mov rax, rdi

.scan:
    mov al, [rdi]
    cmp al, 0
    je .done
    cmp al, ' '
    je .term
    inc rdi
    jmp .scan

.term:
    mov byte [rdi], 0
    inc rdi

.done:
    mov rdx, rdi
    ret

.none:
    xor eax, eax
    mov rdx, rdi
    ret

; returns eax=0 on success
get_local_ip:
    sub rsp, 40
    mov ecx, AF_INET
    mov edx, SOCK_DGRAM
    mov r8d, IPPROTO_UDP
    call socket
    add rsp, 40
    cmp rax, INVALID_SOCKET
    je .get_ip_fail
    mov rbx, rax

    mov word [sockaddr_tmp], AF_INET
    mov word [sockaddr_tmp+2], 0x3500
    mov eax, [target_ip]
    mov [sockaddr_tmp+4], eax

    sub rsp, 40
    mov rcx, rbx
    lea rdx, [sockaddr_tmp]
    mov r8d, 16
    call connect
    add rsp, 40
    test eax, eax
    jne .get_ip_cleanup_fail

    mov dword [addrlen], 16
    sub rsp, 40
    mov rcx, rbx
    lea rdx, [sockaddr_local]
    lea r8, [addrlen]
    call getsockname
    add rsp, 40
    test eax, eax
    jne .get_ip_cleanup_fail

    mov eax, [sockaddr_local+4]
    mov [source_ip], eax

    sub rsp, 40
    mov rcx, rbx
    call closesocket
    add rsp, 40
    xor eax, eax
    ret

.get_ip_cleanup_fail:
    sub rsp, 40
    mov rcx, rbx
    call closesocket
    add rsp, 40

.get_ip_fail:
    mov eax, 1
    ret
