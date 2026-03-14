BITS 64
GLOBAL _start

%include "../common/constants.inc"
%include "../common/parse.inc"
%include "../common/checksum.inc"
%include "../common/packet.inc"
%include "../common/engine.inc"

%define OUTPUT_BUF_SIZE 131072
%define OUTPUT_FLUSH_THRESHOLD 98304

SECTION .data
usage_msg db "Usage: netx-asm <target_ip> [-p port|start-end|-] [--rate N]", 10
usage_len equ $-usage_msg
banner_msg db "   _  __    __           ___   ______  ___", 10
           db "  / |/ /__ / /___ ______/ _ | / __/  |/  /", 10
           db " /    / -_) __/\\ \\ /___/ __ |_\\ \\/ /|_/ / ", 10
           db "/_/|_/\\__/\\__//_\\_\\   /_/ |_/___/_/  /_/  ", 10
           db 10
banner_len equ $-banner_msg
closed_msg db " CLOSED", 10
closed_len equ $-closed_msg
filtered_msg db " FILTERED", 10
filtered_len equ $-filtered_msg
open_ttl_msg db " OPEN TTL="
open_ttl_len equ $-open_ttl_msg
open_win_msg db " WIN="
open_win_len equ $-open_win_msg
newline_msg db 10
newline_len equ $-newline_msg
open_count_msg db "OPEN COUNT: "
open_count_len equ $-open_count_msg
open_ports_msg db "OPEN PORTS: "
open_ports_len equ $-open_ports_msg
none_msg db "none"
none_len equ $-none_msg
space_msg db " "
space_len equ $-space_msg
error_msg db "ERROR", 10
error_len equ $-error_msg

hdrincl dd 1
timeout_timeval dq 1, 0

src_port dw 40000
dst_port dw 0
start_port dw 1
end_port dw 1000
src_port_be dw 0
dst_port_be dw 0

SECTION .bss
packet_buf resb 60
recv_buf resb 4096
out_buf resb 16
output_buf resb OUTPUT_BUF_SIZE
output_pos resq 1
sockaddr_dst resb 16
sockaddr_tmp resb 16
sockaddr_local resb 16
addrlen resd 1
raw_fd resq 1
epoll_fd resq 1
target_ip resd 1
source_ip resd 1
last_ttl resb 1
last_win resw 1
epoll_event resb 16
epoll_out resb 16
result_map resb 8192
open_count resd 1
engine_id resb 1
rate_value resd 1
rate_cycles resq 1
rate_enabled resb 1
last_send_tsc resq 1
tsc_hz resq 1
ts_start resq 2
ts_end resq 2
tsc_start resq 1

SECTION .text
_start:
    xor r12d, r12d

    mov rbx, rsp
    mov rax, [rbx]
    cmp rax, 2
    jb .usage

    mov rdi, [rbx+16]
    call parse_ip
    test eax, eax
    jz .usage
    mov [target_ip], eax

    mov r13, [rbx]
    mov rcx, 2

.arg_loop:
    cmp rcx, r13
    jae .ports_ready
    mov rdi, [rbx+rcx*8]
    cmp byte [rdi], '-'
    jne .arg_next
    cmp byte [rdi+1], 'p'
    jne .check_rate
    cmp byte [rdi+2], 0
    jne .check_rate
    inc rcx
    cmp rcx, r13
    jae .usage
    mov rdi, [rbx+rcx*8]
    cmp byte [rdi], '-'
    jne .parse_range
    cmp byte [rdi+1], 0
    jne .parse_range
    mov word [start_port], 1
    mov word [end_port], 65535
    jmp .arg_next

.parse_range:
    call parse_port_range
    test ax, ax
    jz .usage
    mov [start_port], ax
    mov [end_port], dx
    jmp .arg_next

.check_rate:
    cmp byte [rdi], '-'
    jne .arg_next
    cmp byte [rdi+1], '-'
    jne .arg_next
    cmp byte [rdi+2], 'r'
    jne .arg_next
    cmp byte [rdi+3], 'a'
    jne .arg_next
    cmp byte [rdi+4], 't'
    jne .arg_next
    cmp byte [rdi+5], 'e'
    jne .arg_next
    cmp byte [rdi+6], 0
    jne .arg_next
    inc rcx
    cmp rcx, r13
    jae .usage
    mov rdi, [rbx+rcx*8]
    call parse_u32
    test eax, eax
    jz .usage
    mov [rate_value], eax
    jmp .arg_next

.arg_next:
    inc rcx
    jmp .arg_loop

.ports_ready:
    mov ax, [src_port]
    xchg al, ah
    mov [src_port_be], ax
    mov byte [engine_id], ENGINE_SYN
    lea rsi, [banner_msg]
    mov edx, banner_len
    call buf_write

    call get_local_ip
    test eax, eax
    jnz .error

    call init_rate

    mov rax, SYS_SOCKET
    mov rdi, AF_INET
    mov rsi, SOCK_RAW
    mov rdx, IPPROTO_TCP
    syscall
    test rax, rax
    js .error
    mov [raw_fd], rax

    mov rax, SYS_SETSOCKOPT
    mov rdi, [raw_fd]
    mov rsi, IPPROTO_IP
    mov rdx, IP_HDRINCL
    lea r10, [hdrincl]
    mov r8, 4
    syscall
    test rax, rax
    js .error

    mov rax, SYS_SETSOCKOPT
    mov rdi, [raw_fd]
    mov rsi, SOL_SOCKET
    mov rdx, SO_RCVTIMEO
    lea r10, [timeout_timeval]
    mov r8, 16
    syscall
    test rax, rax
    js .error

    mov rax, SYS_EPOLL_CREATE1
    xor rdi, rdi
    syscall
    test rax, rax
    js .error
    mov [epoll_fd], rax

    mov dword [epoll_event], EPOLLIN | EPOLLET
    mov rax, [raw_fd]
    mov [epoll_event+8], rax
    mov rax, SYS_EPOLL_CTL
    mov rdi, [epoll_fd]
    mov rsi, EPOLL_CTL_ADD
    mov rdx, [raw_fd]
    lea r10, [epoll_event]
    syscall
    test rax, rax
    js .error

    call init_packet_template

    mov word [sockaddr_dst], AF_INET
    mov eax, [target_ip]
    mov [sockaddr_dst+4], eax

    movzx ecx, word [start_port]
    movzx r15d, word [end_port]

.scan_loop:
    cmp ecx, r15d
    ja .scan_done

    mov ax, cx
    mov [dst_port], ax
    mov ax, cx
    xchg al, ah
    mov [dst_port_be], ax
    mov ax, [dst_port_be]
    call build_packet

    call rate_gate
    mov rax, SYS_SENDTO
    mov rdi, [raw_fd]
    lea rsi, [packet_buf]
    mov rdx, 40
    xor r10, r10
    lea r8, [sockaddr_dst]
    mov r9, 16
    syscall
    test rax, rax
    js .error

    mov r11d, 8

.epoll_loop:
    mov rax, SYS_EPOLL_WAIT
    mov rdi, [epoll_fd]
    lea rsi, [epoll_out]
    mov rdx, 1
    xor r10, r10
    syscall
    test rax, rax
    js .report_filtered
    cmp rax, 0
    je .epoll_noevent

    mov rax, SYS_RECVFROM
    mov rdi, [raw_fd]
    lea rsi, [recv_buf]
    mov rdx, 4096
    xor r10, r10
    xor r8, r8
    xor r9, r9
    syscall
    test rax, rax
    js .report_filtered

    lea rsi, [recv_buf]
    mov al, [rsi+9]
    cmp al, 6
    jne .recv_mismatch
    mov eax, [rsi+12]
    cmp eax, [target_ip]
    jne .recv_mismatch
    mov al, [rsi]
    and al, 0x0F
    shl al, 2
    movzx edi, al
    lea rdx, [rsi+rdi]
    mov ax, [rdx]
    cmp ax, [dst_port_be]
    jne .recv_mismatch
    mov ax, [rdx+2]
    cmp ax, [src_port_be]
    jne .recv_mismatch
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

.recv_mismatch:
    dec r11d
    jnz .epoll_loop
    jmp .report_filtered

.epoll_noevent:
    dec r11d
    jnz .epoll_loop
    jmp .report_filtered

.report_open:
    call record_open
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

.scan_done:
    call write_summary
    jmp .exit

.usage:
    mov rax, SYS_WRITE
    mov rdi, 2
    lea rsi, [usage_msg]
    mov rdx, usage_len
    syscall
    mov r12d, 1
    jmp .exit

.error:
    call flush_output
    mov rax, SYS_WRITE
    mov rdi, 2
    lea rsi, [error_msg]
    mov rdx, error_len
    syscall
    mov r12d, 1

.exit:
    call flush_output
    mov rax, [epoll_fd]
    test rax, rax
    jz .exit_close_raw
    mov rdi, rax
    mov rax, SYS_CLOSE
    syscall

.exit_close_raw:
    mov rax, [raw_fd]
    test rax, rax
    jz .exit_now
    mov rdi, rax
    mov rax, SYS_CLOSE
    syscall

.exit_now:
    mov rax, SYS_EXIT
    mov rdi, r12
    syscall

; rsi=src, edx=len
buf_write:
    mov r8, rsi
    mov r9, rdx
    mov rax, [output_pos]
    mov rcx, rax
    add rcx, r9
    cmp rcx, OUTPUT_BUF_SIZE
    ja .buf_flush
    cmp rcx, OUTPUT_FLUSH_THRESHOLD
    jae .buf_flush

.buf_write:
    lea rdi, [output_buf+rax]
    mov rsi, r8
    mov rdx, r9
    mov rcx, rdx
    rep movsb
    add rax, r9
    mov [output_pos], rax
    ret

.buf_flush:
    call flush_output
    mov rax, [output_pos]
    jmp .buf_write

flush_output:
    mov rax, [output_pos]
    test rax, rax
    jz .flush_done
    mov rdi, 1
    lea rsi, [output_buf]
    mov rdx, rax
    mov rax, SYS_WRITE
    syscall
    mov qword [output_pos], 0

.flush_done:
    ret

; inputs: ax=value
append_u16:
    movzx eax, ax
    lea rsi, [out_buf+6]
    xor rcx, rcx

.u16_digits:
    mov r8d, eax
    mov r11d, 0xCCCCCCCD
    mul r11d
    mov eax, edx
    shr eax, 3
    lea edx, [eax*4 + eax]
    add edx, edx
    sub r8d, edx
    add r8b, '0'
    dec rsi
    mov [rsi], r8b
    inc rcx
    test eax, eax
    jnz .u16_digits

    mov edx, ecx
    call buf_write
    ret

; inputs: ax=port, r9=msg ptr, r10d=msg len
write_result:
    call append_u16
    mov rsi, r9
    mov edx, r10d
    call buf_write
    ret

; inputs: ax=port, uses last_ttl/last_win
write_open_intel:
    call append_u16
    lea rsi, [open_ttl_msg]
    mov edx, open_ttl_len
    call buf_write
    movzx ax, byte [last_ttl]
    call append_u16
    lea rsi, [open_win_msg]
    mov edx, open_win_len
    call buf_write
    mov ax, [last_win]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    ret

record_open:
    mov eax, ecx
    dec eax
    mov edx, eax
    shr eax, 3
    and edx, 7
    mov r8b, 1
    shl r8b, dl
    or byte [result_map+rax], r8b
    inc dword [open_count]
    ret

write_summary:
    lea rsi, [open_count_msg]
    mov edx, open_count_len
    call buf_write
    mov ax, [open_count]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write

    mov ax, [open_count]
    test ax, ax
    jz .summary_none

    lea rsi, [open_ports_msg]
    mov edx, open_ports_len
    call buf_write
    movzx ecx, word [start_port]
    movzx r15d, word [end_port]

.summary_loop:
    cmp ecx, r15d
    ja .summary_done
    mov eax, ecx
    dec eax
    mov edx, eax
    shr eax, 3
    and edx, 7
    mov r8b, 1
    shl r8b, dl
    test byte [result_map+rax], r8b
    jz .summary_next
    mov ax, cx
    call append_u16
    lea rsi, [space_msg]
    mov edx, space_len
    call buf_write

.summary_next:
    inc ecx
    jmp .summary_loop

.summary_done:
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    ret

.summary_none:
    lea rsi, [open_ports_msg]
    mov edx, open_ports_len
    call buf_write
    lea rsi, [none_msg]
    mov edx, none_len
    call buf_write
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    ret

rate_gate:
    cmp byte [rate_enabled], 0
    je .rate_done
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r8, [last_send_tsc]
    test r8, r8
    jz .rate_store

.rate_wait:
    mov r9, rax
    sub r9, r8
    cmp r9, [rate_cycles]
    jae .rate_store
    rdtsc
    shl rdx, 32
    or rax, rdx
    jmp .rate_wait

.rate_store:
    mov [last_send_tsc], rax

.rate_done:
    ret

init_rate:
    mov eax, [rate_value]
    test eax, eax
    jz .init_rate_done
    call calibrate_tsc
    mov ecx, [rate_value]
    mov rax, [tsc_hz]
    xor rdx, rdx
    div rcx
    mov [rate_cycles], rax
    mov byte [rate_enabled], 1

.init_rate_done:
    ret

calibrate_tsc:
    mov rax, SYS_CLOCK_GETTIME
    mov rdi, CLOCK_MONOTONIC
    lea rsi, [ts_start]
    syscall
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [tsc_start], rax

.calib_loop:
    mov rax, SYS_CLOCK_GETTIME
    mov rdi, CLOCK_MONOTONIC
    lea rsi, [ts_end]
    syscall
    mov rax, [ts_end]
    mov r10, [ts_start]
    sub rax, r10
    mov rcx, [ts_end+8]
    sub rcx, [ts_start+8]
    jns .calib_delta_ok
    dec rax
    add rcx, 1000000000

.calib_delta_ok:
    mov r11, 1000000000
    imul rax, r11
    add rax, rcx
    cmp rax, 50000000
    jb .calib_loop
    mov r8, rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r9, rax
    mov rax, r9
    sub rax, [tsc_start]
    mov rcx, 1000000000
    mul rcx
    mov rcx, r8
    div rcx
    mov [tsc_hz], rax
    ret

; returns eax = 0 on success, 1 on failure
get_local_ip:
    mov rax, SYS_SOCKET
    mov rdi, AF_INET
    mov rsi, SOCK_DGRAM
    mov rdx, IPPROTO_UDP
    syscall
    test rax, rax
    js .get_ip_fail
    mov rbx, rax

    mov word [sockaddr_tmp], AF_INET
    mov word [sockaddr_tmp+2], 0x3500
    mov eax, [target_ip]
    mov [sockaddr_tmp+4], eax

    mov rax, SYS_CONNECT
    mov rdi, rbx
    lea rsi, [sockaddr_tmp]
    mov rdx, 16
    syscall
    test rax, rax
    js .get_ip_cleanup_fail

    mov dword [addrlen], 16
    mov rax, SYS_GETSOCKNAME
    mov rdi, rbx
    lea rsi, [sockaddr_local]
    lea rdx, [addrlen]
    syscall
    test rax, rax
    js .get_ip_cleanup_fail

    mov eax, [sockaddr_local+4]
    mov [source_ip], eax

    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
    xor eax, eax
    ret

.get_ip_cleanup_fail:
    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall

.get_ip_fail:
    mov eax, 1
    ret
