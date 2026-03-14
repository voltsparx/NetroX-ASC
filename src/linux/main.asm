; ===========================================================================
; Netx-ASM  |  Linux x86_64  |  Part 1 of 5: Headers, .data, .bss
; ===========================================================================

BITS 64
GLOBAL _start

%include "../common/constants.inc"
%include "../common/parse.inc"
%include "../common/checksum.inc"
%include "../common/packet.inc"
%include "../common/engine.inc"
%include "../common/intelligence.inc"

%define OUTPUT_BUF_SIZE         131072
%define OUTPUT_FLUSH_THRESHOLD   98304

; ---------------------------------------------------------------------------
; .data  -  all static strings and tunables
; ---------------------------------------------------------------------------
SECTION .data

usage_msg   db "Usage: netx-asm <target_ip> [-p port|start-end|-]", 10
            db "       [--rate N] [--iface IFACE] [--scan MODE]", 10
            db "       [--bench] [--os] [--stabilize] [--about]", 10
            db "       [--prompt-mode]", 10
            db "Scan modes: syn ack fin null xmas window maimon", 10
usage_len   equ $-usage_msg

banner_msg  db "   _  __    __           ___   ______  ___", 10
            db "  / |/ /__ / /___ ______/ _ | / __/  |/  /", 10
            db " /    / -_) __/\\ \\/___/ __ |_\\ \\/ /|_/ / ", 10
            db "/_/|_/\\__/\\__//_\\_\\   /_/ |_/___/_/  /_/  ", 10, 10
banner_len  equ $-banner_msg

about_msg   db "author : voltsparx", 10
            db "email  : voltsparx@gmail.com", 10
            db "repo   : https://github.com/voltsparx/Netx-ASM", 10
            db "github : github.com/voltsparx", 10
about_len   equ $-about_msg

; Prompt strings
prompt_intro    db "Netx-ASM interactive prompt", 10
prompt_intro_len equ $-prompt_intro
prompt_target   db "Target IP: "
prompt_target_len equ $-prompt_target
prompt_ports    db "Ports [1-1000 | - for all]: "
prompt_ports_len equ $-prompt_ports
prompt_scan     db "Scan mode [syn|ack|fin|null|xmas|window|maimon] (default syn): "
prompt_scan_len equ $-prompt_scan
prompt_rate     db "Rate pps (leave blank for unlimited): "
prompt_rate_len equ $-prompt_rate
prompt_iface    db "Interface (optional, press Enter to skip): "
prompt_iface_len equ $-prompt_iface
prompt_stab     db "Stabilize? (y/n) [n]: "
prompt_stab_len equ $-prompt_stab
prompt_invalid  db "Invalid input", 10
prompt_invalid_len equ $-prompt_invalid

; Result output strings
closed_msg      db " CLOSED", 10
closed_len      equ $-closed_msg
filtered_msg    db " FILTERED", 10
filtered_len    equ $-filtered_msg
open_ttl_msg    db " OPEN TTL="
open_ttl_len    equ $-open_ttl_msg
open_win_msg    db " WIN="
open_win_len    equ $-open_win_msg
newline_msg     db 10
newline_len     equ $-newline_msg
space_msg       db " "
space_len       equ $-space_msg
error_msg       db "ERROR", 10
error_len       equ $-error_msg

; Summary output strings
open_count_msg  db "OPEN COUNT: "
open_count_len  equ $-open_count_msg
open_ports_msg  db "OPEN PORTS: "
open_ports_len  equ $-open_ports_msg
none_msg        db "none"
none_len        equ $-none_msg

; OS fingerprint output
os_prefix_msg   db " OS="
os_prefix_len   equ $-os_prefix_msg

; Benchmark output
bench_hdr_msg   db 10, "--- NETX-ASM BENCHMARK ---", 10
bench_hdr_len   equ $-bench_hdr_msg
bench_ports_msg db "Ports scanned : "
bench_ports_len equ $-bench_ports_msg
bench_open_msg  db "Open found    : "
bench_open_len  equ $-bench_open_msg
bench_time_msg  db "Elapsed (ms)  : "
bench_time_len  equ $-bench_time_msg
bench_end_msg   db "--------------------------", 10
bench_end_len   equ $-bench_end_msg

; OS fingerprint string table (index 0-7)
os_str_0    db "Linux-5.x/6.x", 0
os_str_1    db "Linux-3.x/4.x", 0
os_str_2    db "Windows-10/11", 0
os_str_3    db "Windows-7/8",   0
os_str_4    db "macOS/BSD",      0
os_str_5    db "Network-Device", 0
os_str_6    db "Unknown",        0
os_str_ptrs dq os_str_0, os_str_1, os_str_2, os_str_3
            dq os_str_4, os_str_5, os_str_6

; Socket / packet tunables
hdrincl         dd 1
timeout_timeval dq 1, 0     ; 1 second receive timeout

src_port        dw 40000
dst_port        dw 0
start_port      dw 1
end_port        dw 1000
src_port_be     dw 0
dst_port_be     dw 0

; ---------------------------------------------------------------------------
; .bss  -  zero-initialised runtime buffers and variables
; ---------------------------------------------------------------------------
SECTION .bss

packet_buf      resb 60
recv_buf        resb 4096
out_buf         resb 16
output_buf      resb OUTPUT_BUF_SIZE
output_pos      resq 1

sockaddr_dst    resb 16
sockaddr_tmp    resb 16
sockaddr_local  resb 16
sockaddr_ll     resb 32
addrlen         resd 1

raw_fd          resq 1
send_fd         resq 1
epoll_fd        resq 1
epoll_event     resb 16
epoll_out       resb 16

target_ip       resd 1
source_ip       resd 1
last_ttl        resb 1
last_win        resw 1

result_map      resb 8192
open_count      resd 1

engine_id       resb 1
scan_mode       resb 1

; Rate control
rate_value      resd 1
rate_cycles     resq 1
rate_min_cycles resq 1
rate_max_cycles resq 1
rate_enabled    resb 1
last_send_tsc   resq 1
tsc_hz          resq 1
ts_start        resq 2
ts_end          resq 2
tsc_start       resq 1

; Interface
iface_name      resb 16
iface_set       resb 1
ifreq_buf       resb 40
ifindex         resd 1

; Stabilizer
stab_enabled    resb 1
stab_sent       resd 1
stab_recv       resd 1
stab_timeout    resd 1

; Prompt / flags
input_buf       resb 256
prompt_mode     resb 1

; Feature flags
bench_enabled   resb 1
os_enabled      resb 1

; Benchmark counters
bench_start_tsc resq 1
bench_end_tsc   resq 1

; OS fingerprint last result
os_result_idx   resb 1
os_score        resb 1
intel_rtt_table     resd 65535
intel_ipid_ring     resw 6
intel_ipid_idx      resb 1
intel_lb_ttl        resb 5
intel_lb_win        resw 5
intel_lb_ts         resd 5
intel_lb_opthash    resd 5
intel_lb_idx        resb 1
intel_rtt_before    resq 1
intel_fp_ttl        resb 1
intel_fp_win        resw 1
intel_fp_mss        resw 1
intel_fp_wscale     resb 1
intel_fp_sack       resb 1
intel_fp_ts         resb 1
intel_fp_ts_val     resd 1
intel_fp_df         resb 1
intel_fp_ipid_class resb 1
intel_fp_opthash    resd 1
intel_fp_scores     resb 7
intel_fp_best_idx   resb 1
intel_fp_best_score resb 1
intel_svc_id        resb 1
intel_svc_name      resb 16
intel_banner        resb 64
intel_banner_len    resw 1
intel_port_cur      resw 1

; ===========================================================================
; Netx-ASM  |  Linux x86_64  |  Part 2 of 5: _start, arg parsing, init
; ===========================================================================

SECTION .text
_start:
    xor r12d, r12d

    mov rbx, rsp
    mov rax, [rbx]
    cmp rax, 2
    jb .usage

    mov rdi, [rbx+16]
    call is_prompt_mode
    test eax, eax
    jnz .prompt_entry
    call is_about_mode
    test eax, eax
    jnz .about_entry

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

    ; -p <port|range|->
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
    ; --rate N
    cmp byte [rdi+1], '-'
    jne .check_iface
    lea rsi, [rdi+2]
    cmp dword [rsi], 'rate'
    jne .check_iface
    cmp byte [rsi+4], 0
    jne .check_iface
    inc rcx
    cmp rcx, r13
    jae .usage
    mov rdi, [rbx+rcx*8]
    call parse_u32
    test eax, eax
    jz .usage
    mov [rate_value], eax
    jmp .arg_next

.check_iface:
    ; --iface NAME
    cmp byte [rdi+1], '-'
    jne .check_scan
    lea rsi, [rdi+2]
    cmp dword [rsi], 'ifac'
    jne .check_scan
    cmp word [rsi+4], 'e'
    jne .check_scan
    cmp byte [rsi+5], 0
    jne .check_scan
    inc rcx
    cmp rcx, r13
    jae .usage
    mov rsi, [rbx+rcx*8]
    call copy_iface_name
    test eax, eax
    jnz .usage
    mov byte [iface_set], 1
    jmp .arg_next

.check_scan:
    ; --scan MODE
    cmp byte [rdi+1], '-'
    jne .check_bench
    lea rsi, [rdi+2]
    cmp dword [rsi], 'scan'
    jne .check_bench
    cmp byte [rsi+4], 0
    jne .check_bench
    inc rcx
    cmp rcx, r13
    jae .usage
    mov rdi, [rbx+rcx*8]
    call parse_scan_mode
    test al, al
    jz .usage
    mov [scan_mode], al
    jmp .arg_next

.check_bench:
    ; --bench
    cmp byte [rdi+1], '-'
    jne .check_os
    lea rsi, [rdi+2]
    cmp dword [rsi], 'benc'
    jne .check_os
    cmp word [rsi+4], 'h'
    jne .check_os
    cmp byte [rsi+5], 0
    jne .check_os
    mov byte [bench_enabled], 1
    jmp .arg_next

.check_os:
    ; --os
    cmp byte [rdi+1], '-'
    jne .check_stabilize
    lea rsi, [rdi+2]
    cmp word [rsi], 'os'
    jne .check_stabilize
    cmp byte [rsi+2], 0
    jne .check_stabilize
    mov byte [os_enabled], 1
    jmp .arg_next

.check_stabilize:
    ; --stabilize
    cmp byte [rdi+1], '-'
    jne .arg_next
    lea rsi, [rdi+2]
    cmp dword [rsi],   'stab'
    jne .arg_next
    cmp dword [rsi+4], 'iliz'
    jne .arg_next
    cmp word  [rsi+8], 'e'
    jne .arg_next
    cmp byte  [rsi+9], 0
    jne .arg_next
    mov byte [stab_enabled], 1

.arg_next:
    inc rcx
    jmp .arg_loop

; -------------------------------------------------------------------
; All args parsed - set up engine and start scan
; -------------------------------------------------------------------
.ports_ready:
    ; Convert src_port to big-endian
    mov ax, [src_port]
    xchg al, ah
    mov [src_port_be], ax

    ; Set scan mode default
    cmp byte [scan_mode], 0
    jne .scan_mode_set
    mov byte [scan_mode], SCAN_SYN
.scan_mode_set:

    ; Set engine based on scan_mode
    mov byte [engine_id], ENGINE_SYN

    ; Print banner unless in prompt mode
    cmp byte [prompt_mode], 0
    jne .skip_banner
    lea rsi, [banner_msg]
    mov edx, banner_len
    call buf_write
.skip_banner:

    ; Detect local source IP
    call get_local_ip
    test eax, eax
    jnz .error

    ; Init rate control and TSC calibration
    call init_rate
    call intel_init

    ; Capture bench start TSC
    cmp byte [bench_enabled], 0
    je .after_bench_start
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [bench_start_tsc], rax
.after_bench_start:

    ; Open raw TCP socket (used for all scan types as recv socket)
    mov rax, SYS_SOCKET
    mov rdi, AF_INET
    mov rsi, SOCK_RAW
    mov rdx, IPPROTO_TCP
    syscall
    test rax, rax
    js .error
    mov [raw_fd], rax

    ; IP_HDRINCL = 1
    mov rax, SYS_SETSOCKOPT
    mov rdi, [raw_fd]
    mov rsi, IPPROTO_IP
    mov rdx, IP_HDRINCL
    lea r10, [hdrincl]
    mov r8, 4
    syscall
    test rax, rax
    js .error

    ; SO_RCVTIMEO = 1s
    mov rax, SYS_SETSOCKOPT
    mov rdi, [raw_fd]
    mov rsi, SOL_SOCKET
    mov rdx, SO_RCVTIMEO
    lea r10, [timeout_timeval]
    mov r8, 16
    syscall

    ; epoll setup
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

    ; Build IP/TCP template
    call init_packet_template

    ; sockaddr_dst: AF_INET + target_ip
    mov word [sockaddr_dst], AF_INET
    mov eax, [target_ip]
    mov [sockaddr_dst+4], eax

    ; Setup send engine (raw or AF_PACKET if --iface)
    call setup_send_engine
    test eax, eax
    jnz .error

    ; Load scan range into registers
    movzx ecx, word [start_port]
    movzx r15d, word [end_port]
    ; fall through into scan loop (Part 3)

; ===========================================================================
; Netx-ASM  |  Linux x86_64  |  Part 3 of 5: Scan loop, classify, OS FP
; ===========================================================================

; -------------------------------------------------------------------
; Main scan loop
; ecx = current port, r15d = end port
; -------------------------------------------------------------------
.scan_loop:
    cmp ecx, r15d
    ja .scan_done

    mov ax, cx
    mov [dst_port], ax
    xchg al, ah
    mov [dst_port_be], ax

    call build_packet
    call intel_rtt_start
    call intelligence_gate

    ; sendto
    mov rax, SYS_SENDTO
    mov rdi, [send_fd]
    lea rsi, [packet_buf]
    ; TCP packet length
    mov edx, 40
    xor r10, r10
    cmp byte [iface_set], 0
    jne .send_ll
    lea r8, [sockaddr_dst]
    mov r9, 16
    jmp .send_do
.send_ll:
    lea r8, [sockaddr_ll]
    mov r9, 20
.send_do:
    syscall
    test rax, rax
    js .error

    cmp byte [stab_enabled], 0
    je .after_sent
    inc dword [stab_sent]
.after_sent:

    ; --- Receive phase: up to 8 epoll checks ---
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

    ; -------------------------------------------
    ; Decode received packet
    ; Check: IP protocol, source IP, ports
    ; -------------------------------------------
    lea rsi, [recv_buf]

    ; TCP response decode
    ; TCP response decode
    mov al, [rsi+9]
    cmp al, 6                           ; TCP
    jne .recv_mismatch
    mov eax, [rsi+12]
    cmp eax, [target_ip]
    jne .recv_mismatch
    ; Get IHL to find TCP header offset
    mov al, [rsi]
    and al, 0x0F
    shl al, 2
    movzx edi, al
    lea rdx, [rsi+rdi]                  ; rdx -> TCP header
    ; Check dest port == our src port
    mov ax, [rdx]
    cmp ax, [dst_port_be]
    jne .recv_mismatch
    mov ax, [rdx+2]
    cmp ax, [src_port_be]
    jne .recv_mismatch

    ; Capture TTL and window for intel output
    mov al, [rsi+8]
    mov [last_ttl], al
    mov ax, [rdx+14]
    xchg al, ah
    mov [last_win], ax

    call intel_rtt_record
    cmp byte [os_enabled], 0
    je .classify_flags
    call intel_analyze

.classify_flags:
    mov al, [rdx+13]                    ; TCP flags byte
    mov bl, al
    mov dl, [scan_mode]

    cmp dl, SCAN_SYN
    je .classify_syn
    cmp dl, SCAN_ACK
    je .classify_ack
    cmp dl, SCAN_WINDOW
    je .classify_ack
    ; FIN/NULL/XMAS/MAIMON: RST = CLOSED, no response = OPEN|FILTERED
    test bl, 0x04
    jnz .report_closed
    jmp .report_filtered

.classify_ack:
    test bl, 0x04                       ; RST = unfiltered
    jnz .report_open
    jmp .report_filtered

.classify_syn:
    and bl, 0x12
    cmp bl, 0x12                        ; SYN+ACK = OPEN
    je .report_open
    test al, 0x04                       ; RST = CLOSED
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

; -------------------------------------------------------------------
; Report helpers
; -------------------------------------------------------------------
.report_open:
    call record_open
    cmp byte [stab_enabled], 0
    je .open_no_stab
    inc dword [stab_recv]
.open_no_stab:
    mov ax, cx
    call write_open_intel
    cmp byte [os_enabled], 0
    je .skip_intel_print
    mov word [intel_port_cur], cx
    call intel_print_record
    .skip_intel_print:
    jmp .next_port

.report_closed:
    cmp byte [stab_enabled], 0
    je .closed_no_stab
    inc dword [stab_recv]
.closed_no_stab:
    mov ax, cx
    mov r9, closed_msg
    mov r10d, closed_len
    call write_result
    jmp .next_port

.report_filtered:
    cmp byte [stab_enabled], 0
    je .filtered_no_stab
    inc dword [stab_timeout]
.filtered_no_stab:
    mov ax, cx
    mov r9, filtered_msg
    mov r10d, filtered_len
    call write_result

.next_port:
    call stabilize_step
    inc ecx
    jmp .scan_loop

; -------------------------------------------------------------------
; Scan done
; -------------------------------------------------------------------
.scan_done:
    ; Capture bench end TSC
    cmp byte [bench_enabled], 0
    je .skip_bench_end
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [bench_end_tsc], rax
.skip_bench_end:
    call write_summary
    cmp byte [os_enabled], 0
    je .skip_rtt_map
    call intel_print_rtt_map
    .skip_rtt_map:
    cmp byte [bench_enabled], 0
    je .skip_bench_print
    call write_bench
.skip_bench_print:
    jmp .exit

; -------------------------------------------------------------------
; Entry points for special modes
; -------------------------------------------------------------------
.prompt_entry:
    mov byte [prompt_mode], 1
    call prompt_flow
    test eax, eax
    jnz .prompt_fail
    jmp .ports_ready

.prompt_fail:
    mov r12d, 1
    jmp .exit

.about_entry:
    call print_about
    xor r12d, r12d
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
    mov rax, [send_fd]
    test rax, rax
    jz .exit_close_raw_fd
    cmp rax, [raw_fd]
    je .exit_close_raw_fd
    mov rdi, rax
    mov rax, SYS_CLOSE
    syscall

.exit_close_raw_fd:
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

; -------------------------------------------------------------------
; fingerprint_os
; Passive OS detection from SYN-ACK already in recv_buf
; Sets os_result_idx based on TTL, window, and options scoring
; -------------------------------------------------------------------
fingerprint_os:
    push rbx
    push r12
    push r13

    ; Score table: [window_lo, window_hi, ttl_class, score, os_idx]
    ; ttl_class: 0=64 (Linux), 1=128 (Windows), 2=255 (Device)
    movzx r12d, byte [last_ttl]
    movzx r13d, word [last_win]

    ; Determine TTL class
    xor ebx, ebx                        ; ttl_class = 0 (Linux)
    cmp r12d, 70
    jbe .ttl_class_done
    mov ebx, 1                          ; Windows
    cmp r12d, 130
    jbe .ttl_class_done
    mov ebx, 2                          ; Device
.ttl_class_done:

    ; Score each OS candidate
    xor eax, eax                        ; best_score
    mov byte [os_result_idx], 6         ; default: Unknown

    ; Linux 5.x/6.x: win=64240, ttl_class=0
    xor ecx, ecx
    cmp r13d, 64240
    jne .fp_linux_old
    inc ecx
.fp_linux_old:
    cmp r13d, 29200
    jne .fp_linux_score
    inc ecx
.fp_linux_score:
    test ebx, ebx
    jnz .fp_linux_end
    inc ecx
    cmp ecx, eax
    jbe .fp_linux_end
    mov eax, ecx
    mov byte [os_result_idx], 0
.fp_linux_end:

    ; Linux 3.x/4.x: win=29200 or 65535, ttl_class=0
    xor ecx, ecx
    cmp r13d, 29200
    je .fp_l3_win
    cmp r13d, 65535
    jne .fp_l3_score
.fp_l3_win:
    inc ecx
.fp_l3_score:
    test ebx, ebx
    jnz .fp_l3_end
    inc ecx
    cmp ecx, eax
    jbe .fp_l3_end
    mov eax, ecx
    mov byte [os_result_idx], 1
.fp_l3_end:

    ; Windows 10/11: win=65535 or 64240, ttl_class=1
    xor ecx, ecx
    cmp r13d, 65535
    je .fp_w10_win
    cmp r13d, 64240
    jne .fp_w10_score
.fp_w10_win:
    inc ecx
.fp_w10_score:
    cmp ebx, 1
    jne .fp_w10_end
    inc ecx
    cmp ecx, eax
    jbe .fp_w10_end
    mov eax, ecx
    mov byte [os_result_idx], 2
.fp_w10_end:

    ; Windows 7/8: win=8192 or 16384, ttl_class=1
    xor ecx, ecx
    cmp r13d, 8192
    je .fp_w7_win
    cmp r13d, 16384
    jne .fp_w7_score
.fp_w7_win:
    inc ecx
.fp_w7_score:
    cmp ebx, 1
    jne .fp_w7_end
    inc ecx
    cmp ecx, eax
    jbe .fp_w7_end
    mov eax, ecx
    mov byte [os_result_idx], 3
.fp_w7_end:

    ; macOS/BSD: win=65228 or 65535, ttl_class=0
    xor ecx, ecx
    cmp r13d, 65228
    je .fp_mac_win
    cmp r13d, 65535
    jne .fp_mac_score
.fp_mac_win:
    inc ecx
.fp_mac_score:
    test ebx, ebx
    jnz .fp_mac_end
    inc ecx
    cmp ecx, eax
    jbe .fp_mac_end
    mov eax, ecx
    mov byte [os_result_idx], 4
.fp_mac_end:

    ; Network device: ttl_class=2
    xor ecx, ecx
    cmp ebx, 2
    jne .fp_dev_end
    add ecx, 2
    cmp ecx, eax
    jbe .fp_dev_end
    mov eax, ecx
    mov byte [os_result_idx], 5
.fp_dev_end:

    pop r13
    pop r12
    pop rbx
    ret

; ===========================================================================
; Netx-ASM  |  Linux x86_64  |  Part 4 of 5: Output, summary, bench, prompt
; ===========================================================================

; -------------------------------------------------------------------
; buf_write  rsi=src, edx=len
; Buffered write to stdout (flush when near-full)
; -------------------------------------------------------------------
buf_write:
    mov r8, rsi
    mov r9d, edx
    mov rax, [output_pos]
    mov rcx, rax
    add rcx, r9
    cmp rcx, OUTPUT_BUF_SIZE
    ja .buf_flush
    cmp rcx, OUTPUT_FLUSH_THRESHOLD
    jae .buf_flush
.buf_write_inner:
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
    jmp .buf_write_inner

flush_output:
    mov rax, [output_pos]
    test rax, rax
    jz .done
    mov rdi, 1
    lea rsi, [output_buf]
    mov rdx, rax
    mov rax, SYS_WRITE
    syscall
    mov qword [output_pos], 0
.done:
    ret

; -------------------------------------------------------------------
; append_u16  ax=value
; Converts 16-bit value to ASCII and calls buf_write
; Uses multiply-by-reciprocal trick (no idiv)
; -------------------------------------------------------------------
append_u16:
    movzx eax, ax
    lea rsi, [out_buf+6]
    xor rcx, rcx
.digits:
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
    jnz .digits
    mov edx, ecx
    call buf_write
    ret

; -------------------------------------------------------------------
; write_result  ax=port, r9=msg_ptr, r10d=msg_len
; -------------------------------------------------------------------
write_result:
    call append_u16
    mov rsi, r9
    mov edx, r10d
    call buf_write
    ret

; -------------------------------------------------------------------
; write_open_intel  ax=port
; Prints:  PORT OPEN TTL=N WIN=N[ OS=name]\n
; -------------------------------------------------------------------
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
    ; Optional OS fingerprint
    cmp byte [os_enabled], 0
    je .no_os
    lea rsi, [os_prefix_msg]
    mov edx, os_prefix_len
    call buf_write
    movzx eax, byte [os_result_idx]
    cmp eax, 6
    jbe .os_valid
    mov eax, 6
.os_valid:
    mov rsi, [os_str_ptrs + rax*8]
    ; measure length of null-terminated string
    xor edx, edx
.os_strlen:
    cmp byte [rsi+rdx], 0
    je .os_strlen_done
    inc edx
    jmp .os_strlen
.os_strlen_done:
    call buf_write
.no_os:
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    ret

; -------------------------------------------------------------------
; record_open  ecx=port
; Sets bit in result_map and increments open_count
; -------------------------------------------------------------------
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

; -------------------------------------------------------------------
; write_summary
; Prints open count and the list of open ports from result_map
; -------------------------------------------------------------------
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

; -------------------------------------------------------------------
; write_bench
; Prints benchmark stats after scan completes
; -------------------------------------------------------------------
write_bench:
    lea rsi, [bench_hdr_msg]
    mov edx, bench_hdr_len
    call buf_write

    ; Ports scanned
    lea rsi, [bench_ports_msg]
    mov edx, bench_ports_len
    call buf_write
    mov ax, [end_port]
    mov bx, [start_port]
    sub ax, bx
    inc ax
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write

    ; Open ports found
    lea rsi, [bench_open_msg]
    mov edx, bench_open_len
    call buf_write
    mov ax, [open_count]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write

    ; Elapsed time in ms = (end_tsc - start_tsc) * 1000 / tsc_hz
    lea rsi, [bench_time_msg]
    mov edx, bench_time_len
    call buf_write
    mov rax, [bench_end_tsc]
    sub rax, [bench_start_tsc]
    mov rcx, 1000
    mul rcx
    mov rcx, [tsc_hz]
    test rcx, rcx
    jz .bench_no_time
    div rcx
    ; ax = elapsed ms (low 16 bits sufficient for most scans)
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
.bench_no_time:
    lea rsi, [bench_end_msg]
    mov edx, bench_end_len
    call buf_write
    ret

; -------------------------------------------------------------------
; print_about
; -------------------------------------------------------------------
print_about:
    lea rsi, [banner_msg]
    mov edx, banner_len
    call buf_write
    lea rsi, [about_msg]
    mov edx, about_len
    call buf_write
    call flush_output
    ret

; -------------------------------------------------------------------
; is_prompt_mode  rdi=arg -> eax=1 if "--prompt-mode"
; -------------------------------------------------------------------
is_prompt_mode:
    cmp dword [rdi],    '--pr'
    jne .no
    cmp dword [rdi+4],  'ompt'
    jne .no
    cmp dword [rdi+8],  '-mod'
    jne .no
    cmp byte  [rdi+12], 'e'
    jne .no
    cmp byte  [rdi+13], 0
    jne .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; -------------------------------------------------------------------
; is_about_mode  rdi=arg -> eax=1 if "--about"
; -------------------------------------------------------------------
is_about_mode:
    cmp dword [rdi],   '--ab'
    jne .no
    cmp dword [rdi+4], 'out'
    jne .no
    cmp byte  [rdi+6], 0
    jne .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; -------------------------------------------------------------------
; prompt_flow
; Interactive configuration wizard
; Returns eax=0 on success, 1 on failure
; -------------------------------------------------------------------
prompt_flow:
    call print_about
    lea rsi, [prompt_intro]
    mov edx, prompt_intro_len
    call buf_write
    call flush_output

    ; Target IP
    lea rsi, [prompt_target]
    mov edx, prompt_target_len
    lea rdi, [input_buf]
    mov ecx, 256
    call prompt_read_line
    test eax, eax
    jz .fail
    lea rdi, [input_buf]
    call parse_ip
    test eax, eax
    jz .fail
    mov [target_ip], eax

    ; Port range
    lea rsi, [prompt_ports]
    mov edx, prompt_ports_len
    lea rdi, [input_buf]
    mov ecx, 256
    call prompt_read_line
    test eax, eax
    jz .ports_ok
    cmp byte [input_buf], '-'
    jne .ports_parse
    cmp byte [input_buf+1], 0
    jne .ports_parse
    mov word [start_port], 1
    mov word [end_port], 65535
    jmp .ports_ok
.ports_parse:
    lea rdi, [input_buf]
    call parse_port_range
    test ax, ax
    jz .fail
    mov [start_port], ax
    mov [end_port], dx
.ports_ok:

    ; Scan mode
    lea rsi, [prompt_scan]
    mov edx, prompt_scan_len
    lea rdi, [input_buf]
    mov ecx, 256
    call prompt_read_line
    test eax, eax
    jz .scan_ok
    lea rdi, [input_buf]
    call parse_scan_mode
    test al, al
    jz .fail
    mov [scan_mode], al
.scan_ok:

    ; Rate
    lea rsi, [prompt_rate]
    mov edx, prompt_rate_len
    lea rdi, [input_buf]
    mov ecx, 256
    call prompt_read_line
    test eax, eax
    jz .rate_ok
    lea rdi, [input_buf]
    call parse_u32
    test eax, eax
    jz .fail
    mov [rate_value], eax
.rate_ok:

    ; Interface
    lea rsi, [prompt_iface]
    mov edx, prompt_iface_len
    lea rdi, [input_buf]
    mov ecx, 256
    call prompt_read_line
    test eax, eax
    jz .iface_ok
    lea rsi, [input_buf]
    call copy_iface_name
    test eax, eax
    jnz .fail
    mov byte [iface_set], 1
.iface_ok:

    ; Stabilize
    lea rsi, [prompt_stab]
    mov edx, prompt_stab_len
    lea rdi, [input_buf]
    mov ecx, 256
    call prompt_read_line
    test eax, eax
    jz .stab_ok
    mov al, [input_buf]
    or al, 0x20
    cmp al, 'y'
    jne .stab_ok
    mov byte [stab_enabled], 1
.stab_ok:
    xor eax, eax
    ret
.fail:
    lea rsi, [prompt_invalid]
    mov edx, prompt_invalid_len
    call buf_write
    call flush_output
    mov eax, 1
    ret

; -------------------------------------------------------------------
; prompt_read_line  rsi=prompt, edx=len, rdi=buf, ecx=bufsize
; Returns eax=1 if non-empty, 0 if empty/error
; -------------------------------------------------------------------
prompt_read_line:
    push rbx
    mov rbx, rdi
    mov r8d, ecx
    call buf_write
    call flush_output
    mov rax, SYS_READ
    xor rdi, rdi
    mov rsi, rbx
    mov rdx, r8
    dec rdx
    syscall
    test rax, rax
    jle .none
    mov rcx, rax
    mov byte [rbx+rcx], 0
    mov rdi, rbx
    call trim_line
    mov al, [rbx]
    test al, al
    setnz al
    movzx eax, al
    pop rbx
    ret
.none:
    mov byte [rbx], 0
    xor eax, eax
    pop rbx
    ret

; -------------------------------------------------------------------
; trim_line  rdi=buffer  (strips \r and \n at end)
; -------------------------------------------------------------------
trim_line:
    mov al, [rdi]
    test al, al
    jz .done
    cmp al, 10
    je .term
    cmp al, 13
    je .term
    inc rdi
    jmp trim_line
.term:
    mov byte [rdi], 0
.done:
    ret

; ===========================================================================
; Netx-ASM  |  Linux x86_64  |  Part 5 of 5: Network helpers, rate, stabilize
; ===========================================================================

; -------------------------------------------------------------------
; copy_iface_name  rsi=src  -> eax=0 ok, 1 too long
; Copies up to 15 bytes into iface_name
; -------------------------------------------------------------------
copy_iface_name:
    push rbx
    lea rdi, [iface_name]
    xor eax, eax
    mov rcx, 16
    rep stosb
    lea rdi, [iface_name]
    mov rcx, 15
.copy:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz .ok
    inc rsi
    inc rdi
    dec rcx
    jnz .copy
    pop rbx
    mov eax, 1
    ret
.ok:
    pop rbx
    xor eax, eax
    ret

; -------------------------------------------------------------------
; setup_send_engine
; If --iface: use AF_PACKET + verify interface is up.
; Otherwise: reuse raw_fd for sending.
; Returns eax=0 ok, 1 fail
; -------------------------------------------------------------------
setup_send_engine:
    cmp byte [iface_set], 0
    je .use_raw
    call verify_iface
    test eax, eax
    jnz .fail
    mov rax, SYS_SOCKET
    mov rdi, AF_PACKET
    mov rsi, SOCK_DGRAM
    mov rdx, ETH_P_IP_BE
    syscall
    test rax, rax
    js .fail
    mov [send_fd], rax
    mov word [sockaddr_ll], AF_PACKET
    mov word [sockaddr_ll+2], ETH_P_IP_BE
    mov eax, [ifindex]
    mov [sockaddr_ll+4], eax
    mov byte [engine_id], ENGINE_L2
    xor eax, eax
    ret
.use_raw:
    mov rax, [raw_fd]
    mov [send_fd], rax
    xor eax, eax
    ret
.fail:
    mov eax, 1
    ret

; -------------------------------------------------------------------
; verify_iface
; Checks iface_name via SIOCGIFINDEX + SIOCGIFFLAGS
; Returns eax=0 ok, 1 fail
; -------------------------------------------------------------------
verify_iface:
    push rbx
    lea rdi, [ifreq_buf]
    xor eax, eax
    mov rcx, 5
    rep stosq
    lea rsi, [iface_name]
    lea rdi, [ifreq_buf]
    mov rcx, 16
.copy_ifr:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz .ifr_copied
    inc rsi
    inc rdi
    dec rcx
    jnz .copy_ifr
    jmp .fail_pop

.ifr_copied:
    mov rax, SYS_SOCKET
    mov rdi, AF_INET
    mov rsi, SOCK_DGRAM
    mov rdx, IPPROTO_UDP
    syscall
    test rax, rax
    js .fail_pop
    mov rbx, rax

    mov rax, SYS_IOCTL
    mov rdi, rbx
    mov rsi, SIOCGIFINDEX
    lea rdx, [ifreq_buf]
    syscall
    test rax, rax
    js .fail_close
    mov eax, [ifreq_buf+16]
    mov [ifindex], eax

    mov rax, SYS_IOCTL
    mov rdi, rbx
    mov rsi, SIOCGIFFLAGS
    lea rdx, [ifreq_buf]
    syscall
    test rax, rax
    js .fail_close
    mov ax, [ifreq_buf+16]
    test ax, IFF_UP
    jz .fail_close
    test ax, IFF_RUNNING
    jz .fail_close

    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
    pop rbx
    xor eax, eax
    ret

.fail_close:
    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
.fail_pop:
    pop rbx
    mov eax, 1
    ret

; -------------------------------------------------------------------
; get_local_ip
; Opens a UDP socket, connects to target IP (port 53),
; reads back our local IP via getsockname
; Returns eax=0 ok, 1 fail
; -------------------------------------------------------------------
get_local_ip:
    mov rax, SYS_SOCKET
    mov rdi, AF_INET
    mov rsi, SOCK_DGRAM
    mov rdx, IPPROTO_UDP
    syscall
    test rax, rax
    js .fail
    mov rbx, rax

    mov word  [sockaddr_tmp],   AF_INET
    mov word  [sockaddr_tmp+2], 0x3500      ; port 53 big-endian
    mov eax, [target_ip]
    mov [sockaddr_tmp+4], eax

    mov rax, SYS_CONNECT
    mov rdi, rbx
    lea rsi, [sockaddr_tmp]
    mov rdx, 16
    syscall
    test rax, rax
    js .fail_close

    mov dword [addrlen], 16
    mov rax, SYS_GETSOCKNAME
    mov rdi, rbx
    lea rsi, [sockaddr_local]
    lea rdx, [addrlen]
    syscall
    test rax, rax
    js .fail_close

    mov eax, [sockaddr_local+4]
    mov [source_ip], eax

    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
    xor eax, eax
    ret

.fail_close:
    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
.fail:
    mov eax, 1
    ret

; -------------------------------------------------------------------
; intelligence_gate  - calls rate_gate (and future hooks)
; -------------------------------------------------------------------
intelligence_gate:
    call rate_gate
    ret

; -------------------------------------------------------------------
; rate_gate  - RDTSC-based packet rate limiter
; -------------------------------------------------------------------
rate_gate:
    cmp byte [rate_enabled], 0
    je .done
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r8, [last_send_tsc]
    test r8, r8
    jz .store
.wait:
    mov r9, rax
    sub r9, r8
    cmp r9, [rate_cycles]
    jae .store
    rdtsc
    shl rdx, 32
    or rax, rdx
    jmp .wait
.store:
    mov [last_send_tsc], rax
.done:
    ret

; -------------------------------------------------------------------
; stabilize_step
; Adaptive rate control: slow down if too many timeouts,
; speed up if too many confirmed responses
; -------------------------------------------------------------------
stabilize_step:
    cmp byte [stab_enabled], 0
    je .done
    cmp byte [rate_enabled], 0
    je .done
    push rcx
    mov eax, [stab_sent]
    test eax, eax
    jz .restore
    xor edx, edx
    mov ecx, 128
    div ecx
    test edx, edx
    jne .restore
    mov eax, [stab_timeout]
    mov ecx, [stab_recv]
    lea edx, [ecx*2]
    cmp eax, edx
    ja .slow
    lea edx, [eax*2]
    cmp ecx, edx
    ja .fast
    jmp .reset
.slow:
    call slow_down
    jmp .reset
.fast:
    call speed_up
.reset:
    mov dword [stab_sent],   0
    mov dword [stab_recv],   0
    mov dword [stab_timeout], 0
.restore:
    pop rcx
.done:
    ret

slow_down:
    mov rax, [rate_cycles]
    mov rcx, rax
    shr rcx, 2
    add rax, rcx
    mov rdx, [rate_max_cycles]
    test rdx, rdx
    jz .store
    cmp rax, rdx
    jbe .store
    mov rax, rdx
.store:
    mov [rate_cycles], rax
    ret

speed_up:
    mov rax, [rate_cycles]
    mov rcx, rax
    shr rcx, 3
    sub rax, rcx
    mov rdx, [rate_min_cycles]
    test rdx, rdx
    jz .store
    cmp rax, rdx
    jae .store
    mov rax, rdx
.store:
    mov [rate_cycles], rax
    ret

; -------------------------------------------------------------------
; init_rate
; Reads rate_value, calibrates TSC, sets rate_cycles
; -------------------------------------------------------------------
init_rate:
    mov eax, [rate_value]
    test eax, eax
    jnz .do
    cmp byte [stab_enabled], 0
    je .done
    mov dword [rate_value], 200000
    mov eax, [rate_value]
.do:
    call calibrate_tsc
    mov ecx, [rate_value]
    mov rax, [tsc_hz]
    xor rdx, rdx
    div rcx
    mov [rate_cycles], rax
    mov byte [rate_enabled], 1
    cmp byte [stab_enabled], 0
    je .done
    mov rax, [rate_cycles]
    mov rcx, rax
    shl rcx, 2
    mov [rate_max_cycles], rcx
    shr rax, 2
    mov [rate_min_cycles], rax
.done:
    ret

; -------------------------------------------------------------------
; calibrate_tsc
; Measures TSC frequency using clock_gettime(CLOCK_MONOTONIC)
; Waits ~50ms, counts TSC ticks, computes tsc_hz
; -------------------------------------------------------------------
calibrate_tsc:
    mov rax, SYS_CLOCK_GETTIME
    mov rdi, CLOCK_MONOTONIC
    lea rsi, [ts_start]
    syscall
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [tsc_start], rax
.loop:
    mov rax, SYS_CLOCK_GETTIME
    mov rdi, CLOCK_MONOTONIC
    lea rsi, [ts_end]
    syscall
    mov rax, [ts_end]
    mov r10, [ts_start]
    sub rax, r10
    mov rcx, [ts_end+8]
    sub rcx, [ts_start+8]
    jns .delta_ok
    dec rax
    add rcx, 1000000000
.delta_ok:
    mov r11, 1000000000
    imul rax, r11
    add rax, rcx
    cmp rax, 50000000           ; wait at least 50ms
    jb .loop
    mov r8, rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r9, rax
    sub rax, [tsc_start]
    mov rcx, 1000000000
    mul rcx
    div r8
    mov [tsc_hz], rax
    ret
