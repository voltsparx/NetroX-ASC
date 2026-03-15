; ============================================================
; callback_engine.inc - Callback-Ping engine
; ============================================================

%ifndef CALLBACK_ENGINE_INC
%define CALLBACK_ENGINE_INC 1

; ------------------------------------------------------------
; cb_rdtsc_start
; ------------------------------------------------------------
cb_rdtsc_start:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [cb_t_send], rax
    ret

; ------------------------------------------------------------
; cb_rdtsc_end
; ------------------------------------------------------------
cb_rdtsc_end:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [cb_t_recv], rax
    sub  rax, [cb_t_send]
    call sar_cycles_to_ns
    ret

; ------------------------------------------------------------
; cb_subnet_check
; ------------------------------------------------------------
cb_subnet_check:
    mov  ebx, eax
    shr  eax, 8
    and  eax, 0xFFFF
    mov  edx, eax
    shr  eax, 3
    and  edx, 7
    mov  cl, 1
    shl  cl, dl
    test byte [cb_subnet_seen + rax], cl
    ret

; ------------------------------------------------------------
; cb_subnet_mark
; ------------------------------------------------------------
cb_subnet_mark:
    mov  ebx, eax
    shr  eax, 8
    and  eax, 0xFFFF
    mov  edx, eax
    shr  eax, 3
    and  edx, 7
    mov  cl, 1
    shl  cl, dl
    or   byte [cb_subnet_seen + rax], cl
    ret

; ------------------------------------------------------------
; cb_detect_inbound
; ------------------------------------------------------------
cb_detect_inbound:
    mov  eax, [rsi+12]
    cmp  eax, [target_ip]
    je   .no

    mov  bl, [rsi+9]
    cmp  bl, 6
    je   .tcp
    cmp  bl, 1
    je   .icmp
    cmp  bl, 17
    je   .udp
    jmp  .no

.tcp:
    movzx eax, byte [rsi]
    and  al, 0x0F
    shl  al, 2
    movzx edi, al
    lea  rdx, [rsi+rdi]
    mov  al, [rdx+13]
    test al, 0x02
    jz   .no
    mov  byte [cb_trigger_proto], 1
    mov  eax, [rsi+12]
    mov  [cb_src_ip], eax
    movzx ecx, word [rdx]
    xchg cl, ch
    mov  [cb_src_port], cx
    jmp  .seen_check

.icmp:
    cmp  byte [rsi+20], 8
    jne  .no
    mov  byte [cb_trigger_proto], 2
    mov  eax, [rsi+12]
    mov  [cb_src_ip], eax
    mov  word [cb_src_port], 0
    jmp  .seen_check

.udp:
    mov  byte [cb_trigger_proto], 3
    mov  eax, [rsi+12]
    mov  [cb_src_ip], eax
    movzx ecx, word [rsi+20]
    xchg cl, ch
    mov  [cb_src_port], cx

.seen_check:
    mov  eax, [cb_src_ip]
    call cb_subnet_check
    jnz  .no
    mov  eax, [cb_src_ip]
    call cb_subnet_mark
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; ------------------------------------------------------------
; cb_select_proto
; ------------------------------------------------------------
cb_select_proto:
    mov  al, [cb_proto]
    test al, al
    jnz  .done
    mov  al, [cb_trigger_proto]
    cmp  al, 1
    je   .dns
    cmp  al, 2
    je   .ntp
    cmp  al, 3
    je   .icmp
    jmp  .dns
.dns:
    mov  al, CB_PROTO_DNS
    jmp  .done
.ntp:
    mov  al, CB_PROTO_NTP
    jmp  .done
.icmp:
    mov  al, CB_PROTO_ICMP
.done:
    ret

; ------------------------------------------------------------
; cb_build_dns
; ------------------------------------------------------------
cb_build_dns:
    mov  eax, [cb_src_ip]
    mov  [packet_buf+16], eax
    mov  [sockaddr_dst+4], eax
    mov  word [packet_buf+2], 0
    mov  ax, 20+8+cb_dns_len
    xchg al, ah
    mov  [packet_buf+2], ax
    mov  byte [packet_buf+9], 17
    mov  ax, [packet_buf+4]
    inc  ax
    mov  [packet_buf+4], ax
    mov  word [packet_buf+10], 0
    lea  rdi, [packet_buf]
    call ip_checksum
    mov  [packet_buf+10], ax
    call xorshift64_next
    mov  ax, ax
    test ax, ax
    jnz  .src_ok
    inc  ax
.src_ok:
    xchg al, ah
    mov  [packet_buf+20], ax
    mov  word [packet_buf+22], CB_DNS_PORT_BE
    mov  ax, 8+cb_dns_len
    xchg al, ah
    mov  [packet_buf+24], ax
    mov  word [packet_buf+26], 0
    lea  rdi, [packet_buf+28]
    lea  rsi, [cb_dns_payload]
    mov  ecx, cb_dns_len
    rep  movsb
    ret

; ------------------------------------------------------------
; cb_build_ntp
; ------------------------------------------------------------
cb_build_ntp:
    mov  eax, [cb_src_ip]
    mov  [packet_buf+16], eax
    mov  [sockaddr_dst+4], eax
    mov  word [packet_buf+2], 0
    mov  ax, 20+8+48
    xchg al, ah
    mov  [packet_buf+2], ax
    mov  byte [packet_buf+9], 17
    mov  ax, [packet_buf+4]
    inc  ax
    mov  [packet_buf+4], ax
    mov  word [packet_buf+10], 0
    lea  rdi, [packet_buf]
    call ip_checksum
    mov  [packet_buf+10], ax
    call xorshift64_next
    mov  ax, ax
    test ax, ax
    jnz  .src_ok
    inc  ax
.src_ok:
    xchg al, ah
    mov  [packet_buf+20], ax
    mov  word [packet_buf+22], CB_NTP_PORT_BE
    mov  ax, 8+48
    xchg al, ah
    mov  [packet_buf+24], ax
    mov  word [packet_buf+26], 0
    lea  rdi, [packet_buf+28]
    lea  rsi, [cb_ntp_payload]
    mov  ecx, cb_ntp_len
    rep  movsb
    ret

; ------------------------------------------------------------
; cb_build_icmp
; ------------------------------------------------------------
cb_build_icmp:
    mov  eax, [cb_src_ip]
    mov  [packet_buf+16], eax
    mov  [sockaddr_dst+4], eax
    mov  ax, 36
    xchg al, ah
    mov  [packet_buf+2], ax
    mov  byte [packet_buf+9], 1
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
    mov  word [packet_buf+24], CB_IDENT
    mov  ax, [cb_count_total]
    mov  [packet_buf+26], ax
    lea  rdi, [packet_buf+28]
    mov  ecx, 8
    mov  al, 0x41
    rep  stosb
    xor  rax, rax
    lea  rsi, [packet_buf+20]
    mov  ecx, 8
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

; ------------------------------------------------------------
; cb_build_tcp_ack
; ------------------------------------------------------------
cb_build_tcp_ack:
    push rax
    mov  eax, [target_ip]
    push rax
    mov  eax, [cb_src_ip]
    mov  [target_ip], eax
    mov  [sockaddr_dst+4], eax
    mov  [packet_buf+16], eax
    movzx ecx, word [cb_src_port]
    call phantom_build_pulse
    pop  rax
    mov  [target_ip], eax
    mov  [sockaddr_dst+4], eax
    mov  [packet_buf+16], eax
    pop  rax
    ret

; ------------------------------------------------------------
; cb_send_callback
; ------------------------------------------------------------
cb_send_callback:
    ; save sockaddr_dst
    mov  rbx, [sockaddr_dst]
    mov  rcx, [sockaddr_dst+8]
    call cb_select_proto
    mov  [cb_proto], al
    cmp  al, CB_PROTO_DNS
    je   .do_dns
    cmp  al, CB_PROTO_NTP
    je   .do_ntp
    cmp  al, CB_PROTO_ICMP
    je   .do_icmp
    jmp  .do_ack
.do_dns:
    call cb_build_dns
    jmp  .send
.do_ntp:
    call cb_build_ntp
    jmp  .send
.do_icmp:
    call cb_build_icmp
    jmp  .send
.do_ack:
    call cb_build_tcp_ack
.send:
    call cb_rdtsc_start
    mov  rax, SYS_SENDTO
    mov  rdi, [raw_fd]
    lea  rsi, [packet_buf]
    mov  edx, 76
    cmp  byte [packet_buf+9], 1
    je   .len_icmp
    cmp  word [packet_buf+22], CB_DNS_PORT_BE
    je   .len_dns
    cmp  word [packet_buf+22], CB_NTP_PORT_BE
    je   .len_ntp
    jmp  .send_len_ok
.len_icmp:
    mov  edx, 36
    jmp  .send_len_ok
.len_dns:
    mov  edx, 57
    jmp  .send_len_ok
.len_ntp:
    mov  edx, 76
.send_len_ok:
    xor  r10d, r10d
    lea  r8, [sockaddr_dst]
    mov  r9d, 16
    syscall
    inc  dword [cb_count_total]
    ; restore sockaddr_dst
    mov  [sockaddr_dst], rbx
    mov  [sockaddr_dst+8], rcx
    ret

; ------------------------------------------------------------
; cb_await_response
; ------------------------------------------------------------
cb_await_response:
    mov  rax, SYS_EPOLL_WAIT
    mov  rdi, [epoll_fd]
    lea  rsi, [epoll_out]
    mov  edx, 1
    mov  r10d, CB_RESPONSE_TIMEOUT_MS
    syscall
    test rax, rax
    jle  .timeout
    mov  rax, SYS_RECVFROM
    mov  rdi, [raw_fd]
    lea  rsi, [recv_buf]
    mov  edx, 4096
    xor  r10d, r10d
    xor  r8d, r8d
    xor  r9d, r9d
    syscall
    mov  eax, [recv_buf+12]
    cmp  eax, [cb_src_ip]
    jne  .timeout
    call cb_rdtsc_end
    mov  [cb_latency_ns], rax
    mov  eax, 1
    ret
.timeout:
    xor  eax, eax
    mov  [cb_latency_ns], rax
    ret

; ------------------------------------------------------------
; cb_classify_response
; ------------------------------------------------------------
cb_classify_response:
    test rax, rax
    jnz .has_resp
    mov  byte [cb_class], CB_CLASS_SILENT
    inc  dword [cb_count_silent]
    ret
.has_resp:
    mov  rax, [cb_latency_ns]
    mov  rcx, CB_DELAYED_THRESHOLD_MS
    imul rcx, 1000000
    cmp  rax, rcx
    ja   .delayed
    mov  al, [recv_buf+9]
    cmp  al, 6
    je   .chk_rst
    cmp  al, 1
    je   .chk_icmp
    cmp  al, 17
    je   .responsive
    jmp  .standard
.chk_rst:
    movzx eax, byte [recv_buf]
    and  al, 0x0F
    shl  al, 2
    movzx edi, al
    lea  rdx, [recv_buf+rdi]
    mov  al, [rdx+13]
    test al, 0x04
    jnz  .standard
    jmp  .standard
.chk_icmp:
    cmp  byte [recv_buf+20], 3
    je   .standard
    jmp  .standard
.responsive:
    mov  byte [cb_class], CB_CLASS_RESPONSIVE
    inc  dword [cb_count_responsive]
    ret
.standard:
    mov  byte [cb_class], CB_CLASS_STANDARD
    inc  dword [cb_count_standard]
    ret
.delayed:
    mov  byte [cb_class], CB_CLASS_DELAYED
    inc  dword [cb_count_delayed]
    ret

; ------------------------------------------------------------
; cb_fingerprint
; ------------------------------------------------------------
cb_fingerprint:
    mov  al, [recv_buf+9]
    cmp  al, 6
    jne  .unknown
    movzx eax, byte [recv_buf]
    and  al, 0x0F
    shl  al, 2
    movzx edi, al
    lea  rdx, [recv_buf+rdi]
    call intel_analyze
    movzx eax, byte [intel_fp_best_idx]
    cmp  al, 0
    je   .linux
    cmp  al, 1
    je   .linux
    cmp  al, 2
    je   .windows
    cmp  al, 3
    je   .windows
    cmp  al, 4
    je   .macos
    cmp  al, 5
    je   .device
    jmp  .unknown
.linux:
    inc dword [cb_count_linux]
    ret
.windows:
    inc dword [cb_count_windows]
    ret
.macos:
    inc dword [cb_count_macos]
    ret
.device:
    inc dword [cb_count_device]
    ret
.unknown:
    inc dword [cb_count_unknown_os]
    ret

; ------------------------------------------------------------
; cb_print_result
; ------------------------------------------------------------
cb_print_result:
    call color_guard_check
    jz .skip_cb_prefix_color
    COLOR_CYAN
.skip_cb_prefix_color:
    lea  rsi, [cb_prefix_msg]
    call .pstr
    call color_guard_check
    jz .skip_cb_prefix_reset
    COLOR_RESET
.skip_cb_prefix_reset:
    movzx eax, byte [cb_src_ip]
    call append_u16
    call .dot
    movzx eax, byte [cb_src_ip+1]
    call append_u16
    call .dot
    movzx eax, byte [cb_src_ip+2]
    call append_u16
    call .dot
    movzx eax, byte [cb_src_ip+3]
    call append_u16
    mov  byte [out_buf], ':'
    lea  rsi, [out_buf]
    mov  edx, 1
    call buf_write
    movzx ax, word [cb_src_port]
    call append_u16
    lea  rsi, [space_msg]
    mov  edx, space_len
    call buf_write

    mov  al, [cb_trigger_proto]
    cmp  al, 1
    je   .tr_syn
    cmp  al, 2
    je   .tr_icmp
    lea  rsi, [cb_trigger_udp]
    call .pstr
    jmp  .tr_done
.tr_syn:
    lea  rsi, [cb_trigger_syn]
    call .pstr
    jmp  .tr_done
.tr_icmp:
    lea  rsi, [cb_trigger_icmp]
    call .pstr
.tr_done:

    mov  al, [cb_proto]
    cmp  al, CB_PROTO_DNS
    je   .pr_dns
    cmp  al, CB_PROTO_NTP
    je   .pr_ntp
    cmp  al, CB_PROTO_ICMP
    je   .pr_icmp
    lea  rsi, [cb_proto_ack_str]
    call .pstr
    jmp  .pr_done
.pr_dns:
    lea  rsi, [cb_proto_dns_str]
    call .pstr
    jmp  .pr_done
.pr_ntp:
    lea  rsi, [cb_proto_ntp_str]
    call .pstr
    jmp  .pr_done
.pr_icmp:
    lea  rsi, [cb_proto_icmp_str]
    call .pstr
.pr_done:

    mov  al, [cb_class]
    cmp  al, CB_CLASS_SILENT
    je   .cls_silent
    cmp  al, CB_CLASS_STANDARD
    je   .cls_std
    cmp  al, CB_CLASS_RESPONSIVE
    je   .cls_resp
    lea  rsi, [cb_class_delayed]
    call .pstr
    jmp  .cls_done
.cls_silent:
    call color_guard_check
    jz .skip_silent_color
    COLOR_YELLOW
.skip_silent_color:
    lea  rsi, [cb_class_silent]
    call .pstr
    call color_guard_check
    jz .skip_silent_reset
    COLOR_RESET
.skip_silent_reset:
    jmp  .cls_done
.cls_std:
    lea  rsi, [cb_class_std]
    call .pstr
    jmp  .cls_done
.cls_resp:
    call color_guard_check
    jz .skip_resp_color
    COLOR_GREEN
.skip_resp_color:
    lea  rsi, [cb_class_resp]
    call .pstr
    call color_guard_check
    jz .skip_resp_reset
    COLOR_RESET
.skip_resp_reset:
.cls_done:

    lea  rsi, [cb_lat_msg]
    call .pstr
    cmp  byte [cb_class], CB_CLASS_SILENT
    je   .lat_timeout
    mov  rax, [cb_latency_ns]
    call append_u16
    lea  rsi, [phantom_ns_msg]
    call .pstr
    jmp  .lat_done
.lat_timeout:
    lea  rsi, [cb_lat_timeout]
    call .pstr
.lat_done:

    lea  rsi, [space_msg]
    mov  edx, space_len
    call buf_write
    lea  rsi, [cb_os_msg]
    call .pstr
    movzx eax, byte [intel_fp_best_idx]
    mov  rsi, [os_str_ptrs + rax*8]
    call .pstr
    lea  rsi, [space_msg]
    mov  edx, space_len
    call buf_write
    lea  rsi, [cb_ttl_msg]
    call .pstr
    movzx eax, byte [last_ttl]
    call append_u16
    lea  rsi, [newline_msg]
    mov  edx, newline_len
    call buf_write
    ret
.dot:
    mov  byte [out_buf], '.'
    lea  rsi, [out_buf]
    mov  edx, 1
    call buf_write
    ret
.pstr:
    xor edx, edx
.len:
    cmp byte [rsi+rdx], 0
    je .done
    inc edx
    jmp .len
.done:
    call buf_write
    ret

; ------------------------------------------------------------
; cb_print_summary
; ------------------------------------------------------------
cb_print_summary:
    call color_guard_check
    jz .skip_sum_color
    COLOR_CYAN
.skip_sum_color:
    lea rsi, [cb_sum_hdr]
    call .pstr
    call color_guard_check
    jz .skip_sum_reset
    COLOR_RESET
.skip_sum_reset:
    lea rsi, [cb_sum_total]
    call .pstr
    mov eax, [cb_count_total]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [cb_sum_silent]
    call .pstr
    mov eax, [cb_count_silent]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [cb_sum_standard]
    call .pstr
    mov eax, [cb_count_standard]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [cb_sum_responsive]
    call .pstr
    mov eax, [cb_count_responsive]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [cb_sum_delayed]
    call .pstr
    mov eax, [cb_count_delayed]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [cb_sum_os_hdr]
    call .pstr
    lea rsi, [cb_sum_linux]
    call .pstr
    mov eax, [cb_count_linux]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [cb_sum_windows]
    call .pstr
    mov eax, [cb_count_windows]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [cb_sum_macos]
    call .pstr
    mov eax, [cb_count_macos]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [cb_sum_device]
    call .pstr
    mov eax, [cb_count_device]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [cb_sum_unknown]
    call .pstr
    mov eax, [cb_count_unknown_os]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    ret
.pstr:
    xor edx, edx
.len:
    cmp byte [rsi+rdx], 0
    je .done
    inc edx
    jmp .len
.done:
    call buf_write
    ret

; ------------------------------------------------------------
; cb_queue_push
; ------------------------------------------------------------
cb_queue_push:
    movzx eax, byte [cb_queue_count]
    cmp eax, CB_QUEUE_SIZE
    jae .full
    movzx ebx, byte [cb_queue_head]
    lea rdi, [cb_queue + rbx*8]
    mov eax, [cb_src_ip]
    mov [rdi], eax
    mov ax, [cb_src_port]
    mov [rdi+4], ax
    mov al, [cb_trigger_proto]
    mov [rdi+6], al
    inc byte [cb_queue_head]
    cmp byte [cb_queue_head], CB_QUEUE_SIZE
    jb .count_up
    mov byte [cb_queue_head], 0
.count_up:
    inc byte [cb_queue_count]
.full:
    ret

; ------------------------------------------------------------
; cb_queue_pop
; ------------------------------------------------------------
cb_queue_pop:
    movzx eax, byte [cb_queue_count]
    test eax, eax
    jz .empty
    movzx ebx, byte [cb_queue_tail]
    lea rsi, [cb_queue + rbx*8]
    mov eax, [rsi]
    mov [cb_src_ip], eax
    mov ax, [rsi+4]
    mov [cb_src_port], ax
    mov al, [rsi+6]
    mov [cb_trigger_proto], al
    inc byte [cb_queue_tail]
    cmp byte [cb_queue_tail], CB_QUEUE_SIZE
    jb .dec_count
    mov byte [cb_queue_tail], 0
.dec_count:
    dec byte [cb_queue_count]
    mov eax, 1
    ret
.empty:
    xor eax, eax
    ret

; ------------------------------------------------------------
; cb_init
; ------------------------------------------------------------
cb_init:
    mov byte [cb_enabled], 1
    mov byte [cb_proto], 0
    mov dword [cb_response_timeout], CB_RESPONSE_TIMEOUT_MS
    call color_guard_check
    jz .skip_hdr_color
    COLOR_CYAN
.skip_hdr_color:
    lea rsi, [cb_hdr_msg]
    call .pstr
    call color_guard_check
    jz .skip_hdr_reset
    COLOR_RESET
.skip_hdr_reset:
    lea rsi, [cb_proto_msg]
    call .pstr
    lea rsi, [cb_proto_dns_str]
    call .pstr
    lea rsi, [cb_timeout_msg]
    call .pstr
    mov eax, [cb_response_timeout]
    call append_u16
    lea rsi, [cb_ms_msg]
    call .pstr
    call flush_output
    ret
.pstr:
    xor edx, edx
.len:
    cmp byte [rsi+rdx], 0
    je .done
    inc edx
    jmp .len
.done:
    call buf_write
    ret

; ------------------------------------------------------------
; cb_secondary_check
; ------------------------------------------------------------
cb_secondary_check:
    call cb_detect_inbound
    test eax, eax
    jz .done
    call cb_send_callback
    call cb_await_response
    call cb_classify_response
    call cb_fingerprint
    call cb_print_result
.done:
    ret

; ------------------------------------------------------------
; cb_run
; ------------------------------------------------------------
cb_run:
    call cb_init
.loop:
    mov  rax, SYS_EPOLL_WAIT
    mov  rdi, [epoll_fd]
    lea  rsi, [epoll_out]
    mov  edx, 1
    mov  r10d, 5000
    syscall
    test rax, rax
    jle  .loop
    mov  rax, SYS_RECVFROM
    mov  rdi, [raw_fd]
    lea  rsi, [recv_buf]
    mov  edx, 4096
    xor  r10d, r10d
    xor  r8d, r8d
    xor  r9d, r9d
    syscall
    lea  rsi, [recv_buf]
    call cb_secondary_check
    jmp  .loop

%endif
