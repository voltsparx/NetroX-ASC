; ============================================================
; sar_engine.inc - Synthetic Ambient Resonance scan engine
; Decision-Delta Mapping with Synaptic Sync guardrail
; ============================================================

%ifndef SAR_ENGINE_INC
%define SAR_ENGINE_INC 1

; ------------------------------------------------------------
; sar_cycles_to_ns
; Input:  rax = TSC cycle delta
; Output: rax = nanoseconds
; Uses:   [tsc_hz]
; ------------------------------------------------------------
sar_cycles_to_ns:
    mov  rcx, 1000000000
    mul  rcx
    xor  rdx, rdx
    div  qword [tsc_hz]
    ret

; ------------------------------------------------------------
; sar_rdtsc_start
; Records RDTSC into sar_t_send
; ------------------------------------------------------------
sar_rdtsc_start:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [sar_t_send], rax
    ret

; ------------------------------------------------------------
; sar_rdtsc_end
; Records RDTSC into sar_t_recv
; Computes delta and converts to ns
; Returns rax = nanoseconds elapsed
; ------------------------------------------------------------
sar_rdtsc_end:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [sar_t_recv], rax
    sub  rax, [sar_t_send]
    call sar_cycles_to_ns
    ret

; ------------------------------------------------------------
; sar_compute_delta
; Input:  rax = synthetic_rtt_ns
;         rbx = baseline_rtt_ns  (must be non-zero)
; Output: rax = delta * 1000 (e.g. 1250 = 1.250x)
; ------------------------------------------------------------
sar_compute_delta:
    mov  rcx, 1000
    mul  rcx
    xor  rdx, rdx
    div  rbx
    ret

; ------------------------------------------------------------
; sar_classify_delta
; Input:  rax = delta * 1000
; Output: [sar_class] = SAR_CLASS_xxx
; ------------------------------------------------------------
sar_classify_delta:
    cmp  rax, 1010
    jb   .none
    cmp  rax, 1050
    jb   .acl
    cmp  rax, 1100
    jb   .stateful
    cmp  rax, 1200
    jb   .dpi
    cmp  rax, 1500
    jb   .ai_edr
    mov  byte [sar_class], SAR_CLASS_PROXY
    ret
.none:
    mov  byte [sar_class], SAR_CLASS_NONE
    ret
.acl:
    mov  byte [sar_class], SAR_CLASS_ACL
    ret
.stateful:
    mov  byte [sar_class], SAR_CLASS_STATEFUL
    ret
.dpi:
    mov  byte [sar_class], SAR_CLASS_DPI
    ret
.ai_edr:
    mov  byte [sar_class], SAR_CLASS_AI_EDR
    ret

; ------------------------------------------------------------
; sar_update_counter
; Increments the counter for the current sar_class value
; ------------------------------------------------------------
sar_update_counter:
    movzx eax, byte [sar_class]
    cmp  al, SAR_CLASS_NONE
    jne  .chk_acl
    inc  dword [sar_count_none]
    ret
.chk_acl:
    cmp  al, SAR_CLASS_ACL
    jne  .chk_stateful
    inc  dword [sar_count_acl]
    ret
.chk_stateful:
    cmp  al, SAR_CLASS_STATEFUL
    jne  .chk_dpi
    inc  dword [sar_count_acl]
    ret
.chk_dpi:
    cmp  al, SAR_CLASS_DPI
    jne  .chk_ai
    inc  dword [sar_count_dpi]
    ret
.chk_ai:
    cmp  al, SAR_CLASS_AI_EDR
    jne  .chk_proxy
    inc  dword [sar_count_ai]
    ret
.chk_proxy:
    inc  dword [sar_count_proxy]
    ret

; ------------------------------------------------------------
; sar_check_guardrail
; Checks all Synaptic Sync trigger conditions.
; Sets [sar_synced]=1 and returns with ZF=0 if triggered.
; Returns with ZF=1 if stable.
; ------------------------------------------------------------
sar_check_guardrail:
    cmp  rax, 0
    movzx ebx, word [sar_synaptic_limit]
    cmp  rax, rbx
    jae  .trigger

    movzx eax, byte [sar_timeout_streak]
    cmp  al, SAR_TIMEOUT_STREAK_MAX
    jae  .trigger

    xor  eax, eax
    test eax, eax
    ret

.trigger:
    mov  byte [sar_synced], 1
    inc  dword [sar_count_syncs]
    mov  eax, 1
    test eax, eax
    ret

; ------------------------------------------------------------
; sar_execute_sync
; Prints sync alert and stops the scan.
; ------------------------------------------------------------
sar_execute_sync:
    call color_guard_check
    jz .skip_sync_color
    COLOR_YELLOW
.skip_sync_color:
    lea  rsi, [sar_sync_msg]
    call .strlen_write
    call color_guard_check
    jz .skip_sync_reset
    COLOR_RESET
.skip_sync_reset:
    call flush_output
    jmp  .scan_done
.strlen_write:
    xor  edx, edx
.len:
    cmp  byte [rsi+rdx], 0
    je   .done_len
    inc  edx
    jmp  .len
.done_len:
    call buf_write
    ret

; ------------------------------------------------------------
; sar_baseline_probe
; Sends SAR_BASELINE_PROBES ICMP Echo Requests.
; Stores RTTs in sar_baseline_samples.
; Computes median and stores in sar_baseline_ns.
; ------------------------------------------------------------
sar_baseline_probe:
    push rbx
    push r12
    push r13

    mov  al, [engine_id]
    push rax
    mov  byte [engine_id], ENGINE_ICMP
    mov  word [dst_port_be], 0

    xor  r12d, r12d

.probe_loop:
    cmp  r12d, SAR_BASELINE_PROBES
    jae  .probe_done

    call build_icmp_packet
    call sar_rdtsc_start

    mov  rax, SYS_SENDTO
    mov  rdi, [raw_fd]
    lea  rsi, [packet_buf]
    mov  edx, 60
    xor  r10d, r10d
    lea  r8,  [sockaddr_dst]
    mov  r9d, 16
    syscall

    mov  rax, SYS_EPOLL_WAIT
    mov  rdi, [epoll_fd]
    lea  rsi, [epoll_out]
    mov  edx, 1
    mov  r10d, 1000
    syscall
    test rax, rax
    jle  .probe_timeout

    mov  rax, SYS_RECVFROM
    mov  rdi, [raw_fd]
    lea  rsi, [recv_buf]
    mov  edx, 4096
    xor  r10d, r10d
    xor  r8d, r8d
    xor  r9d, r9d
    syscall
    test rax, rax
    jle  .probe_timeout

    call sar_rdtsc_end
    mov  [sar_baseline_samples + r12*8], rax
    inc  r12d
    jmp  .probe_loop

.probe_timeout:
    mov  qword [sar_baseline_samples + r12*8], 999999999
    inc  r12d
    jmp  .probe_loop

.probe_done:
    mov  rax, [sar_baseline_samples]
    mov  rcx, SAR_BASELINE_PROBES
    xor  r13d, r13d
.min_loop:
    mov  rbx, [sar_baseline_samples + r13*8]
    cmp  rbx, rax
    jae  .min_next
    mov  rax, rbx
.min_next:
    inc  r13d
    loop .min_loop
    mov  [sar_baseline_ns], rax

    pop  rax
    mov  [engine_id], al

    pop  r13
    pop  r12
    pop  rbx
    ret

; ------------------------------------------------------------
; sar_probe_port
; Input: ecx = port number
; Sends chameleon pulse, records RTT into sar_chameleon_ns.
; Sends synthetic pulse, records RTT into sar_synthetic_ns.
; Uses existing packet_buf, raw_fd, epoll_fd.
; ------------------------------------------------------------
sar_probe_port:
    push rbx
    push rcx
    push rdx

    mov  ax, cx
    xchg al, ah
    mov  [dst_port_be], ax
    mov  [sockaddr_dst+2], ax

    mov  byte [scan_mode], SCAN_SYN
    call build_syn_packet

    call sar_rdtsc_start

    mov  rax, SYS_SENDTO
    mov  rdi, [raw_fd]
    lea  rsi, [packet_buf]
    mov  edx, 40
    xor  r10d, r10d
    lea  r8,  [sockaddr_dst]
    mov  r9d, 16
    syscall

    mov  rax, SYS_EPOLL_WAIT
    mov  rdi, [epoll_fd]
    lea  rsi, [epoll_out]
    mov  edx, 1
    mov  r10d, 500
    syscall
    test rax, rax
    jle  .chameleon_timeout

    mov  rax, SYS_RECVFROM
    mov  rdi, [raw_fd]
    lea  rsi, [recv_buf]
    mov  edx, 4096
    xor  r10d, r10d
    xor  r8d, r8d
    xor  r9d, r9d
    syscall

    call sar_rdtsc_end
    mov  [sar_chameleon_ns], rax
    mov  byte [sar_timeout_streak], 0
    jmp  .synthetic_phase

.chameleon_timeout:
    mov  rax, [sar_baseline_ns]
    mov  [sar_chameleon_ns], rax
    inc  byte [sar_timeout_streak]

.synthetic_phase:
    call build_syn_packet

    lea  rdi, [packet_buf+40]
    lea  rsi, [sar_synthetic_payload]
    mov  ecx, sar_synthetic_len
    rep  movsb

    mov  word [packet_buf+2], 0x3800
    mov  word [packet_buf+10], 0
    lea  rdi, [packet_buf]
    call ip_checksum
    mov  [packet_buf+10], ax

    call sar_rdtsc_start

    mov  rax, SYS_SENDTO
    mov  rdi, [raw_fd]
    lea  rsi, [packet_buf]
    mov  edx, 56
    xor  r10d, r10d
    lea  r8,  [sockaddr_dst]
    mov  r9d, 16
    syscall

    mov  rax, SYS_EPOLL_WAIT
    mov  rdi, [epoll_fd]
    lea  rsi, [epoll_out]
    mov  edx, 1
    mov  r10d, 500
    syscall
    test rax, rax
    jle  .synthetic_timeout

    mov  rax, SYS_RECVFROM
    mov  rdi, [raw_fd]
    lea  rsi, [recv_buf]
    mov  edx, 4096
    xor  r10d, r10d
    xor  r8d, r8d
    xor  r9d, r9d
    syscall

    call sar_rdtsc_end
    mov  [sar_synthetic_ns], rax
    jmp  .probe_done

.synthetic_timeout:
    mov  rax, [sar_chameleon_ns]
    mov  [sar_synthetic_ns], rax

.probe_done:
    pop  rdx
    pop  rcx
    pop  rbx
    ret

; ------------------------------------------------------------
; sar_print_result
; Input: ecx = port, rax = delta*1000
; Prints one result line to output buffer
; ------------------------------------------------------------
sar_print_result:
    push rax
    push rcx

    mov  ax, cx
    call append_u16

    lea  rsi, [space_msg]
    mov  edx, space_len
    call buf_write
    lea  rsi, [space_msg]
    call buf_write

    pop  rax
    push rax
    mov  rbx, rax
    mov  rcx, 1000
    xor  rdx, rdx
    div  rcx
    call append_u16
    lea  rsi, [space_msg]
    mov  byte [out_buf], '.'
    lea  rsi, [out_buf]
    mov  edx, 1
    call buf_write
    mov  rax, rdx
    call append_u16
    mov  byte [out_buf], 'x'
    lea  rsi, [out_buf]
    mov  edx, 1
    call buf_write
    mov  byte [out_buf], ' '
    call buf_write
    call buf_write

    movzx eax, byte [sar_class]
    cmp  eax, 5
    jbe  .class_ok
    xor  eax, eax
.class_ok:
    mov  rsi, [sar_class_ptrs + rax*8]
    xor  edx, edx
.class_len:
    cmp  byte [rsi+rdx], 0
    je   .class_done
    inc  edx
    jmp  .class_len
.class_done:
    call buf_write

    mov  rax, [sar_baseline_ns]
    call append_u16
    lea  rsi, [sar_ns_msg]
    mov  edx, 2
    call buf_write
    mov  byte [out_buf], ' '
    lea  rsi, [out_buf]
    mov  edx, 1
    call buf_write

    mov  rax, [sar_synthetic_ns]
    call append_u16
    lea  rsi, [sar_ns_msg]
    mov  edx, 2
    call buf_write

    lea  rsi, [newline_msg]
    mov  edx, newline_len
    call buf_write

    pop  rcx
    pop  rax
    ret

; ------------------------------------------------------------
; sar_print_summary
; Prints full cognitive map summary after scan
; ------------------------------------------------------------
sar_print_summary:
    call color_guard_check
    jz .skip_sum_color
    COLOR_CYAN
.skip_sum_color:
    lea  rsi, [sar_sum_hdr]
    call .pstr
    call color_guard_check
    jz .skip_sum_reset
    COLOR_RESET
.skip_sum_reset:

    lea  rsi, [sar_sum_audit]
    call .pstr
    mov  eax, [sar_count_total]
    call append_u16
    lea  rsi, [newline_msg]
    mov  edx, newline_len
    call buf_write

    lea  rsi, [sar_sum_none]
    call .pstr
    mov  eax, [sar_count_none]
    call append_u16
    lea  rsi, [newline_msg]
    mov  edx, newline_len
    call buf_write

    lea  rsi, [sar_sum_acl]
    call .pstr
    mov  eax, [sar_count_acl]
    call append_u16
    lea  rsi, [newline_msg]
    mov  edx, newline_len
    call buf_write

    lea  rsi, [sar_sum_dpi]
    call .pstr
    mov  eax, [sar_count_dpi]
    call append_u16
    lea  rsi, [newline_msg]
    mov  edx, newline_len
    call buf_write

    lea  rsi, [sar_sum_ai]
    call .pstr
    mov  eax, [sar_count_ai]
    call append_u16
    lea  rsi, [newline_msg]
    mov  edx, newline_len
    call buf_write

    lea  rsi, [sar_sum_proxy]
    call .pstr
    mov  eax, [sar_count_proxy]
    call append_u16
    lea  rsi, [newline_msg]
    mov  edx, newline_len
    call buf_write

    lea  rsi, [sar_sum_syncs]
    call .pstr
    mov  eax, [sar_count_syncs]
    call append_u16
    lea  rsi, [newline_msg]
    mov  edx, newline_len
    call buf_write

    mov  eax, [sar_count_proxy]
    add  eax, [sar_count_ai]
    cmp  eax, 5
    jg   .storm
    mov  eax, [sar_count_syncs]
    cmp  eax, 2
    jg   .storm
    mov  eax, [sar_count_dpi]
    cmp  eax, 3
    jg   .collapsing
    mov  eax, [sar_count_syncs]
    test eax, eax
    jnz  .collapsing
    call color_guard_check
    jz .skip_stable_color
    COLOR_GREEN
.skip_stable_color:
    lea  rsi, [sar_status_stab]
    jmp  .print_status
.collapsing:
    call color_guard_check
    jz .skip_collapse_color
    COLOR_YELLOW
.skip_collapse_color:
    lea  rsi, [sar_status_coll]
    jmp  .print_status
.storm:
    call color_guard_check
    jz .skip_storm_color
    COLOR_RED
.skip_storm_color:
    lea  rsi, [sar_status_stor]
.print_status:
    call .pstr
    call color_guard_check
    jz .skip_status_reset
    COLOR_RESET
.skip_status_reset:
    ret

.pstr:
    push rdx
    xor  edx, edx
.pstr_len:
    cmp  byte [rsi+rdx], 0
    je   .pstr_done
    inc  edx
    jmp  .pstr_len
.pstr_done:
    call buf_write
    pop  rdx
    ret

; ------------------------------------------------------------
; sar_init
; Called once before sar_run. Zeroes state, sets defaults,
; runs baseline calibration, prints header.
; ------------------------------------------------------------
sar_init:
    lea  rdi, [sar_enabled]
    xor  eax, eax
    mov  ecx, 8 + 1 + 1 + 2 + 1 + 16 + 1 + 1 + 24 + 1 + 8 + 8
    rep  stosb

    mov  word [sar_synaptic_limit], SAR_SYNAPTIC_DEFAULT
    mov  byte [sar_enabled], 1

    mov  dword [sar_count_none],     0
    mov  dword [sar_count_acl],      0
    mov  dword [sar_count_stateful], 0
    mov  dword [sar_count_dpi],      0
    mov  dword [sar_count_ai],       0
    mov  dword [sar_count_proxy],    0
    mov  dword [sar_count_syncs],    0
    mov  dword [sar_count_total],    0

    call color_guard_check
    jz .skip_hdr_color
    COLOR_CYAN
.skip_hdr_color:
    lea  rsi, [sar_hdr_msg]
    xor  edx, edx
.hdr_len:
    cmp  byte [rsi+rdx], 0
    je   .hdr_done
    inc  edx
    jmp  .hdr_len
.hdr_done:
    call buf_write

    lea  rsi, [sar_hdr_end]
    xor  edx, edx
.end_len:
    cmp  byte [rsi+rdx], 0
    je   .end_done
    inc  edx
    jmp  .end_len
.end_done:
    call buf_write
    call color_guard_check
    jz .skip_hdr_reset
    COLOR_RESET
.skip_hdr_reset:

    call sar_baseline_probe

    lea  rsi, [sar_base_msg]
    xor  edx, edx
.base_len:
    cmp  byte [rsi+rdx], 0
    je   .base_done
    inc  edx
    jmp  .base_len
.base_done:
    call buf_write
    mov  rax, [sar_baseline_ns]
    call append_u16
    lea  rsi, [sar_ns_msg]
    xor  edx, edx
.ns_len:
    cmp  byte [rsi+rdx], 0
    je   .ns_done
    inc  edx
    jmp  .ns_len
.ns_done:
    call buf_write

    lea  rsi, [sar_col_hdr]
    xor  edx, edx
.col_len:
    cmp  byte [rsi+rdx], 0
    je   .col_done
    inc  edx
    jmp  .col_len
.col_done:
    call buf_write
    lea  rsi, [sar_col_sep]
    xor  edx, edx
.sep_len:
    cmp  byte [rsi+rdx], 0
    je   .sep_done
    inc  edx
    jmp  .sep_len
.sep_done:
    call buf_write
    call flush_output
    ret

; ------------------------------------------------------------
; sar_run
; Main SAR scan loop. Iterates port range using Blackrock.
; For each port: probe, compute delta, classify, guardrail check.
; ------------------------------------------------------------
sar_run:
    push rbx
    push r12
    push r13
    push r14
    push r15

    movzx ecx, word [start_port]
    movzx r15d, word [end_port]
    mov   r14d, r15d
    sub   r14d, ecx
    inc   r14d
    xor   ebx, ebx

.sar_loop:
    cmp  ebx, r14d
    jae  .sar_done

    mov  rdi, rbx
    mov  rsi, r14
    call blackrock_permute
    movzx ecx, word [start_port]
    add  ecx, eax

    call sar_probe_port

    mov  rax, [sar_synthetic_ns]
    mov  rbx, [sar_baseline_ns]
    test rbx, rbx
    jz   .sar_skip
    call sar_compute_delta

    push rax

    call sar_classify_delta
    call sar_update_counter
    inc  dword [sar_count_total]

    movzx edx, byte [sar_delta_hist_idx]
    pop  rax
    push rax
    mov  [sar_delta_history + rdx*2], ax
    inc  dl
    and  dl, SAR_TREND_WINDOW - 1
    mov  [sar_delta_hist_idx], dl

    call sar_check_guardrail
    jnz  .sar_sync

    pop  rax
    push ecx
    call sar_print_result
    pop  ecx

    push ecx
    push rbx
    call stabilize_step
    pop  rbx
    pop  ecx

    movzx ecx, word [start_port]
    inc  ebx
    jmp  .sar_loop

.sar_skip:
    pop  rax
    inc  ebx
    jmp  .sar_loop

.sar_sync:
    pop  rax
    call sar_execute_sync

.sar_done:
    call sar_print_summary
    call flush_output

    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

%endif ; SAR_ENGINE_INC
