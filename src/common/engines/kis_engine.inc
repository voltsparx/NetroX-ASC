; ============================================================
; kis_engine.inc - Kinetic Impedance Scan engine
; ============================================================

%ifndef KIS_ENGINE_INC
%define KIS_ENGINE_INC 1

; ------------------------------------------------------------
; kis_cycles_to_ns
; ------------------------------------------------------------
kis_cycles_to_ns:
    mov  rcx, 1000000000
    mul  rcx
    xor  rdx, rdx
    div  qword [tsc_hz]
    ret

; ------------------------------------------------------------
; kis_rdtsc_start
; ------------------------------------------------------------
kis_rdtsc_start:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [kis_t_send], rax
    ret

; ------------------------------------------------------------
; kis_rdtsc_end
; ------------------------------------------------------------
kis_rdtsc_end:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [kis_t_recv], rax
    sub  rax, [kis_t_send]
    call kis_cycles_to_ns
    ret

; ------------------------------------------------------------
; kis_isqrt
; ------------------------------------------------------------
kis_isqrt:
    test rax, rax
    jz .zero
    mov rbx, rax
    shr rbx, 1
    test rbx, rbx
    jz .one
.iterate:
    mov rcx, rax
    xor rdx, rdx
    div rbx
    add rbx, rcx
    shr rbx, 1
    mov rcx, rax
    xor rdx, rdx
    div rbx
    add rbx, rcx
    shr rbx, 1
    mov rcx, rax
    xor rdx, rdx
    div rbx
    add rbx, rcx
    shr rbx, 1
    mov rax, rbx
    ret
.zero:
    ret
.one:
    mov rax, 1
    ret

; ------------------------------------------------------------
; kis_trimmed_mean
; Input: kis_probe_samples[5]
; Output: rax = mean of middle 3 (sorted)
; ------------------------------------------------------------
kis_trimmed_mean:
    push rbx
    push rcx
    push rdx
    push r8
    push r9

    mov ecx, 5
.outer:
    dec ecx
    js .sorted
    mov r8d, 0
.inner:
    mov rax, [kis_probe_samples + r8*8]
    mov rbx, [kis_probe_samples + r8*8 + 8]
    cmp rax, rbx
    jbe .no_swap
    mov [kis_probe_samples + r8*8], rbx
    mov [kis_probe_samples + r8*8 + 8], rax
.no_swap:
    inc r8d
    cmp r8d, ecx
    jl .inner
    jmp .outer

.sorted:
    mov rax, [kis_probe_samples + 8]
    add rax, [kis_probe_samples + 16]
    add rax, [kis_probe_samples + 24]
    mov rcx, 3
    xor rdx, rdx
    div rcx

    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

; ------------------------------------------------------------
; kis_compute_variance
; Input: rbx = mean
; Output: rax = variance (middle 3)
; ------------------------------------------------------------
kis_compute_variance:
    push rcx
    push rdx
    push r8
    xor rax, rax

    mov r8, [kis_probe_samples + 8]
    sub r8, rbx
    imul r8, r8
    add rax, r8

    mov r8, [kis_probe_samples + 16]
    sub r8, rbx
    imul r8, r8
    add rax, r8

    mov r8, [kis_probe_samples + 24]
    sub r8, rbx
    imul r8, r8
    add rax, r8

    mov rcx, 3
    xor rdx, rdx
    div rcx

    pop r8
    pop rdx
    pop rcx
    ret

; ------------------------------------------------------------
; kis_sjs_lookup
; ------------------------------------------------------------
kis_sjs_lookup:
    lea rsi, [kis_sjs_table]
.entry_loop:
    movzx ecx, word [rsi]
    test cx, cx
    jz .not_found
    movzx edx, word [rsi+2]
    cmp rax, rcx
    jb .next_entry
    cmp rax, rdx
    ja .next_entry
    movzx ecx, word [rsi+4]
    movzx edx, word [rsi+6]
    cmp rbx, rcx
    jb .next_entry
    cmp rbx, rdx
    ja .next_entry
    movzx eax, word [rsi+8]
    mov [kis_svc_id], ax
    mov al, [rsi+10]
    mov [kis_confidence], al
    ret
.next_entry:
    add rsi, 24
    jmp .entry_loop
.not_found:
    mov word [kis_svc_id], KIS_SVC_UNKNOWN
    mov byte [kis_confidence], 0
    ret

; ------------------------------------------------------------
; kis_quantum_brake
; ------------------------------------------------------------
kis_quantum_brake:
    mov byte [kis_fuse_blown], 1
    call flush_output
    call color_guard_check
    jz .skip_brake_color
    COLOR_YELLOW
.skip_brake_color:
    lea rsi, [kis_brake_msg]
    call .pstr
    movzx eax, byte [kis_fuse_reason]
    mov rsi, [kis_fuse_reason_ptrs + rax*8]
    call .pstr
    lea rsi, [kis_brake_end]
    call .pstr
    call color_guard_check
    jz .skip_brake_reset
    COLOR_RESET
.skip_brake_reset:
    call flush_output
    jmp .scan_done
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
; kis_check_fuse
; ------------------------------------------------------------
kis_check_fuse:
    cmp byte [kis_fuse_blown], 0
    jne .fuse

    movzx eax, byte [kis_timeout_streak]
    cmp al, KIS_TIMEOUT_STREAK_MAX
    jb .check_ttl
    mov byte [kis_fuse_reason], KIS_FUSE_TIMEOUTS
    jmp .trigger

.check_ttl:
    movzx eax, byte [kis_recheck_counter]
    inc al
    mov [kis_recheck_counter], al
    cmp al, KIS_TTL_RECHECK_INTERVAL
    jb .check_drift
    mov byte [kis_recheck_counter], 0
    movzx ebx, byte [kis_ambient_ttl]
    call kis_ambient_probe
    movzx eax, byte [kis_ambient_ttl]
    cmp al, bl
    je .check_drift
    mov byte [kis_fuse_reason], KIS_FUSE_TTL_SHIFT
    jmp .trigger

.check_drift:
    movzx eax, byte [kis_recheck_counter]
    cmp al, 0
    jne .check_jitter
    mov rax, [kis_ambient_ns]
    mov rbx, [kis_baseline_orig]
    mov rcx, KIS_DRIFT_THRESHOLD
    mul rcx
    xor rdx, rdx
    mov rcx, 100
    div rcx
    cmp rax, rbx
    jbe .check_jitter
    mov byte [kis_fuse_reason], KIS_FUSE_DRIFT
    jmp .trigger

.check_jitter:
    mov  rax, [kis_port_jitter]
    mov  rbx, [kis_jitter_baseline]
    test rbx, rbx
    jz   .skip_jitter_check
    mov  rcx, KIS_JITTER_THRESHOLD
    imul rbx, rcx
    mov  rcx, 100
    xor  rdx, rdx
    div  rcx
    cmp  rax, rbx
    jae  .trigger_jitter
.skip_jitter_check:
    jmp  .check_spike

.trigger_jitter:
    mov byte [kis_fuse_reason], KIS_FUSE_JITTER_EXP
    jmp .trigger

.check_spike:
    mov rax, [kis_port_impedance]
    mov rbx, [kis_ambient_ns]
    mov rcx, KIS_IMP_SPIKE_MULT
    mul rcx
    cmp rax, rbx
    jbe .ok
    mov byte [kis_fuse_reason], KIS_FUSE_IMP_SPIKE
    jmp .trigger

.ok:
    xor eax, eax
    test eax, eax
    ret

.trigger:
    mov byte [kis_fuse_blown], 1
.fuse:
    mov eax, 1
    test eax, eax
    ret

; ------------------------------------------------------------
; kis_ambient_probe
; ------------------------------------------------------------
kis_ambient_probe:
    push rbx
    push r12
    push r13

    mov  al, [engine_id]
    push rax
    mov  byte [engine_id], ENGINE_ICMP
    mov  word [dst_port_be], 0

    xor  r12d, r12d

.probe_loop:
    cmp  r12d, KIS_AMBIENT_PROBES
    jae  .probe_done

    call build_icmp_packet
    call kis_rdtsc_start

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

    mov al, [recv_buf+8]
    mov [kis_ambient_ttl], al

    call kis_rdtsc_end
    mov  [kis_ambient_samples + r12*8], rax
    inc  r12d
    jmp  .probe_loop

.probe_timeout:
    mov  qword [kis_ambient_samples + r12*8], 999999999
    inc  r12d
    jmp  .probe_loop

.probe_done:
    mov  rax, [kis_ambient_samples]
    mov  rcx, KIS_AMBIENT_PROBES
    xor  r13d, r13d
.min_loop:
    mov  rbx, [kis_ambient_samples + r13*8]
    cmp  rbx, rax
    jae  .min_next
    mov  rax, rbx
.min_next:
    inc  r13d
    loop .min_loop
    mov  [kis_ambient_ns], rax

    ; compute ambient jitter baseline (mean + avg abs deviation)
    xor  rax, rax
    xor  r13d, r13d
.sum_loop:
    add  rax, [kis_ambient_samples + r13*8]
    inc  r13d
    cmp  r13d, KIS_AMBIENT_PROBES
    jb   .sum_loop
    xor  rdx, rdx
    mov  rcx, KIS_AMBIENT_PROBES
    div  rcx                        ; rax = mean
    mov  r12, rax                   ; r12 = mean

    xor  rax, rax                   ; sum abs deviation
    xor  r13d, r13d
.var_loop:
    mov  rbx, [kis_ambient_samples + r13*8]
    sub  rbx, r12
    jns  .pos_dev
    neg  rbx
.pos_dev:
    add  rax, rbx
    inc  r13d
    cmp  r13d, KIS_AMBIENT_PROBES
    jb   .var_loop
    xor  rdx, rdx
    mov  rcx, KIS_AMBIENT_PROBES
    div  rcx
    mov  [kis_jitter_baseline], rax

    pop  rax
    mov  [engine_id], al

    pop  r13
    pop  r12
    pop  rbx
    ret

; ------------------------------------------------------------
; kis_send_pulse
; Input: ecx = port
; ------------------------------------------------------------
kis_send_pulse:
    mov  ax, cx
    xchg al, ah
    mov  [dst_port_be], ax
    mov  [sockaddr_dst+2], ax

    call build_syn_packet
    mov  byte [packet_buf+33], 0x06
    mov  word [packet_buf+34], 0
    mov  byte [packet_buf+8], 128
    mov  word [packet_buf+10], 0
    lea  rdi, [packet_buf]
    call ip_checksum
    mov  [packet_buf+10], ax
    mov  word [packet_buf+36], 0
    lea  rdi, [packet_buf]
    call tcp_checksum
    mov  [packet_buf+36], ax
    ret

; ------------------------------------------------------------
; kis_probe_port
; Input: ecx = port
; ------------------------------------------------------------
kis_probe_port:
    push rbx
    push r12

    xor r12d, r12d
    xor ebx, ebx

.probe_loop:
    cmp r12d, KIS_PROBES_PER_PORT
    jae .probe_done

    call kis_send_pulse
    call kis_rdtsc_start

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
    jle  .probe_timeout

    mov  rax, SYS_RECVFROM
    mov  rdi, [raw_fd]
    lea  rsi, [recv_buf]
    mov  edx, 4096
    xor  r10d, r10d
    xor  r8d, r8d
    xor  r9d, r9d
    syscall

    call kis_rdtsc_end
    mov  [kis_probe_samples + r12*8], rax
    mov  byte [kis_timeout_streak], 0
    jmp  .next_sample

.probe_timeout:
    call kis_rdtsc_end
    mov  [kis_probe_samples + r12*8], rax
    inc  byte [kis_timeout_streak]

.next_sample:
    inc r12d
    jmp .probe_loop

.probe_done:
    call kis_trimmed_mean
    mov  [kis_port_impedance], rax
    mov  rbx, rax
    call kis_compute_variance
    call kis_isqrt
    mov  [kis_port_jitter], rax

    mov  rax, [kis_port_impedance]
    mov  rbx, [kis_port_jitter]
    call kis_sjs_lookup

    pop  r12
    pop  rbx
    ret

; ------------------------------------------------------------
; kis_print_result
; Input: ecx = port
; ------------------------------------------------------------
kis_print_result:
    push rcx
    mov  ax, cx
    call append_u16
    lea  rsi, [space_msg]
    mov  edx, space_len
    call buf_write
    lea  rsi, [space_msg]
    call buf_write

    mov  rax, [kis_port_impedance]
    call append_u16
    lea  rsi, [space_msg]
    mov  edx, space_len
    call buf_write

    mov  rax, [kis_port_jitter]
    call append_u16
    lea  rsi, [space_msg]
    mov  edx, space_len
    call buf_write

    movzx eax, word [kis_svc_id]
    cmp  eax, 10
    jbe  .svc_ok
    xor  eax, eax
.svc_ok:
    mov  rsi, [kis_svc_ptrs + rax*8]
    xor  edx, edx
.svc_len:
    cmp  byte [rsi+rdx], 0
    je   .svc_done
    inc  edx
    jmp  .svc_len
.svc_done:
    call buf_write

    movzx eax, byte [kis_confidence]
    call append_u16
    lea  rsi, [kis_pct_msg]
    mov  edx, 1
    call buf_write

    lea  rsi, [newline_msg]
    mov  edx, newline_len
    call buf_write
    pop  rcx
    ret

; ------------------------------------------------------------
; kis_print_summary
; ------------------------------------------------------------
kis_print_summary:
    call color_guard_check
    jz .skip_sum_color
    COLOR_CYAN
.skip_sum_color:
    lea rsi, [kis_sum_hdr]
    call .pstr
    call color_guard_check
    jz .skip_sum_reset
    COLOR_RESET
.skip_sum_reset:
    lea rsi, [kis_sum_closed]
    call .pstr
    mov eax, [kis_count_closed]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [kis_sum_filtered]
    call .pstr
    mov eax, [kis_count_filtered]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [kis_sum_open]
    call .pstr
    mov eax, [kis_count_open]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [kis_sum_heavy]
    call .pstr
    mov eax, [kis_count_heavy]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [kis_sum_virt]
    call .pstr
    mov eax, [kis_count_virt]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [kis_sum_unknown]
    call .pstr
    mov eax, [kis_count_unknown]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write

    cmp byte [kis_fuse_blown], 0
    jne .fuse_done
    call color_guard_check
    jz .skip_fuse_color
    COLOR_GREEN
.skip_fuse_color:
    lea rsi, [kis_fuse_ok_msg]
    call .pstr
    call color_guard_check
    jz .skip_fuse_reset
    COLOR_RESET
.skip_fuse_reset:
.fuse_done:
    ret

.pstr:
    xor edx, edx
.plen:
    cmp byte [rsi+rdx], 0
    je .pdone
    inc edx
    jmp .plen
.pdone:
    call buf_write
    ret

; ------------------------------------------------------------
; kis_init
; ------------------------------------------------------------
kis_init:
    mov byte [kis_enabled], 1
    mov byte [kis_fuse_blown], 0
    mov byte [kis_fuse_reason], 0
    mov byte [kis_recheck_counter], 0
    mov byte [kis_timeout_streak], 0
    mov dword [kis_count_closed], 0
    mov dword [kis_count_filtered], 0
    mov dword [kis_count_open], 0
    mov dword [kis_count_heavy], 0
    mov dword [kis_count_virt], 0
    mov dword [kis_count_unknown], 0
    mov dword [kis_count_total], 0

    call kis_ambient_probe
    mov rax, [kis_ambient_ns]
    mov [kis_baseline_orig], rax
    mov qword [kis_jitter_baseline], 0

    call color_guard_check
    jz .skip_hdr_color
    COLOR_CYAN
.skip_hdr_color:
    lea rsi, [kis_hdr_msg]
    call .pstr
    lea rsi, [kis_hdr_end]
    call .pstr
    call color_guard_check
    jz .skip_hdr_reset
    COLOR_RESET
.skip_hdr_reset:
    lea rsi, [kis_ambient_msg]
    call .pstr
    mov rax, [kis_ambient_ns]
    call append_u16
    lea rsi, [kis_ns_msg]
    mov edx, 2
    call buf_write
    lea rsi, [kis_ttl_msg]
    call .pstr
    movzx eax, byte [kis_ambient_ttl]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write

    lea rsi, [kis_col_hdr]
    call .pstr
    lea rsi, [kis_col_sep]
    call .pstr
    call flush_output
    ret

; ------------------------------------------------------------
; kis_run
; ------------------------------------------------------------
kis_run:
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

.kis_loop:
    cmp  ebx, r14d
    jae  .kis_done

    mov  rdi, rbx
    mov  rsi, r14
    call blackrock_permute
    movzx ecx, word [start_port]
    add  ecx, eax

    call kis_probe_port
    inc  dword [kis_count_total]

    mov rax, [kis_port_impedance]
    cmp rax, 200
    jb .count_closed
    cmp rax, 500
    jb .count_filtered
    cmp rax, 1200
    jb .count_open
    cmp rax, 2500
    jb .count_heavy
    jmp .count_virt
.count_closed:
    inc dword [kis_count_closed]
    jmp .after_count
.count_filtered:
    inc dword [kis_count_filtered]
    jmp .after_count
.count_open:
    inc dword [kis_count_open]
    jmp .after_count
.count_heavy:
    inc dword [kis_count_heavy]
    jmp .after_count
.count_virt:
    inc dword [kis_count_virt]
.after_count:
    call kis_print_result

    call kis_check_fuse
    jnz .kis_sync

    inc ebx
    jmp .kis_loop

.kis_sync:
    call kis_quantum_brake

.kis_done:
    call kis_print_summary
    call flush_output

    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

%endif
