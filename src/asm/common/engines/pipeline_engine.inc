%ifndef PIPELINE_ENGINE_INC
%define PIPELINE_ENGINE_INC 1

engine_pipeline_run:
    call inflight_init

    movzx eax, word [pipe_depth]
    test eax, eax
    jnz .depth_set
    mov word [pipe_depth], 128
.depth_set:

    movzx ecx, word [start_port]
    movzx r15d, word [end_port]
    mov r14d, r15d
    sub r14d, ecx
    inc r14d
    xor ebx, ebx
    mov word [pipe_inflight], 0

.pipe_fill:
    movzx eax, word [pipe_inflight]
    movzx edx, word [pipe_depth]
    cmp eax, edx
    jae .pipe_main
    cmp ebx, r14d
    jae .pipe_main
    call pipeline_send_next
    jmp .pipe_fill

.pipe_main:
    cmp ebx, r14d
    jae .pipe_drain_final
    movzx eax, word [inflight_count]
    test eax, eax
    jz .pipe_done

    mov rax, SYS_EPOLL_WAIT
    mov rdi, [epoll_fd]
    lea rsi, [epoll_out]
    mov edx, 1
    mov r10d, 1000
    syscall
    test rax, rax
    jle .pipe_timeout

    call recv_and_classify
    dec word [pipe_inflight]
    cmp ebx, r14d
    jae .pipe_main
    call pipeline_send_next
    jmp .pipe_main

.pipe_timeout:
    call inflight_check_timeouts
    jmp .pipe_main

.pipe_drain_final:
    movzx eax, word [inflight_count]
    test eax, eax
    jz .pipe_done
    mov rax, SYS_EPOLL_WAIT
    mov rdi, [epoll_fd]
    lea rsi, [epoll_out]
    mov edx, 1
    mov r10d, 2000
    syscall
    test rax, rax
    jle .pipe_drain_timeout
    call recv_and_classify
    dec word [pipe_inflight]
    jmp .pipe_drain_final
.pipe_drain_timeout:
    call inflight_check_timeouts
    jmp .pipe_drain_final
.pipe_done:
    ret

pipeline_send_next:
    push rcx
    push rbx
    mov rdi, rbx
    mov rsi, r14
    call blackrock_permute
    movzx ecx, word [start_port]
    add ecx, eax
    mov ax, cx
    xchg al, ah
    mov [dst_port_be], ax
    call build_packet
    call intel_rtt_start
    call rate_gate
    mov rax, SYS_SENDTO
    mov rdi, [send_fd]
    lea rsi, [packet_buf]
    mov edx, 40
    xor r10d, r10d
    lea r8, [sockaddr_dst]
    mov r9d, 16
    syscall
    push rcx
    call inflight_add
    pop rcx
    inc word [pipe_inflight]
    inc ebx
    pop rbx
    pop rcx
    ret

%endif
