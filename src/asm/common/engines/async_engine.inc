%ifndef ASYNC_ENGINE_INC
%define ASYNC_ENGINE_INC 1

async_drain_responses:
    mov r12d, ASYNC_RECV_MAX
.drain_loop:
    test r12d, r12d
    jz .drain_done
    mov rax, SYS_EPOLL_WAIT
    mov rdi, [epoll_fd]
    lea rsi, [epoll_out]
    mov edx, 1
    xor r10d, r10d
    syscall
    test rax, rax
    jle .drain_done
    call recv_and_classify
    dec r12d
    jmp .drain_loop
.drain_done:
    ret

engine_async_run:
    call inflight_init
    movzx ecx, word [start_port]
    movzx r15d, word [end_port]
    mov r14d, r15d
    sub r14d, ecx
    inc r14d
    xor ebx, ebx

.async_main_loop:
    cmp ebx, r14d
    jae .async_harvest

    xor r13d, r13d
.async_burst_loop:
    cmp r13d, ASYNC_BURST
    jae .async_drain
    cmp ebx, r14d
    jae .async_drain

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

    inc ebx
    inc r13d
    jmp .async_burst_loop

.async_drain:
    call async_drain_responses
    call inflight_check_timeouts
    call stabilize_step
    jmp .async_main_loop

.async_harvest:
    mov r12d, 3000
.harvest_loop:
    movzx eax, word [inflight_count]
    test eax, eax
    jz .async_done
    test r12d, r12d
    jz .async_done
    mov rax, SYS_EPOLL_WAIT
    mov rdi, [epoll_fd]
    lea rsi, [epoll_out]
    mov edx, 1
    mov r10d, 100
    syscall
    test rax, rax
    jg .harvest_recv
    call inflight_check_timeouts
    jmp .harvest_next
.harvest_recv:
    call recv_and_classify
.harvest_next:
    dec r12d
    jmp .harvest_loop
.async_done:
    ret

%endif
