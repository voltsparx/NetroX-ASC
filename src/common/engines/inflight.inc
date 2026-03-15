%ifndef INFLIGHT_INC
%define INFLIGHT_INC 1

inflight_init:
    mov qword [inflight_head], 0
    mov qword [inflight_tail], 0
    mov qword [inflight_count], 0
    mov rax, [tsc_hz]
    shl rax, 1
    mov [inflight_timeout_cy], rax
    ret

inflight_add:
    push rax
    push rbx
    push rdx
    movzx eax, word [inflight_count]
    cmp eax, INFLIGHT_SIZE
    jae .full
    movzx ebx, word [inflight_head]
    mov [inflight_ports + rbx*2], cx
    rdtsc
    mov [inflight_tsc_lo + rbx*4], eax
    inc bx
    cmp bx, INFLIGHT_SIZE
    jb .no_wrap
    xor bx, bx
.no_wrap:
    mov [inflight_head], bx
    inc word [inflight_count]
.full:
    pop rdx
    pop rbx
    pop rax
    ret

inflight_remove:
    push rax
    push rbx
    push rcx
    push rdx
    movzx edx, word [inflight_tail]
    movzx eax, word [inflight_count]
    test eax, eax
    jz .not_found
    mov r8d, eax
.search:
    movzx ebx, word [inflight_ports + rdx*2]
    cmp bx, cx
    jne .next_slot
    mov word [inflight_ports + rdx*2], 0
    dec word [inflight_count]
    jmp .found
.next_slot:
    inc edx
    cmp edx, INFLIGHT_SIZE
    jb .no_wrap2
    xor edx, edx
.no_wrap2:
    dec r8d
    jnz .search
.not_found:
.found:
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret

inflight_check_timeouts:
    push rax
    push rbx
    push rcx
    push rdx
    push r8
    rdtsc
    mov r8d, eax
    xor edx, edx
.check_loop:
    cmp edx, INFLIGHT_SIZE
    jae .check_done
    movzx ecx, word [inflight_ports + rdx*2]
    test cx, cx
    jz .check_next
    mov eax, r8d
    sub eax, [inflight_tsc_lo + rdx*4]
    mov rbx, [inflight_timeout_cy]
    cmp rax, rbx
    jb .check_next
    push rdx
    call inflight_remove
    pop rdx
.check_next:
    inc edx
    jmp .check_loop
.check_done:
    pop r8
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret

%endif
