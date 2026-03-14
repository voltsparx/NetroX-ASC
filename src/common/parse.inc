; parse_ip
; rdi -> null-terminated IPv4 string
; returns eax = host-order IPv4, or 0 on error
parse_ip:
    xor eax, eax
    xor r8d, r8d
    xor r9d, r9d

.parse_ip_loop:
    movzx ebx, byte [rdi]
    cmp bl, 0
    je .parse_ip_last
    cmp bl, '.'
    je .parse_ip_store
    sub bl, '0'
    cmp bl, 9
    ja .parse_ip_invalid
    imul r8d, r8d, 10
    add r8d, ebx
    inc rdi
    jmp .parse_ip_loop

.parse_ip_store:
    cmp r8d, 255
    ja .parse_ip_invalid
    mov ebx, r8d
    mov ecx, r9d
    shl ecx, 3
    shl ebx, cl
    or eax, ebx
    inc r9d
    xor r8d, r8d
    inc rdi
    jmp .parse_ip_loop

.parse_ip_last:
    cmp r8d, 255
    ja .parse_ip_invalid
    cmp r9d, 3
    jne .parse_ip_invalid
    mov ebx, r8d
    mov ecx, r9d
    shl ecx, 3
    shl ebx, cl
    or eax, ebx
    ret

.parse_ip_invalid:
    xor eax, eax
    ret

; parse_port
; rdi -> null-terminated port string
; returns ax = host-order port, or 0 on error
parse_port:
    xor eax, eax

.parse_port_loop:
    movzx ebx, byte [rdi]
    cmp bl, 0
    je .parse_port_done
    sub bl, '0'
    cmp bl, 9
    ja .parse_port_invalid
    imul eax, eax, 10
    add eax, ebx
    cmp eax, 65535
    ja .parse_port_invalid
    inc rdi
    jmp .parse_port_loop

.parse_port_done:
    ret

.parse_port_invalid:
    xor eax, eax
    ret

; parse_port_range
; rdi -> null-terminated string: "N" or "N-M"
; returns ax = start port, dx = end port; ax=0 on error
parse_port_range:
    xor eax, eax
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    xor ecx, ecx

.parse_range_loop:
    movzx ebx, byte [rdi]
    cmp bl, 0
    je .parse_range_done
    cmp bl, '-'
    je .parse_range_dash
    sub bl, '0'
    cmp bl, 9
    ja .parse_range_invalid
    cmp ecx, 0
    jne .parse_range_add_end
    imul eax, eax, 10
    add eax, ebx
    inc r8d
    cmp eax, 65535
    ja .parse_range_invalid
    jmp .parse_range_next

.parse_range_add_end:
    imul edx, edx, 10
    add edx, ebx
    inc r9d
    cmp edx, 65535
    ja .parse_range_invalid
    jmp .parse_range_next

.parse_range_dash:
    cmp ecx, 0
    jne .parse_range_invalid
    mov ecx, 1
    jmp .parse_range_next

.parse_range_next:
    inc rdi
    jmp .parse_range_loop

.parse_range_done:
    cmp r8d, 0
    je .parse_range_invalid
    cmp ecx, 0
    je .parse_range_single
    cmp r9d, 0
    je .parse_range_invalid
    test eax, eax
    jz .parse_range_invalid
    test edx, edx
    jz .parse_range_invalid
    cmp edx, eax
    jb .parse_range_invalid
    ret

.parse_range_single:
    test eax, eax
    jz .parse_range_invalid
    mov edx, eax
    ret

.parse_range_invalid:
    xor eax, eax
    xor edx, edx
    ret
