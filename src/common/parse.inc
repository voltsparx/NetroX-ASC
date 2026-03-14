; ============================================================
; parse.inc  -  all argument and input parsing routines
; ============================================================

%include "scan.inc"

; ------------------------------------------------------------
; parse_ip
; Input:  rdi -> null-terminated IPv4 dotted-decimal string
; Output: eax = 32-bit IP in network byte order, 0 on error
; ------------------------------------------------------------
parse_ip:
    push rbx
    xor  eax, eax
    xor  r8d, r8d
    xor  r9d, r9d
.loop:
    movzx ebx, byte [rdi]
    cmp   bl, 0
    je    .last
    cmp   bl, '.'
    je    .store
    sub   bl, '0'
    cmp   bl, 9
    ja    .invalid
    imul  r8d, r8d, 10
    add   r8d, ebx
    inc   rdi
    jmp   .loop
.store:
    cmp   r8d, 255
    ja    .invalid
    mov   ebx, r8d
    mov   ecx, r9d
    shl   ecx, 3
    shl   ebx, cl
    or    eax, ebx
    inc   r9d
    xor   r8d, r8d
    inc   rdi
    jmp   .loop
.last:
    cmp   r8d, 255
    ja    .invalid
    cmp   r9d, 3
    jne   .invalid
    mov   ebx, r8d
    mov   ecx, r9d
    shl   ecx, 3
    shl   ebx, cl
    or    eax, ebx
    pop   rbx
    ret
.invalid:
    xor   eax, eax
    pop   rbx
    ret

; ------------------------------------------------------------
; parse_port
; Input:  rdi -> null-terminated decimal string
; Output: ax = port (1-65535), or 0 on error
; ------------------------------------------------------------
parse_port:
    push rbx
    xor  eax, eax
.loop:
    movzx ebx, byte [rdi]
    cmp   bl, 0
    je    .done
    sub   bl, '0'
    cmp   bl, 9
    ja    .invalid
    imul  eax, eax, 10
    add   eax, ebx
    cmp   eax, 65535
    ja    .invalid
    inc   rdi
    jmp   .loop
.done:
    pop  rbx
    ret
.invalid:
    xor  eax, eax
    pop  rbx
    ret

; ------------------------------------------------------------
; parse_port_range
; Input:  rdi -> "N" or "N-M"
; Output: ax = start, dx = end  (both 0 on error)
; ------------------------------------------------------------
parse_port_range:
    push rbx
    xor  eax, eax
    xor  edx, edx
    xor  r8d, r8d
    xor  r9d, r9d
    xor  ecx, ecx
.loop:
    movzx ebx, byte [rdi]
    cmp   bl, 0
    je    .done
    cmp   bl, '-'
    je    .dash
    sub   bl, '0'
    cmp   bl, 9
    ja    .invalid
    cmp   ecx, 0
    jne   .add_end
    imul  eax, eax, 10
    add   eax, ebx
    inc   r8d
    cmp   eax, 65535
    ja    .invalid
    jmp   .next
.add_end:
    imul  edx, edx, 10
    add   edx, ebx
    inc   r9d
    cmp   edx, 65535
    ja    .invalid
    jmp   .next
.dash:
    cmp   ecx, 0
    jne   .invalid
    mov   ecx, 1
.next:
    inc   rdi
    jmp   .loop
.done:
    cmp   r8d, 0
    je    .invalid
    cmp   ecx, 0
    je    .single
    cmp   r9d, 0
    je    .invalid
    test  eax, eax
    jz    .invalid
    test  edx, edx
    jz    .invalid
    cmp   edx, eax
    jb    .invalid
    pop   rbx
    ret
.single:
    test  eax, eax
    jz    .invalid
    mov   edx, eax
    pop   rbx
    ret
.invalid:
    xor  eax, eax
    xor  edx, edx
    pop  rbx
    ret

; ------------------------------------------------------------
; parse_u32
; Input:  rdi -> null-terminated decimal string
; Output: eax = value, or 0 on error
; ------------------------------------------------------------
parse_u32:
    push rbx
    xor  eax, eax
.loop:
    movzx ebx, byte [rdi]
    cmp   bl, 0
    je    .done
    sub   bl, '0'
    cmp   bl, 9
    ja    .invalid
    imul  eax, eax, 10
    add   eax, ebx
    inc   rdi
    jmp   .loop
.done:
    test  eax, eax
    jz    .invalid
    pop   rbx
    ret
.invalid:
    xor  eax, eax
    pop  rbx
    ret

; ------------------------------------------------------------
; parse_scan_mode
; Input:  rdi -> null-terminated mode string
; Output: al = SCAN_xxx constant, or 0 on error
; Recognised: syn ack fin null xmas window maimon
; ------------------------------------------------------------
parse_scan_mode:
    push rbx
    mov  al, [rdi]
    ; syn
    cmp  al, 's'
    jne  .ack
    cmp  byte [rdi+1], 'y'
    jne  .ack
    cmp  byte [rdi+2], 'n'
    jne  .ack
    cmp  byte [rdi+3], 0
    jne  .ack
    mov  al, SCAN_SYN
    pop  rbx
    ret
.ack:
    cmp  al, 'a'
    jne  .fin
    cmp  byte [rdi+1], 'c'
    jne  .fin
    cmp  byte [rdi+2], 'k'
    jne  .fin
    cmp  byte [rdi+3], 0
    jne  .fin
    mov  al, SCAN_ACK
    pop  rbx
    ret
.fin:
    cmp  al, 'f'
    jne  .null
    cmp  byte [rdi+1], 'i'
    jne  .null
    cmp  byte [rdi+2], 'n'
    jne  .null
    cmp  byte [rdi+3], 0
    jne  .null
    mov  al, SCAN_FIN
    pop  rbx
    ret
.null:
    cmp  al, 'n'
    jne  .xmas
    cmp  byte [rdi+1], 'u'
    jne  .xmas
    cmp  byte [rdi+2], 'l'
    jne  .xmas
    cmp  byte [rdi+3], 'l'
    jne  .xmas
    cmp  byte [rdi+4], 0
    jne  .xmas
    mov  al, SCAN_NULL
    pop  rbx
    ret
.xmas:
    cmp  al, 'x'
    jne  .window
    cmp  byte [rdi+1], 'm'
    jne  .window
    cmp  byte [rdi+2], 'a'
    jne  .window
    cmp  byte [rdi+3], 's'
    jne  .window
    cmp  byte [rdi+4], 0
    jne  .window
    mov  al, SCAN_XMAS
    pop  rbx
    ret
.window:
    cmp  al, 'w'
    jne  .maimon
    cmp  byte [rdi+1], 'i'
    jne  .maimon
    cmp  byte [rdi+2], 'n'
    jne  .maimon
    cmp  byte [rdi+3], 'd'
    jne  .maimon
    cmp  byte [rdi+4], 'o'
    jne  .maimon
    cmp  byte [rdi+5], 'w'
    jne  .maimon
    cmp  byte [rdi+6], 0
    jne  .maimon
    mov  al, SCAN_WINDOW
    pop  rbx
    ret
.maimon:
    cmp  al, 'm'
    jne  .invalid
    cmp  byte [rdi+1], 'a'
    jne  .udp
    cmp  byte [rdi+2], 'i'
    jne  .udp
    cmp  byte [rdi+3], 'm'
    jne  .udp
    cmp  byte [rdi+4], 'o'
    jne  .udp
    cmp  byte [rdi+5], 'n'
    jne  .udp
    cmp  byte [rdi+6], 0
    jne  .invalid
    mov  al, SCAN_MAIMON
    pop  rbx
    ret
.invalid:
    xor  eax, eax
    pop  rbx
    ret
