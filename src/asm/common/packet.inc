%ifndef PACKET_INC
%define PACKET_INC 1

%include "scan.inc"

; ============================================================
; init_packet_template
;
; Zeroes packet_buf (60 bytes) and fills in the static fields
; that never change during a scan:
;   IP:  version/IHL, DSCP, DF flag, TTL=64, proto=TCP,
;        source IP, dest IP, initial checksum
;   TCP: source port, initial seq, data offset, SYN flag,
;        window size
;
; Called once before the scan loop.
; Depends on: packet_buf, source_ip, target_ip, src_port_be
; ============================================================
init_packet_template:
    ; Zero the entire 60-byte buffer
    lea  rdi, [packet_buf]
    xor  rax, rax
    mov  rcx, 60/8
    rep  stosq

    ; --- IP header (bytes 0-19) ---
    mov  byte [packet_buf+0],  0x45    ; Version=4, IHL=5
    mov  byte [packet_buf+1],  0x00    ; DSCP/ECN = 0
    mov  word [packet_buf+2],  0x2800  ; Total length = 40 (big-endian)
    mov  word [packet_buf+4],  0x3412  ; IP ID = 0x1234 (initial, bumped per packet)
    mov  word [packet_buf+6],  0x0040  ; Flags=DF(0x40), Fragment offset=0
    mov  byte [packet_buf+8],  64      ; TTL = 64
    mov  byte [packet_buf+9],  6       ; Protocol = TCP
    mov  word [packet_buf+10], 0       ; Checksum placeholder (computed below)
    mov  eax, [source_ip]
    mov  [packet_buf+12], eax          ; Source IP
    mov  eax, [target_ip]
    mov  [packet_buf+16], eax          ; Destination IP

    ; Compute initial IP checksum
    lea  rdi, [packet_buf]
    call ip_checksum
    mov  [packet_buf+10], ax

    ; --- TCP header (bytes 20-39) ---
    mov  ax, [src_port_be]
    mov  [packet_buf+20], ax           ; Source port (big-endian)
    mov  dword [packet_buf+24], 0x78563412  ; Seq number (arbitrary, non-zero)
    mov  dword [packet_buf+28], 0      ; ACK number = 0
    mov  byte [packet_buf+32], 0x50   ; Data offset = 5 (20 bytes), reserved = 0
    mov  byte [packet_buf+33], 0x02   ; Flags = SYN (default)
    mov  word [packet_buf+34], 0xFFFF ; Window size = 65535
    mov  word [packet_buf+36], 0      ; Checksum placeholder
    mov  word [packet_buf+38], 0      ; Urgent pointer = 0
    ret

%endif
