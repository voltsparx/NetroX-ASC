%ifndef SCAN_INC
%define SCAN_INC 1

; ============================================================
; TCP flag-based scan modes
; ============================================================
%define SCAN_SYN        1       ; SYN only            flags=0x02
%define SCAN_ACK        2       ; ACK only            flags=0x10
%define SCAN_FIN        3       ; FIN only            flags=0x01
%define SCAN_NULL       4       ; No flags            flags=0x00
%define SCAN_XMAS       5       ; FIN+PSH+URG         flags=0x29
%define SCAN_WINDOW     6       ; ACK (window inspect) flags=0x10
%define SCAN_MAIMON     7       ; FIN+ACK             flags=0x11

%endif
