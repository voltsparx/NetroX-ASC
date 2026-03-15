; ============================================================
; NetroX-ASM Hybrid | Linux hot-path data (WIP extraction)
; ============================================================
%ifndef DATA_LINUX_ASM
%define DATA_LINUX_ASM 1

SECTION .data
; Keep per-engine tables used in hot-path
; TODO: move exact data tables from legacy main.asm

SECTION .bss
; Hot-path buffers and state referenced by scan_core
packet_buf      resb 2048
recv_buf        resb 4096
epoll_out       resb 64

sockaddr_dst    resb 16
sockaddr_ll     resb 32

send_fd         resq 1
iface_set       resb 1

dst_port        resw 1
dst_port_be     resw 1
src_port_be     resw 1
src_port        resw 1

target_ip       resd 1
scan_mode       resb 1
cidr_mode       resb 1
os_enabled      resb 1

batch_counter   resb 1

retry_cur       resb 1
retry_max       resb 1

filtered_count  resd 1
closed_count    resd 1

stab_enabled    resb 1
stab_sent       resd 1
stab_recv       resd 1
stab_timeout    resd 1

last_ttl        resb 1
last_win        resw 1
last_rtt_ns     resd 1

resume_index    resq 1

%endif
