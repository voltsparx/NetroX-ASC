; ============================================================
; NetroX-ASM Hybrid | Windows hot-path data (WIP extraction)
; ============================================================
%ifndef DATA_WINDOWS_ASM
%define DATA_WINDOWS_ASM 1

SECTION .data
; Keep per-engine tables used in hot-path
; TODO: move exact data tables from legacy windows/main.asm

SECTION .bss
; Keep only hot-path state (defined in scan_core.asm)
packet_buf      resb 2048
recv_buf        resb 4096
sockaddr_dst    resb 16

send_fd         resq 1
sock_fd         resq 1
dst_port        resw 1
dst_port_be     resw 1
src_port_be     resw 1
src_port        resw 1
target_ip       resd 1
scan_mode       resb 1
cidr_mode       resb 1
os_enabled      resb 1
engine_id       resb 1
last_ttl        resb 1
last_win        resw 1
last_rtt_ns     resd 1
host_up_map     resb 1
scan_done_flag  resb 1
retry_cur       resb 1
retry_max       resb 1
resume_index    resq 1
port_list_mode  resb 1
port_list_count resw 1
port_list_buf   resw 256
top_ports_mode  resb 1
top_ports_n     resw 1
top_ports_ptr   resq 1
start_port      resw 1
end_port        resw 1
current_scan_ip resd 1
ip_ranges       resb 128 * 8
ip_range_count  resd 1
stab_enabled    resb 1
stab_sent       resd 1
stab_recv       resd 1
stab_timeout    resd 1

%endif
