; ============================================================
; NetroX-ASM Hybrid | Linux network helpers (WIP extraction)
; ============================================================
%ifndef NETWORK_LINUX_ASM
%define NETWORK_LINUX_ASM 1

default rel

SECTION .text
global asm_host_probe
global asm_get_local_ip

asm_get_local_ip:
    xor eax, eax
    ret

asm_host_probe:
    xor eax, eax
    ret

%include "../common/constants.inc"
%include "../common/packet.inc"
%include "../common/checksum.inc"

%endif
