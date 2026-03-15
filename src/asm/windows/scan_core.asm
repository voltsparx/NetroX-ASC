; ============================================================
; NetroX-ASM Hybrid | Windows hot-path scan core (WIP extraction)
; ============================================================
%ifndef SCAN_CORE_WINDOWS_ASM
%define SCAN_CORE_WINDOWS_ASM 1

default rel

SECTION .bss
cfg_ptr         resq 1
tsc_hz          resq 1

SECTION .text
global asm_scan_init
global asm_scan_run
global asm_get_local_ip
global asm_get_tsc_hz
global asm_scan_cleanup

asm_scan_init:
    mov [cfg_ptr], rdi
    xor eax, eax
    ret

asm_scan_run:
    xor eax, eax
    ret

asm_get_local_ip:
    xor eax, eax
    ret

asm_get_tsc_hz:
    mov rax, [tsc_hz]
    ret

asm_scan_cleanup:
    ret

%include "../common/constants.inc"
%include "../common/scan.inc"
%include "../common/packet.inc"
%include "../common/checksum.inc"
%include "../common/engine.inc"
%include "../common/engines/dispatch.inc"

%endif
