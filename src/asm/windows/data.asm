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

%endif
