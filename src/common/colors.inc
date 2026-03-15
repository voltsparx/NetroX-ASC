%ifndef COLORS_INC
%define COLORS_INC 1

SECTION .rodata

clr_red:      db 0x1B, "[91m", 0
clr_yellow:   db 0x1B, "[93m", 0
clr_green:    db 0x1B, "[92m", 0
clr_cyan:     db 0x1B, "[36m", 0
clr_white:    db 0x1B, "[97m", 0
clr_gray:     db 0x1B, "[37m", 0
clr_reset:    db 0x1B, "[0m", 0

clr_red_len    equ 5
clr_yellow_len equ 5
clr_green_len  equ 5
clr_cyan_len   equ 5
clr_white_len  equ 5
clr_gray_len   equ 5
clr_reset_len  equ 4

SECTION .bss
color_enabled   resb 1

SECTION .text

color_write:
    cmp  byte [color_enabled], 0
    je   .cw_skip
    call buf_write
.cw_skip:
    ret

%macro COLOR_RED 0
    lea  rsi, [clr_red]
    mov  edx, clr_red_len
    call color_write
%endmacro

%macro COLOR_YELLOW 0
    lea  rsi, [clr_yellow]
    mov  edx, clr_yellow_len
    call color_write
%endmacro

%macro COLOR_GREEN 0
    lea  rsi, [clr_green]
    mov  edx, clr_green_len
    call color_write
%endmacro

%macro COLOR_CYAN 0
    lea  rsi, [clr_cyan]
    mov  edx, clr_cyan_len
    call color_write
%endmacro

%macro COLOR_WHITE 0
    lea  rsi, [clr_white]
    mov  edx, clr_white_len
    call color_write
%endmacro

%macro COLOR_GRAY 0
    lea  rsi, [clr_gray]
    mov  edx, clr_gray_len
    call color_write
%endmacro

%macro COLOR_RESET 0
    lea  rsi, [clr_reset]
    mov  edx, clr_reset_len
    call color_write
%endmacro

%endif
