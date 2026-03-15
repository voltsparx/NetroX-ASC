; engine.inc - compatibility stub
; All engine logic has been moved to src/common/engines/
; This file exists only so existing %include references
; in main.asm files continue to work without modification.

%ifndef ENGINE_INC
%define ENGINE_INC 1

%include "engines/dispatch.inc"

%endif
