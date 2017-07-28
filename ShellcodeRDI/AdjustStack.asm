; Author:       Matthew Graeber (@mattifestation)
; License:      BSD 3-Clause
; Syntax:       MASM
; Build Syntax: ml64 /c /Cx AdjustStack.asm
; Output:       AdjustStack.obj
; Notes: I really wanted to avoid having this external dependency but I couldn't
; come up with any other way to guarantee 16-byte stack alignment in 64-bit
; shellcode written in C.

EXTRN	ExecutePayload:PROC
PUBLIC  AlignRSP			; Marking AlignRSP as PUBLIC allows for the function
					; to be called as an extern in our C code.

_TEXT	SEGMENT

; AlignRSP is a simple call stub that ensures that the stack is 16-byte aligned prior
; to calling the entry point of the payload. This is necessary because 64-bit functions
; in Windows assume that they were called with 16-byte stack alignment. When amd64
; shellcode is executed, you can't be assured that you stack is 16-byte aligned. For example,
; if your shellcode lands with 8-byte stack alignment, any call to a Win32 function will likely
; crash upon calling any ASM instruction that utilizes XMM registers (which require 16-byte)
; alignment.

AlignRSP PROC
	push	rsi				; Preserve RSI since we're stomping on it
	mov		rsi, rsp		; Save the value of RSP so it can be restored
	and		rsp, 0FFFFFFFFFFFFFFF0h	; Align RSP to 16 bytes
	sub		rsp, 020h		; Allocate homing space for ExecutePayload
	call	ExecutePayload	; Call the entry point of the payload
	mov		rsp, rsi		; Restore the original value of RSP
	pop		rsi				; Restore RSI
	ret						; Return to caller
AlignRSP ENDP

_TEXT	ENDS

END