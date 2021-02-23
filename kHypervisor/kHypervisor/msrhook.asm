EXTERN HookEnabled:DB
EXTERN ArgTble:DB
EXTERN HookTable:DQ
EXTERN KiSystemCall64Ptr:DQ
EXTERN KiServiceCopyEndPtr:DQ
EXTERN KiSystemServiceRepeatPtr:DQ
EXTERN KeServiceDescriptorTablePtr:DQ
EXTERN KiUmsCallEntry:DQ
EXTERN KiSaveDebugRegisterState:DQ
USERMD_STACK_GS = 10h
KERNEL_STACK_GS = 1A8h
MAX_SYSCALL_INDEX = 1000h

.CODE

; *********************************************************
;
; Determine if the specific syscall should be hooked
;
; if (SyscallHookEnabled[EAX & 0xFFF] == TRUE)
;     jmp KiSystemCall64_Emulate
; else (fall-through)
;     jmp KiSystemCall64
;
; *********************************************************
SyscallEntryPoint PROC
    ;cli                                    ; Disable interrupts
    swapgs                                  ; swap GS base to kernel PCR
    mov         gs:[USERMD_STACK_GS], rsp   ; save user stack pointer

    cmp         rax, MAX_SYSCALL_INDEX      ; Is the index larger than the array size?
    jge         KiSystemCall64              ;

    lea         rsp, offset HookEnabled     ; RSP = &SyscallHookEnabled
    cmp         byte ptr [rsp + rax], 0     ; Is hooking enabled for this index?
    jne         KiSystemCall64_Emulate      ; NE = index is hooked
SyscallEntryPoint ENDP

; *********************************************************
;
; Return to the original NTOSKRNL syscall handler
; (Restore all old registers first)
;
; *********************************************************
KiSystemCall64 PROC
	mov         rsp, gs:[USERMD_STACK_GS]   ; Usermode RSP
	swapgs                                  ; Switch to usermode GS
	jmp         [KiSystemCall64Ptr]         ; Jump back to the old syscall handler
KiSystemCall64 ENDP

; *********************************************************
;
; Emulated routine executed directly after a SYSCALL
; (See: MSR_LSTAR)
;
; *********************************************************
KiSystemCall64_Emulate PROC

    ; NOTE:
    ; First 2 lines are included in SyscallEntryPoint

    mov         rsp, gs:[KERNEL_STACK_GS]   ; set kernel stack pointer
    push        2Bh                         ; push dummy SS selector
    push        qword ptr gs:[10h]          ; push user stack pointer
    push        r11                         ; push previous EFLAGS
    push        33h                         ; push dummy 64-bit CS selector
    push        rcx                         ; push return address
    mov         rcx, r10                    ; set first argument value

    sub         rsp, 8h                     ; allocate dummy error code
    push        rbp                         ; save standard register
    sub         rsp, 158h                   ; allocate fixed frame
    lea         rbp, [rsp+80h]              ; set frame pointer
    mov         [rbp+0C0h], rbx             ; save nonvolatile registers
    mov         [rbp+0C8h], rdi             ;
    mov         [rbp+0D0h], rsi             ;
    mov         byte ptr [rbp-55h], 2h      ; set service active
    mov         rbx, gs:[188h]              ; get current thread address
    prefetchw   byte ptr [rbx+1D8h]         ; prefetch with write intent
    stmxcsr     dword ptr [rbp-54h]         ; save current MXCSR
    ldmxcsr     dword ptr gs:[180h]         ; set default MXCSR
    cmp         byte ptr [rbx+3], 0         ; test if debug enabled
    mov         word ptr [rbp+80h], 0       ; assume debug not enabled
    je          KiSS05                      ; if z, debug not enabled
    mov         [rbp-50h], rax              ; save service argument registers
    mov         [rbp-48h], rcx              ;
    mov         [rbp-40h], rdx              ;
	test        byte ptr [rbx+3],3
    mov         [rbp-38h], r8               ;
    mov         [rbp-30h], r9               ;
	je          a2

	call        [KiSaveDebugRegisterState]
a2:
    test        byte ptr [rbx+3],80h 
	je          a3			
	mov         ecx,0C0000102h
	rdmsr
	shl         rdx,20h
	or          rax,rdx
a3:
	cmp         qword ptr [rbx+0B8h],rax
	je          B0
	cmp         qword ptr [rbx+1B0h],rax
	je          B0
	mov         rdx,qword ptr [rbx+1B8h]
	bts         dword ptr [rbx+4Ch],0Bh
	dec         word ptr [rbx+1C4h]
	mov         qword ptr [rdx+80h],rax
	sti
	call        [KiUmsCallEntry]
	jmp         FA0
B0:
	test        byte ptr [rbx+3],40h
	je          FA0
	lock        bts dword ptr [rbx+100h],8
FA0:
	mov         rax,qword ptr [rbp-50h]
	mov         rcx,qword ptr [rbp-48h]
	mov         rdx,qword ptr [rbp-40h]
	mov         r8,qword ptr [rbp-38h]
	mov         r9,qword ptr [rbp-30h]
	xchg        ax,ax
KiSS05:
	sti
	mov         qword ptr [rbx+1E0h],rcx
	mov         dword ptr [rbx+1F8h],eax

    ;  int         3                           ; FIXME (Syscall with debug registers active)
	;  align       10h
KiSystemCall64_Emulate ENDP

KiSystemServiceStart_Emulate PROC
    mov         [rbx+1D8h], rsp
    mov         edi, eax
    shr         edi, 7
    and         edi, 20h
    and         eax, 0FFFh
KiSystemServiceStart_Emulate ENDP

KiSystemServiceRepeat_Emulate PROC
    ; RAX = [IN ] syscall index
    ; RAX = [OUT] number of parameters
    ; R10 = [OUT] function address
    ; R11 = [I/O] trashed
	lea			r10,[KeServiceDescriptorTablePtr]	
	movsxd		r11,dword ptr [r10+rax*4];

    lea         r10, offset HookTable
	mov         r10, qword ptr [r10 + rax * 8h]

    lea         r11, offset ArgTble
    movzx       rax, byte ptr [r11 + rax]   ; RAX = paramter count
	cmp			edi, 20h
	push		[KiSystemServiceRepeatPtr]
	ret
KiSystemServiceRepeat_Emulate ENDP

END