.686p
.model flat,StdCall
option casemap:none
.CODE

; MsrRead (ULONG32 reg );

MsrRead PROC StdCall _reg
	mov		ecx, _reg
	rdmsr				; MSR[ecx] --> edx:eax
	ret
MsrRead ENDP

; MsrWrite (ULONG32 reg , ULONG64 MsrValue );

MsrWrite PROC StdCall _reg, _MsrValue_low,_MsrValue_high
	mov		eax, _MsrValue_low
	mov		edx, _MsrValue_high
	mov		ecx, _reg
	wrmsr
	ret
MsrWrite ENDP

END
