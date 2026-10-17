; elf2exe3 68k startup for WarpOS programs (docs/spec.md section 8)
;
; Assemble: vasmm68k_mot -Fhunk -nosym -o wosstart.o wosstart.s
;
; Runs the PPC program with the Elf2Exe2 register contract:
;   r3 (d0) = DOS argument line, newline at the end, no program name
;   r4 (d1) = PowerPCBase
;   r5 (a0) = WBStartup message, or 0 from the CLI
;   r6 (a1) = length of the argument line
;   r2 (a4) = _LinkerDB (page table + 0x8000, set by elf2exe3)
; and returns the PPC r3 (PP_Regs[0]) as the exit code.
; Everything lives on the stack, so the program can be made resident.

        xref    _LinkerDB
        xref    __ppc_startup
        xdef    __ppc_stacksize

_LVOForbid       equ -132
_LVOFindTask     equ -294
_LVOGetMsg       equ -372
_LVOReplyMsg     equ -378
_LVOWaitPort     equ -384
_LVOCloseLibrary equ -414
_LVOOpenLibrary  equ -552
_LVOWrite        equ -48
_LVOOutput       equ -60
_LVORunPPC       equ -30

pr_MsgPort       equ 92
pr_CLI           equ 172

PP_CODE          equ 0
PP_STACKSIZE     equ 16
PP_REGS          equ 20
PP_SIZE          equ 144

        section startup,code

start:
        movem.l d2-d7/a2-a6,-(sp)
        move.l  a0,a2                   ; argument line
        move.l  d0,d2                   ; its length
        moveq   #20,d7                  ; exit code if anything fails
        moveq   #0,d3                   ; WBStartup message
        move.l  4.w,a6

        sub.l   a1,a1
        jsr     _LVOFindTask(a6)
        move.l  d0,a3
        tst.l   pr_CLI(a3)
        bne     .cli
        lea     pr_MsgPort(a3),a0
        jsr     _LVOWaitPort(a6)
        lea     pr_MsgPort(a3),a0
        jsr     _LVOGetMsg(a6)
        move.l  d0,d3
        lea     emptyline(pc),a2        ; no arguments from Workbench
        moveq   #1,d2
.cli:
        lea     ppcname(pc),a1
        moveq   #14,d0
        jsr     _LVOOpenLibrary(a6)
        move.l  d0,a5
        tst.l   d0
        bne     .run

        tst.l   d3                      ; no powerpc.library
        bne     .done                   ; nowhere to print from Workbench
        lea     dosname(pc),a1
        moveq   #0,d0
        jsr     _LVOOpenLibrary(a6)
        tst.l   d0
        beq     .done
        move.l  d0,a6
        jsr     _LVOOutput(a6)
        move.l  d0,d1
        beq     .closedos
        lea     errmsg(pc),a0
        move.l  a0,d2
        moveq   #errend-errmsg,d3
        jsr     _LVOWrite(a6)
        moveq   #0,d3
.closedos:
        move.l  a6,a1
        move.l  4.w,a6
        jsr     _LVOCloseLibrary(a6)
        bra     .done

.run:
        lea     -PP_SIZE(sp),sp
        move.l  sp,a0
        moveq   #PP_SIZE/4-1,d0
.clear: clr.l   (a0)+
        dbf     d0,.clear
        move.l  #__ppc_startup,PP_CODE(sp)
        move.l  __ppc_stacksize(pc),PP_STACKSIZE(sp)
        move.l  a2,PP_REGS+0*4(sp)      ; d0 -> r3
        move.l  a5,PP_REGS+1*4(sp)      ; d1 -> r4
        move.l  d3,PP_REGS+8*4(sp)      ; a0 -> r5
        move.l  d2,PP_REGS+9*4(sp)      ; a1 -> r6
        move.l  #_LinkerDB,PP_REGS+12*4(sp) ; a4 -> r2
        move.l  sp,a0
        move.l  a5,a6
        jsr     _LVORunPPC(a6)
        tst.l   d0                      ; PPERR_SUCCESS?
        bne     .failed
        move.l  PP_REGS(sp),d7
.failed:
        lea     PP_SIZE(sp),sp
        move.l  a5,a1
        move.l  4.w,a6
        jsr     _LVOCloseLibrary(a6)

.done:
        tst.l   d3
        beq     .exit
        move.l  4.w,a6
        jsr     _LVOForbid(a6)          ; reply after we can no longer run
        move.l  d3,a1
        jsr     _LVOReplyMsg(a6)
.exit:
        move.l  d7,d0
        movem.l (sp)+,d2-d7/a2-a6
        rts

        cnop    0,4
__ppc_stacksize:
        dc.l    0                       ; PP_StackSize, set by elf2exe3 --stack

ppcname:   dc.b    "powerpc.library",0
dosname:   dc.b    "dos.library",0
emptyline: dc.b    10,0
errmsg:    dc.b    "This program needs powerpc.library (WarpOS)",10
errend:
        even
