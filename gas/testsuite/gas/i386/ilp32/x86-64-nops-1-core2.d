#source: ../nops-1.s
#as: -mtune=core2
#objdump: -drw
#name: x86-64 (ILP32) -mtune=core2 nops 1

.*: +file format .*

Disassembly of section .text:

0+ <nop15>:
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00 	data32 data32 data32 data32 data32 nopw %cs:0x0\(%rax,%rax,1\)

0+10 <nop14>:
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00 	data32 data32 data32 data32 nopw %cs:0x0\(%rax,%rax,1\)

0+20 <nop13>:
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	66 66 66 66 2e 0f 1f 84 00 00 00 00 00 	data32 data32 data32 nopw %cs:0x0\(%rax,%rax,1\)

0+30 <nop12>:
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	66 66 66 2e 0f 1f 84 00 00 00 00 00 	data32 data32 nopw %cs:0x0\(%rax,%rax,1\)

0+40 <nop11>:
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	66 66 2e 0f 1f 84 00 00 00 00 00 	data32 nopw %cs:0x0\(%rax,%rax,1\)

0+50 <nop10>:
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	66 2e 0f 1f 84 00 00 00 00 00 	nopw   %cs:0x0\(%rax,%rax,1\)

0+60 <nop9>:
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	66 0f 1f 84 00 00 00 00 00 	nopw   0x0\(%rax,%rax,1\)

0+70 <nop8>:
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	0f 1f 84 00 00 00 00 00 	nopl   0x0\(%rax,%rax,1\)

0+80 <nop7>:
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	0f 1f 80 00 00 00 00 	nopl   0x0\(%rax\)

0+90 <nop6>:
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	66 0f 1f 44 00 00    	nopw   0x0\(%rax,%rax,1\)

0+a0 <nop5>:
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	0f 1f 44 00 00       	nopl   0x0\(%rax,%rax,1\)

0+b0 <nop4>:
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	0f 1f 40 00          	nopl   0x0\(%rax\)

0+c0 <nop3>:
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	0f 1f 00             	nopl   \(%rax\)

0+d0 <nop2>:
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	90                   	nop
[ 	]*[a-f0-9]+:	66 90                	xchg   %ax,%ax
#pass
