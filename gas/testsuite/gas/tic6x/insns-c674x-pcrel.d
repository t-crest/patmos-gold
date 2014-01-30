#objdump: -dr --prefix-addresses --show-raw-insn
#name: C674x instructions generating PC-relative relocations
#as: -march=c674x -mlittle-endian

.*: *file format elf32-tic6x-le


Disassembly of section \.text:
[ \t]*\.\.\.
0+1c <[^>]*> 00806162[ \t]+addkpc \.S2 00000000 <f>,b1,3
0+20 <[^>]*> a1f9e162[ \t]+\[a2\] addkpc \.S2 00000004 <f\+0x4>,b3,7
0+24 <[^>]*> 02030162[ \t]+addkpc \.S2 0000002c <g>,b4,0
0+28 <[^>]*> 02808162[ \t]+addkpc \.S2 00000020 <f\+0x20>,b5,4
[ \t]*28: R_C6000_PCR_S7[ \t]+ext1\+0x8
[ \t]*\.\.\.
[ \t]*\.\.\.
0+48 <[^>]*> 00000012[ \t]+b \.S2 00000040 <f2>
[ \t]*48: R_C6000_PCR_S21[ \t]+ext3\+0x4
0+4c <[^>]*> 00000010[ \t]+b \.S1 00000040 <f2>
[ \t]*4c: R_C6000_PCR_S21[ \t]+ext2
0+50 <[^>]*> 00000012[ \t]+b \.S2 00000040 <f2>
[ \t]*50: R_C6000_PCR_S21[ \t]+nrp
0+54 <[^>]*> 00000012[ \t]+b \.S2 00000040 <f2>
[ \t]*54: R_C6000_PCR_S21[ \t]+irp
0+58 <[^>]*> 00000010[ \t]+b \.S1 00000040 <f2>
[ \t]*58: R_C6000_PCR_S21[ \t]+a1
0+5c <[^>]*> 00000012[ \t]+b \.S2 00000040 <f2>
0+60 <[^>]*> 6ffffc92[ \t]+\[b2\] b \.S2 00000044 <f2\+0x4>
0+64 <[^>]*> 00000192[ \t]+b \.S2 0000006c <g2>
0+68 <[^>]*> 00000012[ \t]+b \.S2 00000060 <f2\+0x20>
[ \t]*68: R_C6000_PCR_S21[ \t]+b1
[ \t]*\.\.\.
[ \t]*\.\.\.
0+88 <[^>]*> 00000012[ \t]+b \.S2 00000080 <f3>
[ \t]*88: R_C6000_PCR_S21[ \t]+ext3\+0x4
0+8c <[^>]*> 00000010[ \t]+b \.S1 00000080 <f3>
[ \t]*8c: R_C6000_PCR_S21[ \t]+ext2
0+90 <[^>]*> 00000012[ \t]+b \.S2 00000080 <f3>
[ \t]*90: R_C6000_PCR_S21[ \t]+nrp
0+94 <[^>]*> 00000012[ \t]+b \.S2 00000080 <f3>
[ \t]*94: R_C6000_PCR_S21[ \t]+irp
0+98 <[^>]*> 00000010[ \t]+b \.S1 00000080 <f3>
[ \t]*98: R_C6000_PCR_S21[ \t]+a1
0+9c <[^>]*> 00000012[ \t]+b \.S2 00000080 <f3>
0+a0 <[^>]*> 6ffffc92[ \t]+\[b2\] b \.S2 00000084 <f3\+0x4>
0+a4 <[^>]*> 00000192[ \t]+b \.S2 000000ac <g3>
0+a8 <[^>]*> 00000012[ \t]+b \.S2 000000a0 <f3\+0x20>
[ \t]*a8: R_C6000_PCR_S21[ \t]+b1
[ \t]*\.\.\.
[ \t]*\.\.\.
0+c8 <[^>]*> 01001022[ \t]+bdec \.S2 000000c0 <f4>,b2
[ \t]*c8: R_C6000_PCR_S10[ \t]+ext3\+0x4
0+cc <[^>]*> 01001020[ \t]+bdec \.S1 000000c0 <f4>,a2
[ \t]*cc: R_C6000_PCR_S10[ \t]+ext2
0+d0 <[^>]*> 01001022[ \t]+bdec \.S2 000000c0 <f4>,b2
[ \t]*d0: R_C6000_PCR_S10[ \t]+nrp
0+d4 <[^>]*> 01001022[ \t]+bdec \.S2 000000c0 <f4>,b2
[ \t]*d4: R_C6000_PCR_S10[ \t]+irp
0+d8 <[^>]*> 01001020[ \t]+bdec \.S1 000000c0 <f4>,a2
[ \t]*d8: R_C6000_PCR_S10[ \t]+a1
0+dc <[^>]*> 01001022[ \t]+bdec \.S2 000000c0 <f4>,b2
0+e0 <[^>]*> 917f3022[ \t]+\[!a1\] bdec \.S2 000000c4 <f4\+0x4>,b2
0+e4 <[^>]*> 01007022[ \t]+bdec \.S2 000000ec <g4>,b2
0+e8 <[^>]*> 01001022[ \t]+bdec \.S2 000000e0 <f4\+0x20>,b2
[ \t]*e8: R_C6000_PCR_S10[ \t]+b1
[ \t]*\.\.\.
[ \t]*\.\.\.
0+108 <[^>]*> 01000022[ \t]+bpos \.S2 00000100 <f5>,b2
[ \t]*108: R_C6000_PCR_S10[ \t]+ext3\+0x4
0+10c <[^>]*> 01000020[ \t]+bpos \.S1 00000100 <f5>,a2
[ \t]*10c: R_C6000_PCR_S10[ \t]+ext2
0+110 <[^>]*> 01000022[ \t]+bpos \.S2 00000100 <f5>,b2
[ \t]*110: R_C6000_PCR_S10[ \t]+nrp
0+114 <[^>]*> 01000022[ \t]+bpos \.S2 00000100 <f5>,b2
[ \t]*114: R_C6000_PCR_S10[ \t]+irp
0+118 <[^>]*> 01000020[ \t]+bpos \.S1 00000100 <f5>,a2
[ \t]*118: R_C6000_PCR_S10[ \t]+a1
0+11c <[^>]*> 01000022[ \t]+bpos \.S2 00000100 <f5>,b2
0+120 <[^>]*> 517f2022[ \t]+\[!b1\] bpos \.S2 00000104 <f5\+0x4>,b2
0+124 <[^>]*> 01006022[ \t]+bpos \.S2 0000012c <g5>,b2
0+128 <[^>]*> 01000022[ \t]+bpos \.S2 00000120 <f5\+0x20>,b2
[ \t]*128: R_C6000_PCR_S10[ \t]+b1
[ \t]*\.\.\.
[ \t]*\.\.\.
0+148 <[^>]*> 00000122[ \t]+bnop \.S2 00000140 <f6>,0
[ \t]*148: R_C6000_PCR_S12[ \t]+ext3\+0x4
0+14c <[^>]*> 00002120[ \t]+bnop \.S1 00000140 <f6>,1
[ \t]*14c: R_C6000_PCR_S12[ \t]+ext2
0+150 <[^>]*> 00004120[ \t]+bnop \.S1 00000140 <f6>,2
[ \t]*150: R_C6000_PCR_S12[ \t]+nrp
0+154 <[^>]*> 00006122[ \t]+bnop \.S2 00000140 <f6>,3
[ \t]*154: R_C6000_PCR_S12[ \t]+irp
0+158 <[^>]*> 00008120[ \t]+bnop \.S1 00000140 <f6>,4
[ \t]*158: R_C6000_PCR_S12[ \t]+a1
0+15c <[^>]*> 0000a122[ \t]+bnop \.S2 00000140 <f6>,5
0+160 <[^>]*> 5ff9c122[ \t]+\[!b1\] bnop \.S2 00000144 <f6\+0x4>,6
0+164 <[^>]*> 0003e120[ \t]+bnop \.S1 0000016c <g6>,7
0+168 <[^>]*> 00000122[ \t]+bnop \.S2 00000160 <f6\+0x20>,0
[ \t]*168: R_C6000_PCR_S12[ \t]+b1
[ \t]*\.\.\.
[ \t]*\.\.\.
0+188 <[^>]*> 00000122[ \t]+bnop \.S2 00000180 <f7>,0
[ \t]*188: R_C6000_PCR_S12[ \t]+ext3\+0x4
0+18c <[^>]*> 00002120[ \t]+bnop \.S1 00000180 <f7>,1
[ \t]*18c: R_C6000_PCR_S12[ \t]+ext2
0+190 <[^>]*> 00004120[ \t]+bnop \.S1 00000180 <f7>,2
[ \t]*190: R_C6000_PCR_S12[ \t]+nrp
0+194 <[^>]*> 00006122[ \t]+bnop \.S2 00000180 <f7>,3
[ \t]*194: R_C6000_PCR_S12[ \t]+irp
0+198 <[^>]*> 00008120[ \t]+bnop \.S1 00000180 <f7>,4
[ \t]*198: R_C6000_PCR_S12[ \t]+a1
0+19c <[^>]*> 0000a122[ \t]+bnop \.S2 00000180 <f7>,5
0+1a0 <[^>]*> cff9c122[ \t]+\[a0\] bnop \.S2 00000184 <f7\+0x4>,6
0+1a4 <[^>]*> 0003e120[ \t]+bnop \.S1 000001ac <g7>,7
0+1a8 <[^>]*> 00000122[ \t]+bnop \.S2 000001a0 <f7\+0x20>,0
[ \t]*1a8: R_C6000_PCR_S12[ \t]+b1
[ \t]*\.\.\.
[ \t]*\.\.\.
0+1c8 <[^>]*> 10000012[ \t]+callp \.S2 000001c0 <f8>,b3
[ \t]*1c8: R_C6000_PCR_S21[ \t]+ext3\+0x4
0+1cc <[^>]*> 10000010[ \t]+callp \.S1 000001c0 <f8>,a3
[ \t]*1cc: R_C6000_PCR_S21[ \t]+ext2
0+1d0 <[^>]*> 10000010[ \t]+callp \.S1 000001c0 <f8>,a3
[ \t]*1d0: R_C6000_PCR_S21[ \t]+nrp
0+1d4 <[^>]*> 10000012[ \t]+callp \.S2 000001c0 <f8>,b3
[ \t]*1d4: R_C6000_PCR_S21[ \t]+irp
0+1d8 <[^>]*> 10000010[ \t]+callp \.S1 000001c0 <f8>,a3
[ \t]*1d8: R_C6000_PCR_S21[ \t]+a1
0+1dc <[^>]*> 10000012[ \t]+callp \.S2 000001c0 <f8>,b3
0+1e0 <[^>]*> 1ffffc92[ \t]+callp \.S2 000001c4 <f8\+0x4>,b3
0+1e4 <[^>]*> 10000190[ \t]+callp \.S1 000001ec <g8>,a3
0+1e8 <[^>]*> 10000012[ \t]+callp \.S2 000001e0 <f8\+0x20>,b3
[ \t]*1e8: R_C6000_PCR_S21[ \t]+b1
[ \t]*\.\.\.
[ \t]*\.\.\.
0+208 <[^>]*> 00000012[ \t]+b \.S2 00000200 <f9>
[ \t]*208: R_C6000_PCR_S21[ \t]+ext3\+0x4
0+20c <[^>]*> 00000010[ \t]+b \.S1 00000200 <f9>
[ \t]*20c: R_C6000_PCR_S21[ \t]+ext2
0+210 <[^>]*> 00000012[ \t]+b \.S2 00000200 <f9>
[ \t]*210: R_C6000_PCR_S21[ \t]+nrp
0+214 <[^>]*> 00000012[ \t]+b \.S2 00000200 <f9>
[ \t]*214: R_C6000_PCR_S21[ \t]+irp
0+218 <[^>]*> 00000010[ \t]+b \.S1 00000200 <f9>
[ \t]*218: R_C6000_PCR_S21[ \t]+a1
0+21c <[^>]*> 00000012[ \t]+b \.S2 00000200 <f9>
0+220 <[^>]*> 6ffffc92[ \t]+\[b2\] b \.S2 00000204 <f9\+0x4>
0+224 <[^>]*> 00000192[ \t]+b \.S2 0000022c <g9>
0+228 <[^>]*> 00000012[ \t]+b \.S2 00000220 <f9\+0x20>
[ \t]*228: R_C6000_PCR_S21[ \t]+b1
[ \t]*\.\.\.
[ \t]*\.\.\.
0+248 <[^>]*> 00000012[ \t]+b \.S2 00000240 <f10>
[ \t]*248: R_C6000_PCR_S21[ \t]+ext3\+0x4
0+24c <[^>]*> 00000010[ \t]+b \.S1 00000240 <f10>
[ \t]*24c: R_C6000_PCR_S21[ \t]+ext2
0+250 <[^>]*> 00000012[ \t]+b \.S2 00000240 <f10>
[ \t]*250: R_C6000_PCR_S21[ \t]+nrp
0+254 <[^>]*> 00000012[ \t]+b \.S2 00000240 <f10>
[ \t]*254: R_C6000_PCR_S21[ \t]+irp
0+258 <[^>]*> 00000010[ \t]+b \.S1 00000240 <f10>
[ \t]*258: R_C6000_PCR_S21[ \t]+a1
0+25c <[^>]*> 00000012[ \t]+b \.S2 00000240 <f10>
0+260 <[^>]*> 6ffffc92[ \t]+\[b2\] b \.S2 00000244 <f10\+0x4>
0+264 <[^>]*> 00000192[ \t]+b \.S2 0000026c <g10>
0+268 <[^>]*> 00000012[ \t]+b \.S2 00000260 <f10\+0x20>
[ \t]*268: R_C6000_PCR_S21[ \t]+b1
[ \t]*\.\.\.
[ \t]*\.\.\.
0+288 <[^>]*> 10000012[ \t]+callp \.S2 00000280 <f11>,b3
[ \t]*288: R_C6000_PCR_S21[ \t]+ext3\+0x4
0+28c <[^>]*> 10000010[ \t]+callp \.S1 00000280 <f11>,a3
[ \t]*28c: R_C6000_PCR_S21[ \t]+ext2
0+290 <[^>]*> 10000010[ \t]+callp \.S1 00000280 <f11>,a3
[ \t]*290: R_C6000_PCR_S21[ \t]+nrp
0+294 <[^>]*> 10000012[ \t]+callp \.S2 00000280 <f11>,b3
[ \t]*294: R_C6000_PCR_S21[ \t]+irp
0+298 <[^>]*> 10000010[ \t]+callp \.S1 00000280 <f11>,a3
[ \t]*298: R_C6000_PCR_S21[ \t]+a1
0+29c <[^>]*> 10000012[ \t]+callp \.S2 00000280 <f11>,b3
0+2a0 <[^>]*> 1ffffc92[ \t]+callp \.S2 00000284 <f11\+0x4>,b3
0+2a4 <[^>]*> 10000190[ \t]+callp \.S1 000002ac <g11>,a3
0+2a8 <[^>]*> 10000012[ \t]+callp \.S2 000002a0 <f11\+0x20>,b3
[ \t]*2a8: R_C6000_PCR_S21[ \t]+b1
[ \t]*\.\.\.
0+2c0 <[^>]*> 3014a120[ \t]+\[!b0\] bnop \.S1 00000310 <g12\+0x50>,5
0+2c4 <[^>]*> 2010a120[ \t]+\[b0\] bnop \.S1 00000300 <g12\+0x40>,5
0+2c8 <[^>]*> 00000410[ \t]+b \.S1 000002e0 <g12\+0x20>
[ \t]*\.\.\.
0+2f8 <[^>]*> 80801021[ \t]+\[a1\] bdec \.S1 000002e0 <g12\+0x20>,a1
[ \t]*\.\.\.
0+320 <[^>]*> 3014a120[ \t]+\[!b0\] bnop \.S1 00000348 <g13\+0x28>,5
0+324 <[^>]*> 2010a120[ \t]+\[b0\] bnop \.S1 00000340 <g13\+0x20>,5
0+328 <[^>]*> 00000410[ \t]+b \.S1 00000340 <g13\+0x20>
[ \t]*\.\.\.
0+33c <[^>]*> e0000000[ \t]+<fetch packet header 0xe0000000>
[ \t]*\.\.\.
0+358 <[^>]*> 80801021[ \t]+\[a1\] bdec \.S1 00000340 <g13\+0x20>,a1
0+35c <[^>]*> e0000000[ \t]+<fetch packet header 0xe0000000>
