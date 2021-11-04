// TC_OUT
0000000000000000 <iconv_open>:
   0:	push   %rbp
   1:	mov    %rsp,%rbp
   4:	push   %r15
   6:	push   %r14
   8:	push   %r13
   a:	push   %r12
   c:	mov    %rdi,%r13
   f:	push   %rbx
  10:	mov    %rsi,%r15
  13:	sub    $0x28,%rsp
  17:	callq  1c <iconv_open+0x1c>
  1c:	lea    0x3(%rax),%rbx
  20:	cmp    $0x1000,%rbx
  27:	ja     321 <iconv_open+0x321>
  2d:	add    $0x1e,%rbx
  31:	mov    $0x1,%r12d
  37:	and    $0xfffffffffffffff0,%rbx
  3b:	sub    %rbx,%rsp
  3e:	lea    0xf(%rsp),%rbx
  43:	and    $0xfffffffffffffff0,%rbx
  47:	movzbl 0x0(%r13),%r14d
  4c:	test   %r14b,%r14b
  4f:	je     3c3 <iconv_open+0x3c3>
  55:	mov    0x0(%rip),%rdi        # 5c <iconv_open+0x5c>
  5c:	mov    0x0(%rip),%r11        # 63 <iconv_open+0x63>
  63:	mov    %r13,%rcx
  66:	mov    %rbx,%rsi
  69:	mov    %r14d,%eax
  6c:	xor    %r10d,%r10d
  6f:	jmp    98 <iconv_open+0x98>
  71:	nopl   0x0(%rax)
  78:	testb  $0x8,(%rdi,%r8,2)
  7d:	jne    bb <iconv_open+0xbb>
  7f:	cmp    $0x2f,%al
  81:	je     260 <iconv_open+0x260>
  87:	add    $0x1,%rcx
  8b:	movzbl (%rcx),%eax
  8e:	test   %al,%al
  90:	je     d1 <iconv_open+0xd1>
  92:	nopw   0x0(%rax,%rax,1)
  98:	cmp    $0x3a,%al
  9a:	movsbq %al,%r8
  9e:	sete   %r9b
  a2:	cmp    $0x5f,%al
  a4:	sete   %dl
  a7:	or     %r9d,%edx
  aa:	lea    -0x2c(%rax),%r9d
  ae:	cmp    $0x2,%r9b
  b2:	setbe  %r9b
  b6:	or     %r9b,%dl
  b9:	je     78 <iconv_open+0x78>
  bb:	mov    (%r11,%r8,4),%eax
  bf:	add    $0x1,%rcx
  c3:	add    $0x1,%rsi
  c7:	mov    %al,-0x1(%rsi)
  ca:	movzbl (%rcx),%eax
  cd:	test   %al,%al
  cf:	jne    98 <iconv_open+0x98>
  d1:	cmp    $0x1,%r10d
  d5:	jg     38d <iconv_open+0x38d>
  db:	test   %r10d,%r10d
  de:	lea    0x1(%rsi),%rax
  e2:	movb   $0x2f,(%rsi)
  e5:	jne    39f <iconv_open+0x39f>
  eb:	lea    0x1(%rax),%rdx
  ef:	movb   $0x2f,(%rax)
  f2:	movb   $0x0,(%rdx)
  f5:	cmpb   $0x0,0x2(%rbx)
  f9:	je     298 <iconv_open+0x298>
  ff:	mov    %r15,%rdi
 102:	callq  107 <iconv_open+0x107>
 107:	lea    0x3(%rax),%r13
 10b:	cmp    $0x1000,%r13
 112:	ja     350 <iconv_open+0x350>
 118:	add    $0x1e,%r13
 11c:	movl   $0x1,-0x44(%rbp)
 123:	and    $0xfffffffffffffff0,%r13
 127:	sub    %r13,%rsp
 12a:	lea    0xf(%rsp),%r13
 12f:	and    $0xfffffffffffffff0,%r13
 133:	movzbl (%r15),%edi
 137:	test   %dil,%dil
 13a:	je     3cf <iconv_open+0x3cf>
 140:	mov    0x0(%rip),%r14        # 147 <iconv_open+0x147>
 147:	mov    0x0(%rip),%r11        # 14e <iconv_open+0x14e>
 14e:	mov    %r15,%r8
 151:	mov    %r13,%r9
 154:	mov    %edi,%edx
 156:	xor    %esi,%esi
 158:	jmp    180 <iconv_open+0x180>
 15a:	nopw   0x0(%rax,%rax,1)
 160:	testb  $0x8,(%r14,%r10,2)
 165:	jne    19e <iconv_open+0x19e>
 167:	cmp    $0x2f,%dl
 16a:	je     2d0 <iconv_open+0x2d0>
 170:	add    $0x1,%r8
 174:	movzbl (%r8),%edx
 178:	test   %dl,%dl
 17a:	je     1b6 <iconv_open+0x1b6>
 17c:	nopl   0x0(%rax)
 180:	cmp    $0x3a,%dl
 183:	movsbq %dl,%r10
 187:	sete   %cl
 18a:	cmp    $0x5f,%dl
 18d:	sete   %al
 190:	or     %eax,%ecx
 192:	lea    -0x2c(%rdx),%eax
 195:	cmp    $0x2,%al
 197:	setbe  %al
 19a:	or     %al,%cl
 19c:	je     160 <iconv_open+0x160>
 19e:	add    $0x1,%r8
 1a2:	movzbl (%r8),%edx
 1a6:	mov    (%r11,%r10,4),%eax
 1aa:	add    $0x1,%r9
 1ae:	mov    %al,-0x1(%r9)
 1b2:	test   %dl,%dl
 1b4:	jne    180 <iconv_open+0x180>
 1b6:	cmp    $0x1,%esi
 1b9:	jg     3a7 <iconv_open+0x3a7>
 1bf:	test   %esi,%esi
 1c1:	lea    0x1(%r9),%rax
 1c5:	movb   $0x2f,(%r9)
 1c9:	jne    3bb <iconv_open+0x3bb>
 1cf:	lea    0x1(%rax),%rdx
 1d3:	movb   $0x2f,(%rax)
 1d6:	movb   $0x0,(%rdx)
 1d9:	cmpb   $0x0,0x2(%r13)
 1de:	jne    208 <iconv_open+0x208>
 1e0:	test   %dil,%dil
 1e3:	je     208 <iconv_open+0x208>
 1e5:	mov    0x0(%rip),%r11        # 1ec <iconv_open+0x1ec>
 1ec:	mov    %r13,%rax
 1ef:	nop
 1f0:	add    $0x1,%r15
 1f4:	movsbq -0x1(%r15),%rdx
 1f9:	add    $0x1,%rax
 1fd:	mov    (%r11,%rdx,4),%edx
 201:	test   %dl,%dl
 203:	mov    %dl,-0x1(%rax)
 206:	jne    1f0 <iconv_open+0x1f0>
 208:	lea    -0x38(%rbp),%rdx
 20c:	xor    %ecx,%ecx
 20e:	mov    %r13,%rsi
 211:	mov    %rbx,%rdi
 214:	callq  219 <iconv_open+0x219>
 219:	mov    %eax,%r14d
 21c:	mov    -0x44(%rbp),%eax
 21f:	test   %eax,%eax
 221:	je     2f0 <iconv_open+0x2f0>
 227:	test   %r12d,%r12d
 22a:	je     301 <iconv_open+0x301>
 230:	test   %r14d,%r14d
 233:	je     280 <iconv_open+0x280>
 235:	sub    $0x1,%r14d
 239:	cmp    $0x1,%r14d
 23d:	jbe    30e <iconv_open+0x30e>
 243:	lea    -0x28(%rbp),%rsp
 247:	mov    $0xffffffffffffffff,%rax
 24e:	pop    %rbx
 24f:	pop    %r12
 251:	pop    %r13
 253:	pop    %r14
 255:	pop    %r15
 257:	pop    %rbp
 258:	retq   
 259:	nopl   0x0(%rax)
 260:	add    $0x1,%r10d
 264:	cmp    $0x3,%r10d
 268:	je     38d <iconv_open+0x38d>
 26e:	movb   $0x2f,(%rsi)
 271:	add    $0x1,%rsi
 275:	jmpq   87 <iconv_open+0x87>
 27a:	nopw   0x0(%rax,%rax,1)
 280:	mov    -0x38(%rbp),%rax
 284:	lea    -0x28(%rbp),%rsp
 288:	pop    %rbx
 289:	pop    %r12
 28b:	pop    %r13
 28d:	pop    %r14
 28f:	pop    %r15
 291:	pop    %rbp
 292:	retq   
 293:	nopl   0x0(%rax,%rax,1)
 298:	test   %r14b,%r14b
 29b:	je     ff <iconv_open+0xff>
 2a1:	mov    0x0(%rip),%r11        # 2a8 <iconv_open+0x2a8>
 2a8:	mov    %rbx,%rax
 2ab:	nopl   0x0(%rax,%rax,1)
 2b0:	add    $0x1,%r13
 2b4:	movsbq -0x1(%r13),%rdx
 2b9:	add    $0x1,%rax
 2bd:	mov    (%r11,%rdx,4),%edx
 2c1:	test   %dl,%dl
 2c3:	mov    %dl,-0x1(%rax)
 2c6:	jne    2b0 <iconv_open+0x2b0>
 2c8:	jmpq   ff <iconv_open+0xff>
 2cd:	nopl   (%rax)
 2d0:	add    $0x1,%esi
 2d3:	cmp    $0x3,%esi
 2d6:	je     3a7 <iconv_open+0x3a7>
 2dc:	movb   $0x2f,(%r9)
 2e0:	add    $0x1,%r9
 2e4:	jmpq   170 <iconv_open+0x170>
 2e9:	nopl   0x0(%rax)
 2f0:	mov    %r13,%rdi
 2f3:	callq  2f8 <iconv_open+0x2f8>
 2f8:	test   %r12d,%r12d
 2fb:	jne    230 <iconv_open+0x230>
 301:	mov    %rbx,%rdi
 304:	callq  309 <iconv_open+0x309>
 309:	jmpq   230 <iconv_open+0x230>
 30e:	mov    0x0(%rip),%rax        # 315 <iconv_open+0x315>
 315:	movl   $0x16,%fs:(%rax)
 31c:	jmpq   243 <iconv_open+0x243>
 321:	mov    %rbx,%rdi
 324:	callq  329 <iconv_open+0x329>
 329:	test   %eax,%eax
 32b:	mov    %eax,%r12d
 32e:	jne    2d <iconv_open+0x2d>
 334:	mov    %rbx,%rdi
 337:	callq  33c <iconv_open+0x33c>
 33c:	test   %rax,%rax
 33f:	mov    %rax,%rbx
 342:	jne    47 <iconv_open+0x47>
 348:	jmpq   243 <iconv_open+0x243>
 34d:	nopl   (%rax)
 350:	mov    %r13,%rdi
 353:	callq  358 <iconv_open+0x358>
 358:	test   %eax,%eax
 35a:	mov    %eax,-0x44(%rbp)
 35d:	jne    118 <iconv_open+0x118>
 363:	mov    %r13,%rdi
 366:	callq  36b <iconv_open+0x36b>
 36b:	test   %rax,%rax
 36e:	mov    %rax,%r13
 371:	jne    133 <iconv_open+0x133>
 377:	test   %r12d,%r12d
 37a:	jne    243 <iconv_open+0x243>
 380:	mov    %rbx,%rdi
 383:	callq  388 <iconv_open+0x388>
 388:	jmpq   243 <iconv_open+0x243>
 38d:	movb   $0x0,(%rsi)
 390:	cmpb   $0x0,0x2(%rbx)
 394:	je     2a8 <iconv_open+0x2a8>
 39a:	jmpq   ff <iconv_open+0xff>
 39f:	mov    %rax,%rdx
 3a2:	jmpq   f2 <iconv_open+0xf2>
 3a7:	movb   $0x0,(%r9)
 3ab:	cmpb   $0x0,0x2(%r13)
 3b0:	je     1ec <iconv_open+0x1ec>
 3b6:	jmpq   208 <iconv_open+0x208>
 3bb:	mov    %rax,%rdx
 3be:	jmpq   1d6 <iconv_open+0x1d6>
 3c3:	lea    0x1(%rbx),%rax
 3c7:	movb   $0x2f,(%rbx)
 3ca:	jmpq   eb <iconv_open+0xeb>
 3cf:	lea    0x1(%r13),%rax
 3d3:	movb   $0x2f,0x0(%r13)
 3d8:	jmpq   1cf <iconv_open+0x1cf>
