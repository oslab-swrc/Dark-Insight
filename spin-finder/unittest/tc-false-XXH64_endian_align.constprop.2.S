// TC_OUT
0000000000d45030 <XXH64_endian_align.constprop.2>:
  d45030:	push   %rbp
  d45031:	movabs $0x27d4eb2f165667c5,%r9
  d4503b:	lea    (%rdi,%rsi,1),%r10
  d4503f:	add    %rdx,%r9
  d45042:	cmp    $0x1f,%rsi
  d45046:	mov    %rsp,%rbp
  d45049:	push   %r13
  d4504b:	push   %r12
  d4504d:	push   %rbx
  d4504e:	jbe    d45195 <XXH64_endian_align.constprop.2+0x165>
  d45054:	movabs $0x60ea27eeadc0b5d6,%r9
  d4505e:	movabs $0x61c8864e7a143579,%rax
  d45068:	movabs $0xc2b2ae3d27d4eb4f,%r12
  d45072:	add    %rdx,%r9
  d45075:	add    %rdx,%rax
  d45078:	cmp    $0x1,%ecx
  d4507b:	lea    -0x20(%r10),%r13
  d4507f:	lea    (%rdx,%r12,1),%r8
  d45083:	je     d45308 <XXH64_endian_align.constprop.2+0x2d8>
  d45089:	movabs $0x9e3779b185ebca87,%rbx
  d45093:	nopl   0x0(%rax,%rax,1)
  d45098:	mov    (%rdi),%r11
  d4509b:	add    $0x20,%rdi
  d4509f:	bswap  %r11
  d450a2:	imul   %r12,%r11
  d450a6:	add    %r11,%r9
  d450a9:	mov    -0x18(%rdi),%r11
  d450ad:	ror    $0x21,%r9
  d450b1:	imul   %rbx,%r9
  d450b5:	bswap  %r11
  d450b8:	imul   %r12,%r11
  d450bc:	add    %r11,%r8
  d450bf:	mov    -0x10(%rdi),%r11
  d450c3:	ror    $0x21,%r8
  d450c7:	imul   %rbx,%r8
  d450cb:	bswap  %r11
  d450ce:	imul   %r12,%r11
  d450d2:	add    %r11,%rdx
  d450d5:	mov    -0x8(%rdi),%r11
  d450d9:	ror    $0x21,%rdx
  d450dd:	imul   %rbx,%rdx
  d450e1:	bswap  %r11
  d450e4:	imul   %r12,%r11
  d450e8:	add    %r11,%rax
  d450eb:	ror    $0x21,%rax
  d450ef:	imul   %rbx,%rax
  d450f3:	cmp    %rdi,%r13
  d450f6:	jae    d45098 <XXH64_endian_align.constprop.2+0x68>
  d450f8:	mov    %r8,%r12
  d450fb:	mov    %r9,%r11
  d450fe:	movabs $0xc2b2ae3d27d4eb4f,%rbx
  d45108:	ror    $0x3f,%r11
  d4510c:	ror    $0x39,%r12
  d45110:	add    %r11,%r12
  d45113:	mov    %rdx,%r11
  d45116:	imul   %rbx,%r9
  d4511a:	ror    $0x34,%r11
  d4511e:	add    %r11,%r12
  d45121:	mov    %rax,%r11
  d45124:	ror    $0x2e,%r11
  d45128:	add    %r11,%r12
  d4512b:	movabs $0x9e3779b185ebca87,%r11
  d45135:	ror    $0x21,%r9
  d45139:	imul   %r11,%r9
  d4513d:	imul   %rbx,%r8
  d45141:	imul   %rbx,%rdx
  d45145:	xor    %r9,%r12
  d45148:	movabs $0x85ebca77c2b2ae63,%r9
  d45152:	ror    $0x21,%r8
  d45156:	imul   %r11,%r12
  d4515a:	ror    $0x21,%rdx
  d4515e:	imul   %r11,%r8
  d45162:	imul   %r11,%rdx
  d45166:	add    %r9,%r12
  d45169:	xor    %r8,%r12
  d4516c:	imul   %r11,%r12
  d45170:	imul   %rbx,%rax
  d45174:	lea    (%r12,%r9,1),%r8
  d45178:	ror    $0x21,%rax
  d4517c:	xor    %rdx,%r8
  d4517f:	imul   %r11,%r8
  d45183:	imul   %r11,%rax
  d45187:	lea    (%r8,%r9,1),%rdx
  d4518b:	xor    %rax,%rdx
  d4518e:	imul   %r11,%rdx
  d45192:	add    %rdx,%r9
  d45195:	lea    0x8(%rdi),%rbx
  d45199:	add    %r9,%rsi
  d4519c:	cmp    %rbx,%r10
  d4519f:	jb     d4520f <XXH64_endian_align.constprop.2+0x1df>
  d451a1:	cmp    $0x1,%ecx
  d451a4:	mov    %rbx,%rdx
  d451a7:	mov    %rdi,%r9
  d451aa:	movabs $0xc2b2ae3d27d4eb4f,%r12
  d451b4:	movabs $0x9e3779b185ebca87,%r8
  d451be:	movabs $0x85ebca77c2b2ae63,%r11
  d451c8:	jne    d451d6 <XXH64_endian_align.constprop.2+0x1a6>
  d451ca:	jmpq   d452d6 <XXH64_endian_align.constprop.2+0x2a6>
  d451cf:	nop
  d451d0:	mov    %rdx,%r9
  d451d3:	mov    %rax,%rdx
  d451d6:	mov    (%r9),%rax
  d451d9:	bswap  %rax
  d451dc:	imul   %r12,%rax
  d451e0:	ror    $0x21,%rax
  d451e4:	imul   %r8,%rax
  d451e8:	xor    %rsi,%rax
  d451eb:	ror    $0x25,%rax
  d451ef:	imul   %r8,%rax
  d451f3:	lea    (%rax,%r11,1),%rsi
  d451f7:	lea    0x8(%rdx),%rax
  d451fb:	cmp    %rax,%r10
  d451fe:	jae    d451d0 <XXH64_endian_align.constprop.2+0x1a0>
  d45200:	lea    -0x8(%r10),%rax
  d45204:	sub    %rdi,%rax
  d45207:	and    $0xfffffffffffffff8,%rax
  d4520b:	lea    (%rbx,%rax,1),%rdi
  d4520f:	lea    0x4(%rdi),%rdx
  d45213:	cmp    %rdx,%r10
  d45216:	jb     d45256 <XXH64_endian_align.constprop.2+0x226>
  d45218:	cmp    $0x1,%ecx
  d4521b:	mov    (%rdi),%eax
  d4521d:	je     d45221 <XXH64_endian_align.constprop.2+0x1f1>
  d4521f:	bswap  %eax
  d45221:	movabs $0x9e3779b185ebca87,%rcx
  d4522b:	mov    %eax,%eax
  d4522d:	mov    %rdx,%rdi
  d45230:	imul   %rcx,%rax
  d45234:	movabs $0xc2b2ae3d27d4eb4f,%rcx
  d4523e:	xor    %rsi,%rax
  d45241:	movabs $0x165667b19e3779f9,%rsi
  d4524b:	ror    $0x29,%rax
  d4524f:	imul   %rcx,%rax
  d45253:	add    %rax,%rsi
  d45256:	cmp    %rdi,%r10
  d45259:	jbe    d4528b <XXH64_endian_align.constprop.2+0x25b>
  d4525b:	movabs $0x27d4eb2f165667c5,%rcx
  d45265:	movabs $0x9e3779b185ebca87,%rdx
  d4526f:	nop
  d45270:	movzbl (%rdi),%eax
  d45273:	add    $0x1,%rdi
  d45277:	imul   %rcx,%rax
  d4527b:	xor    %rax,%rsi
  d4527e:	ror    $0x35,%rsi
  d45282:	imul   %rdx,%rsi
  d45286:	cmp    %r10,%rdi
  d45289:	jne    d45270 <XXH64_endian_align.constprop.2+0x240>
  d4528b:	mov    %rsi,%rax
  d4528e:	movabs $0xc2b2ae3d27d4eb4f,%rdx
  d45298:	shr    $0x21,%rax
  d4529c:	xor    %rsi,%rax
  d4529f:	imul   %rdx,%rax
  d452a3:	pop    %rbx
  d452a4:	pop    %r12
  d452a6:	pop    %r13
  d452a8:	mov    %rax,%rdx
  d452ab:	shr    $0x1d,%rdx
  d452af:	xor    %rax,%rdx
  d452b2:	movabs $0x165667b19e3779f9,%rax
  d452bc:	imul   %rax,%rdx
  d452c0:	pop    %rbp
  d452c1:	mov    %rdx,%rax
  d452c4:	shr    $0x20,%rax
  d452c8:	xor    %rdx,%rax
  d452cb:	retq   
  d452cc:	nopl   0x0(%rax)
  d452d0:	mov    %rdx,%r9
  d452d3:	mov    %rax,%rdx
  d452d6:	mov    %r12,%rax
  d452d9:	imul   (%r9),%rax
  d452dd:	ror    $0x21,%rax
  d452e1:	imul   %r8,%rax
  d452e5:	xor    %rsi,%rax
  d452e8:	ror    $0x25,%rax
  d452ec:	imul   %r8,%rax
  d452f0:	lea    (%rax,%r11,1),%rsi
  d452f4:	lea    0x8(%rdx),%rax
  d452f8:	cmp    %rax,%r10
  d452fb:	jae    d452d0 <XXH64_endian_align.constprop.2+0x2a0>
  d452fd:	jmpq   d45200 <XXH64_endian_align.constprop.2+0x1d0>
  d45302:	nopw   0x0(%rax,%rax,1)
  d45308:	movabs $0x9e3779b185ebca87,%r11
  d45312:	nopw   0x0(%rax,%rax,1)
  d45318:	mov    %r12,%rbx
  d4531b:	add    $0x20,%rdi
  d4531f:	imul   -0x20(%rdi),%rbx
  d45324:	add    %rbx,%r9
  d45327:	mov    %r12,%rbx
  d4532a:	imul   -0x18(%rdi),%rbx
  d4532f:	ror    $0x21,%r9
  d45333:	imul   %r11,%r9
  d45337:	add    %rbx,%r8
  d4533a:	mov    %r12,%rbx
  d4533d:	imul   -0x10(%rdi),%rbx
  d45342:	ror    $0x21,%r8
  d45346:	imul   %r11,%r8
  d4534a:	add    %rbx,%rdx
  d4534d:	mov    %r12,%rbx
  d45350:	imul   -0x8(%rdi),%rbx
  d45355:	ror    $0x21,%rdx
  d45359:	imul   %r11,%rdx
  d4535d:	add    %rbx,%rax
  d45360:	ror    $0x21,%rax
  d45364:	imul   %r11,%rax
  d45368:	cmp    %rdi,%r13
  d4536b:	jae    d45318 <XXH64_endian_align.constprop.2+0x2e8>
  d4536d:	jmpq   d450f8 <XXH64_endian_align.constprop.2+0xc8>
  d45372:	data32 data32 data32 data32 nopw %cs:0x0(%rax,%rax,1)
