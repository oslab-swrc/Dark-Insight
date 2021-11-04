// TC_OUT _ZN7rocksdb15ConcurrentArena8AllocateEm,0x51e088,0x51e0bf,0x0(%r12),0x0(%rdx)
// TC_OUT _ZN7rocksdb15ConcurrentArena8AllocateEm,0x51e178,0x51e1aa,0x0(%r12)
000000000051df90 <_ZN7rocksdb15ConcurrentArena8AllocateEm>:
  51df90:	push   %rbp
  51df91:	mov    %rsp,%rbp
  51df94:	push   %r15
  51df96:	push   %r14
  51df98:	push   %r13
  51df9a:	mov    %rsi,%r13
  51df9d:	push   %r12
  51df9f:	lea    0x8c8(%rdi),%r12
  51dfa6:	push   %rbx
  51dfa7:	mov    %rdi,%rbx
  51dfaa:	sub    $0x58,%rsp
  51dfae:	mov    %r12,-0x50(%rbp)
  51dfb2:	mov    0x40(%rdi),%rax
  51dfb6:	movb   $0x0,-0x48(%rbp)
  51dfba:	shr    $0x2,%rax
  51dfbe:	cmp    %rax,%rsi
  51dfc1:	ja     51e070 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0xe0>
  51dfc7:	mov    $0xfffffffffffffe30,%rax
  51dfce:	mov    0x50(%rdi),%rdx
  51dfd2:	mov    %fs:(%rax),%r14d
  51dfd6:	test   %r14d,%r14d
  51dfd9:	je     51e288 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x2f8>
  51dfdf:	and    0x48(%rbx),%r14
  51dfe3:	shl    $0x6,%r14
  51dfe7:	add    %rdx,%r14
  51dfea:	movzbl 0x28(%r14),%eax
  51dfef:	lea    0x28(%r14),%rcx
  51dff3:	test   %al,%al
  51dff5:	setne  %al
  51dff8:	test   %al,%al
  51dffa:	mov    %al,-0x40(%rbp)
  51dffd:	je     51e2c0 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x330>
  51e003:	mov    %rbx,%rdi
  51e006:	callq  59b910 <_ZN7rocksdb15ConcurrentArena6RepickEv>
  51e00b:	mov    %rax,%r14
  51e00e:	xor    %r15d,%r15d
  51e011:	mov    $0x1,%esi
  51e016:	lea    0x28(%rax),%rcx
  51e01a:	lea    -0x40(%rbp),%rdx
  51e01e:	jmp    51e047 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0xb7>
  51e020:	pause  
  51e022:	cmp    $0x64,%r15
  51e026:	jbe    51e043 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0xb3>
  51e028:	mov    %esi,-0x74(%rbp)
  51e02b:	mov    %rdx,-0x70(%rbp)
  51e02f:	mov    %rcx,-0x68(%rbp)
  51e033:	callq  408580 <sched_yield@plt>
  51e038:	mov    -0x74(%rbp),%esi
  51e03b:	mov    -0x70(%rbp),%rdx
  51e03f:	mov    -0x68(%rbp),%rcx
  51e043:	add    $0x1,%r15
  51e047:	movzbl (%rcx),%eax
  51e04a:	test   %al,%al
  51e04c:	setne  %al
  51e04f:	test   %al,%al
  51e051:	mov    %al,-0x40(%rbp)
  51e054:	jne    51e020 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x90>
  51e056:	movzbl (%rdx),%eax
  51e059:	lock cmpxchg %sil,(%rcx)
  51e05e:	je     51e150 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x1c0>
  51e064:	mov    %al,(%rdx)
  51e066:	jmp    51e020 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x90>
  51e068:	nopl   0x0(%rax,%rax,1)
  51e070:	test   %r12,%r12
  51e073:	je     51e2fb <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x36b>
  51e079:	lea    -0x40(%rbp),%rdx
  51e07d:	xor    %r15d,%r15d
  51e080:	mov    $0x1,%r14d
  51e086:	jmp    51e0ae <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x11e>
  51e088:	movzbl (%rdx),%eax
  51e08b:	lock cmpxchg %r14b,(%r12)
  51e091:	je     51e0c8 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x138>
  51e093:	mov    %al,(%rdx)
  51e095:	pause  
  51e097:	cmp    $0x64,%r15
  51e09b:	jbe    51e0aa <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x11a>
  51e09d:	mov    %rdx,-0x68(%rbp)
  51e0a1:	callq  408580 <sched_yield@plt>
  51e0a6:	mov    -0x68(%rbp),%rdx
  51e0aa:	add    $0x1,%r15
  51e0ae:	movzbl (%r12),%eax
  51e0b3:	test   %al,%al
  51e0b5:	setne  %al
  51e0b8:	test   %al,%al
  51e0ba:	mov    %al,-0x40(%rbp)
  51e0bd:	jne    51e095 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x105>
  51e0bf:	jmp    51e088 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0xf8>
  51e0c1:	nopl   0x0(%rax)
  51e0c8:	mov    0x8b0(%rbx),%rdx
  51e0cf:	movb   $0x1,-0x48(%rbp)
  51e0d3:	cmp    %rdx,%r13
  51e0d6:	ja     51e258 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x2c8>
  51e0dc:	mov    0x8a0(%rbx),%rax
  51e0e3:	sub    %r13,%rdx
  51e0e6:	mov    %rdx,0x8b0(%rbx)
  51e0ed:	sub    %r13,%rax
  51e0f0:	mov    %rax,0x8a0(%rbx)
  51e0f7:	mov    %rdx,0x8d0(%rbx)
  51e0fe:	mov    0x8c0(%rbx),%rdx
  51e105:	mov    %rdx,0x8d8(%rbx)
  51e10c:	mov    0x898(%rbx),%rdx
  51e113:	mov    %rdx,0x8e0(%rbx)
  51e11a:	cmpb   $0x0,-0x48(%rbp)
  51e11e:	jne    51e130 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x1a0>
  51e120:	add    $0x58,%rsp
  51e124:	pop    %rbx
  51e125:	pop    %r12
  51e127:	pop    %r13
  51e129:	pop    %r14
  51e12b:	pop    %r15
  51e12d:	pop    %rbp
  51e12e:	retq   
  51e12f:	nop
  51e130:	mov    -0x50(%rbp),%rdx
  51e134:	test   %rdx,%rdx
  51e137:	je     51e120 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x190>
  51e139:	movb   $0x0,(%rdx)
  51e13c:	add    $0x58,%rsp
  51e140:	pop    %rbx
  51e141:	pop    %r12
  51e143:	pop    %r13
  51e145:	pop    %r14
  51e147:	pop    %r15
  51e149:	pop    %rbp
  51e14a:	retq   
  51e14b:	nopl   0x0(%rax,%rax,1)
  51e150:	lea    0x38(%r14),%rax
  51e154:	mov    %rcx,-0x40(%rbp)
  51e158:	movb   $0x1,-0x38(%rbp)
  51e15c:	mov    %rax,-0x68(%rbp)
  51e160:	mov    0x38(%r14),%r15
  51e164:	cmp    %r15,%r13
  51e167:	jbe    51e21d <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x28d>
  51e16d:	xor    %r15d,%r15d
  51e170:	jmp    51e189 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x1f9>
  51e172:	nopw   0x0(%rax,%rax,1)
  51e178:	pause  
  51e17a:	cmp    $0x64,%r15
  51e17e:	jbe    51e185 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x1f5>
  51e180:	callq  408580 <sched_yield@plt>
  51e185:	add    $0x1,%r15
  51e189:	movzbl (%r12),%eax
  51e18e:	test   %al,%al
  51e190:	setne  %al
  51e193:	test   %al,%al
  51e195:	mov    %al,-0x51(%rbp)
  51e198:	jne    51e178 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x1e8>
  51e19a:	mov    $0x1,%edi
  51e19f:	lock cmpxchg %dil,(%r12)
  51e1a5:	je     51e1b0 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x220>
  51e1a7:	mov    %al,-0x51(%rbp)
  51e1aa:	jmp    51e178 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x1e8>
  51e1ac:	nopl   0x0(%rax)
  51e1b0:	mov    0x8d0(%rbx),%rax
  51e1b7:	mov    0x40(%rbx),%r15
  51e1bb:	mov    %r15,%rdx
  51e1be:	shr    %rdx
  51e1c1:	cmp    %rdx,%rax
  51e1c4:	jb     51e1d8 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x248>
  51e1c6:	lea    (%r15,%r15,1),%rdx
  51e1ca:	cmp    %rdx,%rax
  51e1cd:	cmovb  %rax,%r15
  51e1d1:	nopl   0x0(%rax)
  51e1d8:	xor    %ecx,%ecx
  51e1da:	xor    %edx,%edx
  51e1dc:	lea    0x58(%rbx),%rdi
  51e1e0:	mov    %r15,%rsi
  51e1e3:	callq  598990 <_ZN7rocksdb5Arena15AllocateAlignedEmmPNS_6LoggerE>
  51e1e8:	mov    %rax,0x30(%r14)
  51e1ec:	mov    0x8b0(%rbx),%rax
  51e1f3:	mov    %rax,0x8d0(%rbx)
  51e1fa:	mov    0x8c0(%rbx),%rax
  51e201:	mov    %rax,0x8d8(%rbx)
  51e208:	mov    0x898(%rbx),%rax
  51e20f:	mov    %rax,0x8e0(%rbx)
  51e216:	movb   $0x0,0x8c8(%rbx)
  51e21d:	mov    -0x68(%rbp),%rax
  51e221:	sub    %r13,%r15
  51e224:	test   $0x7,%r13b
  51e228:	mov    %r15,(%rax)
  51e22b:	je     51e278 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x2e8>
  51e22d:	mov    %r15,%rax
  51e230:	add    0x30(%r14),%rax
  51e234:	cmpb   $0x0,-0x38(%rbp)
  51e238:	je     51e11a <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x18a>
  51e23e:	mov    -0x40(%rbp),%rdx
  51e242:	test   %rdx,%rdx
  51e245:	je     51e11a <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x18a>
  51e24b:	movb   $0x0,(%rdx)
  51e24e:	jmpq   51e11a <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x18a>
  51e253:	nopl   0x0(%rax,%rax,1)
  51e258:	lea    0x58(%rbx),%rdi
  51e25c:	xor    %edx,%edx
  51e25e:	mov    %r13,%rsi
  51e261:	callq  5988b0 <_ZN7rocksdb5Arena16AllocateFallbackEmb>
  51e266:	mov    0x8b0(%rbx),%rdx
  51e26d:	jmpq   51e0f7 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x167>
  51e272:	nopw   0x0(%rax,%rax,1)
  51e278:	mov    0x30(%r14),%rax
  51e27c:	add    %rax,%r13
  51e27f:	mov    %r13,0x30(%r14)
  51e283:	jmp    51e234 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x2a4>
  51e285:	nopl   (%rax)
  51e288:	mov    0x38(%rdx),%rax
  51e28c:	xor    %r14d,%r14d
  51e28f:	test   %rax,%rax
  51e292:	jne    51dfdf <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x4f>
  51e298:	test   %r12,%r12
  51e29b:	je     51e2f1 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x361>
  51e29d:	movzbl 0x8c8(%rdi),%eax
  51e2a4:	test   %al,%al
  51e2a6:	setne  %al
  51e2a9:	test   %al,%al
  51e2ab:	mov    %al,-0x40(%rbp)
  51e2ae:	je     51e2d7 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x347>
  51e2b0:	movb   $0x0,-0x48(%rbp)
  51e2b4:	xor    %r14d,%r14d
  51e2b7:	jmpq   51dfdf <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x4f>
  51e2bc:	nopl   0x0(%rax)
  51e2c0:	mov    $0x1,%edx
  51e2c5:	lock cmpxchg %dl,(%rcx)
  51e2c9:	je     51e150 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x1c0>
  51e2cf:	mov    %al,-0x40(%rbp)
  51e2d2:	jmpq   51e003 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x73>
  51e2d7:	mov    $0x1,%edx
  51e2dc:	lock cmpxchg %dl,(%r12)
  51e2e2:	je     51e0c8 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x138>
  51e2e8:	mov    %al,-0x40(%rbp)
  51e2eb:	mov    0x50(%rdi),%rdx
  51e2ef:	jmp    51e2b0 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x320>
  51e2f1:	mov    $0x1,%edi
  51e2f6:	callq  407cc0 <_ZSt20__throw_system_errori@plt>
  51e2fb:	mov    $0x1,%edi
  51e300:	callq  407cc0 <_ZSt20__throw_system_errori@plt>
  51e305:	mov    %rax,%rbx
  51e308:	cmpb   $0x0,-0x48(%rbp)
  51e30c:	je     51e317 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x387>
  51e30e:	lea    -0x50(%rbp),%rdi
  51e312:	callq  51dd50 <_ZNSt11unique_lockIN7rocksdb9SpinMutexEE6unlockEv>
  51e317:	mov    %rbx,%rdi
  51e31a:	callq  4088b0 <_Unwind_Resume@plt>
  51e31f:	movb   $0x0,0x8c8(%rbx)
  51e326:	mov    %rax,%r12
  51e329:	cmpb   $0x0,-0x38(%rbp)
  51e32d:	je     51e338 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x3a8>
  51e32f:	lea    -0x40(%rbp),%rdi
  51e333:	callq  51dd50 <_ZNSt11unique_lockIN7rocksdb9SpinMutexEE6unlockEv>
  51e338:	mov    %r12,%rbx
  51e33b:	jmp    51e308 <_ZN7rocksdb15ConcurrentArena8AllocateEm+0x378>
  51e33d:	nopl   (%rax)
