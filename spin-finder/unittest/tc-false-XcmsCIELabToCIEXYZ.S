// TC_OUT
000000000007c290 <XcmsCIELabToCIEXYZ>:
   7c290:	push   %r12
   7c292:	push   %rbp
   7c293:	push   %rbx
   7c294:	mov    %rdx,%rbx
   7c297:	sub    $0x50,%rsp
   7c29b:	test   %rdx,%rdx
   7c29e:	je     7c46e <XcmsCIELabToCIEXYZ+0x1de>
   7c2a4:	test   %rsi,%rsi
   7c2a7:	je     7c46e <XcmsCIELabToCIEXYZ+0x1de>
   7c2ad:	cmpq   $0x1,0x28(%rsi)
   7c2b2:	mov    %ecx,%ebp
   7c2b4:	je     7c310 <XcmsCIELabToCIEXYZ+0x80>
   7c2b6:	mov    (%rsi),%rax
   7c2b9:	lea    0x20(%rsp),%r12
   7c2be:	xor    %edx,%edx
   7c2c0:	mov    $0x1,%r8d
   7c2c6:	mov    $0x1,%ecx
   7c2cb:	mov    %rax,0x20(%rsp)
   7c2d0:	mov    0x8(%rsi),%rax
   7c2d4:	mov    %rax,0x28(%rsp)
   7c2d9:	mov    0x10(%rsi),%rax
   7c2dd:	mov    %rax,0x30(%rsp)
   7c2e2:	mov    0x18(%rsi),%rax
   7c2e6:	mov    %rax,0x38(%rsp)
   7c2eb:	mov    0x20(%rsi),%rax
   7c2ef:	mov    %rax,0x40(%rsp)
   7c2f4:	mov    0x28(%rsi),%rax
   7c2f8:	mov    %r12,%rsi
   7c2fb:	mov    %rax,0x48(%rsp)
   7c300:	callq  773a0 <_XcmsDIConvertColors>
   7c305:	test   %eax,%eax
   7c307:	mov    %r12,%rsi
   7c30a:	je     7c46e <XcmsCIELabToCIEXYZ+0x1de>
   7c310:	movsd  0x97fb0(%rip),%xmm0        # 1142c8 <_XkeyTable+0x72488>
   7c318:	ucomisd 0x8(%rsi),%xmm0
   7c31d:	jp     7c46e <XcmsCIELabToCIEXYZ+0x1de>
   7c323:	jne    7c46e <XcmsCIELabToCIEXYZ+0x1de>
   7c329:	test   %ebp,%ebp
   7c32b:	je     7c4d0 <XcmsCIELabToCIEXYZ+0x240>
   7c331:	cmpq   $0x4,0x28(%rbx)
   7c336:	movsd  (%rbx),%xmm0
   7c33a:	jne    7c46e <XcmsCIELabToCIEXYZ+0x1de>
   7c340:	movsd  0x97f50(%rip),%xmm2        # 114298 <_XkeyTable+0x72458>
   7c348:	ucomisd %xmm0,%xmm2
   7c34c:	ja     7c46e <XcmsCIELabToCIEXYZ+0x1de>
   7c352:	movsd  0x97f46(%rip),%xmm3        # 1142a0 <_XkeyTable+0x72460>
   7c35a:	ucomisd %xmm3,%xmm0
   7c35e:	ja     7c46e <XcmsCIELabToCIEXYZ+0x1de>
   7c364:	sub    $0x1,%ebp
   7c367:	mov    %rsp,%rax
   7c36a:	lea    0x3(%rbp,%rbp,2),%rcx
   7c36f:	movsd  0x97f90(%rip),%xmm11        # 114308 <_XkeyTable+0x724c8>
   7c378:	movsd  0x97f8f(%rip),%xmm10        # 114310 <_XkeyTable+0x724d0>
   7c381:	shl    $0x4,%rcx
   7c385:	movsd  0x97f9a(%rip),%xmm9        # 114328 <_XkeyTable+0x724e8>
   7c38e:	add    %rbx,%rcx
   7c391:	movsd  0x98a4e(%rip),%xmm8        # 114de8 <_XkeyTable+0x72fa8>
   7c39a:	movsd  0x97fbe(%rip),%xmm7        # 114360 <_XkeyTable+0x72520>
   7c3a2:	movsd  0x98a46(%rip),%xmm6        # 114df0 <_XkeyTable+0x72fb0>
   7c3aa:	movsd  0x98a46(%rip),%xmm5        # 114df8 <_XkeyTable+0x72fb8>
   7c3b2:	movsd  0x98a46(%rip),%xmm4        # 114e00 <_XkeyTable+0x72fc0>
   7c3ba:	jmp    7c3ca <XcmsCIELabToCIEXYZ+0x13a>
   7c3bc:	nopl   0x0(%rax)
   7c3c0:	ucomisd %xmm3,%xmm0
   7c3c4:	ja     7c46e <XcmsCIELabToCIEXYZ+0x1de>
   7c3ca:	movapd %xmm0,%xmm1
   7c3ce:	addsd  %xmm11,%xmm1
   7c3d3:	divsd  %xmm10,%xmm1
   7c3d8:	movapd %xmm1,%xmm12
   7c3dd:	mulsd  %xmm1,%xmm12
   7c3e2:	mulsd  %xmm1,%xmm12
   7c3e7:	ucomisd %xmm12,%xmm9
   7c3ec:	movsd  %xmm12,0x8(%rsp)
   7c3f3:	jbe    7c480 <XcmsCIELabToCIEXYZ+0x1f0>
   7c3f9:	movsd  0x8(%rbx),%xmm1
   7c3fe:	divsd  %xmm6,%xmm0
   7c402:	divsd  %xmm5,%xmm1
   7c406:	movsd  %xmm0,0x8(%rsp)
   7c40c:	addsd  %xmm0,%xmm1
   7c410:	mulsd  (%rsi),%xmm1
   7c414:	movsd  %xmm1,(%rsp)
   7c419:	movsd  0x10(%rbx),%xmm1
   7c41e:	divsd  %xmm4,%xmm1
   7c422:	subsd  %xmm1,%xmm0
   7c426:	mulsd  0x10(%rsi),%xmm0
   7c42b:	movsd  %xmm0,0x10(%rsp)
   7c431:	mov    (%rax),%rdx
   7c434:	add    $0x30,%rbx
   7c438:	movq   $0x1,-0x8(%rbx)
   7c440:	mov    %rdx,-0x30(%rbx)
   7c444:	mov    0x8(%rax),%rdx
   7c448:	mov    %rdx,-0x28(%rbx)
   7c44c:	mov    0x10(%rax),%rdx
   7c450:	mov    %rdx,-0x20(%rbx)
   7c454:	cmp    %rcx,%rbx
   7c457:	je     7c4d0 <XcmsCIELabToCIEXYZ+0x240>
   7c459:	cmpq   $0x4,0x28(%rbx)
   7c45e:	movsd  (%rbx),%xmm0
   7c462:	jne    7c46e <XcmsCIELabToCIEXYZ+0x1de>
   7c464:	ucomisd %xmm0,%xmm2
   7c468:	jbe    7c3c0 <XcmsCIELabToCIEXYZ+0x130>
   7c46e:	add    $0x50,%rsp
   7c472:	xor    %eax,%eax
   7c474:	pop    %rbx
   7c475:	pop    %rbp
   7c476:	pop    %r12
   7c478:	retq   
   7c479:	nopl   0x0(%rax)
   7c480:	movsd  0x8(%rbx),%xmm0
   7c485:	movsd  (%rsi),%xmm12
   7c48a:	divsd  %xmm8,%xmm0
   7c48f:	addsd  %xmm1,%xmm0
   7c493:	mulsd  %xmm0,%xmm12
   7c498:	mulsd  %xmm0,%xmm12
   7c49d:	mulsd  %xmm12,%xmm0
   7c4a2:	movsd  %xmm0,(%rsp)
   7c4a7:	movsd  0x10(%rbx),%xmm0
   7c4ac:	mulsd  %xmm7,%xmm0
   7c4b0:	subsd  %xmm0,%xmm1
   7c4b4:	movsd  0x10(%rsi),%xmm0
   7c4b9:	mulsd  %xmm1,%xmm0
   7c4bd:	mulsd  %xmm1,%xmm0
   7c4c1:	mulsd  %xmm0,%xmm1
   7c4c5:	movsd  %xmm1,0x10(%rsp)
   7c4cb:	jmpq   7c431 <XcmsCIELabToCIEXYZ+0x1a1>
   7c4d0:	add    $0x50,%rsp
   7c4d4:	mov    $0x1,%eax
   7c4d9:	pop    %rbx
   7c4da:	pop    %rbp
   7c4db:	pop    %r12
   7c4dd:	retq   
   7c4de:	xchg   %ax,%ax
