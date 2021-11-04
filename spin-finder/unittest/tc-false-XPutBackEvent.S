// TC_OUT
00000000000301a0 <XPutBackEvent>:
   301a0:	push   %rbp
   301a1:	push   %rbx
   301a2:	mov    %rdi,%rbx
   301a5:	sub    $0x18,%rsp
   301a9:	mov    0x968(%rdi),%rax
   301b0:	test   %rax,%rax
   301b3:	je     301c1 <XPutBackEvent+0x21>
   301b5:	mov    %rsi,0x8(%rsp)
   301ba:	callq  *(%rax)
   301bc:	mov    0x8(%rsp),%rsi
   301c1:	mov    %rbx,%rdi
   301c4:	callq  30010 <_XPutBackEvent>
   301c9:	mov    0x968(%rbx),%rdx
   301d0:	mov    %eax,%ebp
   301d2:	test   %rdx,%rdx
   301d5:	je     301dd <XPutBackEvent+0x3d>
   301d7:	mov    %rbx,%rdi
   301da:	callq  *0x8(%rdx)
   301dd:	add    $0x18,%rsp
   301e1:	mov    %ebp,%eax
   301e3:	pop    %rbx
   301e4:	pop    %rbp
   301e5:	retq   
   301e6:	nopw   %cs:0x0(%rax,%rax,1)
   301f0:	lea    0x1(%rdx),%r11
   301f4:	mov    %r9d,%r9d
   301f7:	push   %r12
   301f9:	push   %rbp
   301fa:	push   %rbx
   301fb:	lea    -0x1(%r9),%rbx
   301ff:	and    $0xfffffffffffffffe,%r11
   30203:	mov    0x20(%rsp),%ebp
   30207:	sub    %r11,%rcx
   3020a:	sub    %r11,%r8
   3020d:	cmp    $0xffffffffffffffff,%rbx
   30211:	je     30283 <XPutBackEvent+0xe3>
   30213:	nopl   0x0(%rax,%rax,1)
   30218:	cmp    %r11,%rdx
   3021b:	je     30235 <XPutBackEvent+0x95>
   3021d:	test   %rbx,%rbx
   30220:	jne    30235 <XPutBackEvent+0x95>
   30222:	sub    $0x2,%r11
   30226:	cmp    $0x1,%ebp
   30229:	je     30290 <XPutBackEvent+0xf0>
   3022b:	movzbl (%rdi,%r11,1),%eax
   30230:	mov    %al,0x1(%rsi,%r11,1)
   30235:	test   %r11,%r11
   30238:	jle    3029f <XPutBackEvent+0xff>
   3023a:	lea    -0x1(%r11),%rax
   3023e:	shr    %rax
   30241:	lea    0x2(%rax,%rax,1),%r12
   30246:	mov    %rsi,%rax
   30249:	lea    (%rdi,%r12,1),%r10
   3024d:	nopl   (%rax)
   30250:	movzbl 0x1(%rdi),%r9d
   30255:	add    $0x2,%rdi
   30259:	add    $0x2,%rax
   3025d:	mov    %r9b,-0x2(%rax)
   30261:	movzbl -0x2(%rdi),%r9d
   30266:	cmp    %r10,%rdi
   30269:	mov    %r9b,-0x1(%rax)
   3026d:	jne    30250 <XPutBackEvent+0xb0>
   3026f:	add    %r12,%rsi
   30272:	sub    $0x1,%rbx
   30276:	add    %r8,%rsi
   30279:	lea    (%r10,%rcx,1),%rdi
   3027d:	cmp    $0xffffffffffffffff,%rbx
   30281:	jne    30218 <XPutBackEvent+0x78>
   30283:	pop    %rbx
   30284:	pop    %rbp
   30285:	pop    %r12
   30287:	retq   
   30288:	nopl   0x0(%rax,%rax,1)
   30290:	movzbl 0x1(%rdi,%r11,1),%eax
   30296:	test   %r11,%r11
   30299:	mov    %al,(%rsi,%r11,1)
   3029d:	jg     3023a <XPutBackEvent+0x9a>
   3029f:	mov    %rdi,%r10
   302a2:	jmp    30272 <XPutBackEvent+0xd2>
   302a4:	data16 data16 nopw %cs:0x0(%rax,%rax,1)
   302b0:	lea    0x3(%rdx),%r11
   302b4:	mov    %r9d,%r9d
   302b7:	push   %r13
   302b9:	push   %r12
   302bb:	push   %rbp
   302bc:	mov    %rdx,%r13
   302bf:	push   %rbx
   302c0:	lea    -0x1(%r9),%rbx
   302c4:	and    $0xfffffffffffffffc,%r11
   302c8:	sub    %r11,%rcx
   302cb:	sub    %r11,%r8
   302ce:	and    $0x2,%r13d
   302d2:	cmp    $0xffffffffffffffff,%rbx
   302d6:	mov    0x28(%rsp),%r12d
   302db:	je     303a1 <XPutBackEvent+0x201>
   302e1:	nopl   0x0(%rax)
   302e8:	cmp    %r11,%rdx
   302eb:	je     30332 <XPutBackEvent+0x192>
   302ed:	test   %rbx,%rbx
   302f0:	jne    30332 <XPutBackEvent+0x192>
   302f2:	sub    $0x4,%r11
   302f6:	cmp    $0x1,%r12d
   302fa:	je     303b0 <XPutBackEvent+0x210>
   30300:	test   %r12d,%r12d
   30303:	jne    30332 <XPutBackEvent+0x192>
   30305:	mov    %rdx,%rax
   30308:	sub    %r11,%rax
   3030b:	cmp    $0x3,%rax
   3030f:	je     303f3 <XPutBackEvent+0x253>
   30315:	test   %r13,%r13
   30318:	je     30325 <XPutBackEvent+0x185>
   3031a:	movzbl 0x1(%rdi,%r11,1),%eax
   30320:	mov    %al,0x2(%rsi,%r11,1)
   30325:	movzbl (%rdi,%r11,1),%eax
   3032a:	lea    0x3(%r11),%r9
   3032e:	mov    %al,(%rsi,%r9,1)
   30332:	test   %r11,%r11
   30335:	jle    303ee <XPutBackEvent+0x24e>
   3033b:	lea    -0x1(%r11),%rax
   3033f:	shr    $0x2,%rax
   30343:	lea    0x4(,%rax,4),%rbp
   3034b:	mov    %rdi,%rax
   3034e:	lea    (%rsi,%rbp,1),%r10
   30352:	nopw   0x0(%rax,%rax,1)
   30358:	movzbl 0x3(%rax),%r9d
   3035d:	add    $0x4,%rsi
   30361:	add    $0x4,%rax
   30365:	mov    %r9b,-0x4(%rsi)
   30369:	movzbl -0x2(%rax),%r9d
   3036e:	mov    %r9b,-0x3(%rsi)
   30372:	movzbl -0x3(%rax),%r9d
   30377:	mov    %r9b,-0x2(%rsi)
   3037b:	movzbl -0x4(%rax),%r9d
   30380:	cmp    %rsi,%r10
   30383:	mov    %r9b,-0x1(%rsi)
   30387:	jne    30358 <XPutBackEvent+0x1b8>
   30389:	add    %rbp,%rdi
   3038c:	sub    $0x1,%rbx
   30390:	add    %rcx,%rdi
   30393:	lea    (%r10,%r8,1),%rsi
   30397:	cmp    $0xffffffffffffffff,%rbx
   3039b:	jne    302e8 <XPutBackEvent+0x148>
   303a1:	pop    %rbx
   303a2:	pop    %rbp
   303a3:	pop    %r12
   303a5:	pop    %r13
   303a7:	retq   
   303a8:	nopl   0x0(%rax,%rax,1)
   303b0:	movzbl 0x3(%rdi,%r11,1),%eax
   303b6:	test   %r13,%r13
   303b9:	mov    %al,(%rsi,%r11,1)
   303bd:	je     30403 <XPutBackEvent+0x263>
   303bf:	movzbl 0x2(%rdi,%r11,1),%eax
   303c5:	mov    %al,0x1(%rsi,%r11,1)
   303ca:	mov    %rdx,%rax
   303cd:	sub    %r11,%rax
   303d0:	cmp    $0x3,%rax
   303d4:	jne    30332 <XPutBackEvent+0x192>
   303da:	movzbl 0x1(%rdi,%r11,1),%eax
   303e0:	mov    %al,0x2(%rsi,%r11,1)
   303e5:	test   %r11,%r11
   303e8:	jg     3033b <XPutBackEvent+0x19b>
   303ee:	mov    %rsi,%r10
   303f1:	jmp    3038c <XPutBackEvent+0x1ec>
   303f3:	movzbl 0x2(%rdi,%r11,1),%eax
   303f9:	mov    %al,0x1(%rsi,%r11,1)
   303fe:	jmpq   30315 <XPutBackEvent+0x175>
   30403:	mov    %rdx,%rax
   30406:	sub    %r11,%rax
   30409:	cmp    $0x3,%rax
   3040d:	jne    30332 <XPutBackEvent+0x192>
   30413:	movzbl 0x1(%rdi,%r11,1),%eax
   30419:	mov    %al,0x2(%rsi,%r11,1)
   3041e:	jmp    303e5 <XPutBackEvent+0x245>
   30420:	lea    0x3(%rdx),%r11
   30424:	mov    %r9d,%r9d
   30427:	push   %r13
   30429:	push   %r12
   3042b:	push   %rbp
   3042c:	mov    %rdx,%r13
   3042f:	push   %rbx
   30430:	lea    -0x1(%r9),%rbx
   30434:	and    $0xfffffffffffffffc,%r11
   30438:	sub    %r11,%rcx
   3043b:	sub    %r11,%r8
   3043e:	and    $0x2,%r13d
   30442:	cmp    $0xffffffffffffffff,%rbx
   30446:	mov    0x28(%rsp),%r12d
   3044b:	je     30511 <XPutBackEvent+0x371>
   30451:	nopl   0x0(%rax)
   30458:	cmp    %r11,%rdx
   3045b:	je     304a2 <XPutBackEvent+0x302>
   3045d:	test   %rbx,%rbx
   30460:	jne    304a2 <XPutBackEvent+0x302>
   30462:	sub    $0x4,%r11
   30466:	cmp    $0x1,%r12d
   3046a:	je     30520 <XPutBackEvent+0x380>
   30470:	test   %r12d,%r12d
   30473:	jne    304a2 <XPutBackEvent+0x302>
   30475:	mov    %rdx,%rax
   30478:	sub    %r11,%rax
   3047b:	cmp    $0x3,%rax
   3047f:	je     30569 <XPutBackEvent+0x3c9>
   30485:	test   %r13,%r13
   30488:	je     30495 <XPutBackEvent+0x2f5>
   3048a:	movzbl 0x1(%rdi,%r11,1),%eax
   30490:	mov    %al,0x3(%rsi,%r11,1)
   30495:	movzbl (%rdi,%r11,1),%eax
   3049a:	lea    0x2(%r11),%r9
   3049e:	mov    %al,(%rsi,%r9,1)
   304a2:	test   %r11,%r11
   304a5:	jle    30564 <XPutBackEvent+0x3c4>
   304ab:	lea    -0x1(%r11),%rax
   304af:	shr    $0x2,%rax
   304b3:	lea    0x4(,%rax,4),%rbp
   304bb:	mov    %rdi,%rax
   304be:	lea    (%rsi,%rbp,1),%r10
   304c2:	nopw   0x0(%rax,%rax,1)
   304c8:	movzbl 0x2(%rax),%r9d
   304cd:	add    $0x4,%rsi
   304d1:	add    $0x4,%rax
   304d5:	mov    %r9b,-0x4(%rsi)
   304d9:	movzbl -0x1(%rax),%r9d
   304de:	mov    %r9b,-0x3(%rsi)
   304e2:	movzbl -0x4(%rax),%r9d
   304e7:	mov    %r9b,-0x2(%rsi)
   304eb:	movzbl -0x3(%rax),%r9d
   304f0:	cmp    %r10,%rsi
   304f3:	mov    %r9b,-0x1(%rsi)
   304f7:	jne    304c8 <XPutBackEvent+0x328>
   304f9:	add    %rbp,%rdi
   304fc:	sub    $0x1,%rbx
   30500:	add    %rcx,%rdi
   30503:	lea    (%r10,%r8,1),%rsi
   30507:	cmp    $0xffffffffffffffff,%rbx
   3050b:	jne    30458 <XPutBackEvent+0x2b8>
   30511:	pop    %rbx
   30512:	pop    %rbp
   30513:	pop    %r12
   30515:	pop    %r13
   30517:	retq   
   30518:	nopl   0x0(%rax,%rax,1)
   30520:	movzbl 0x3(%rdi,%r11,1),%eax
   30526:	test   %r13,%r13
   30529:	lea    0x1(%r11),%r9
   3052d:	lea    0x3(%r11),%r10
   30531:	mov    %al,0x1(%rsi,%r11,1)
   30536:	je     30578 <XPutBackEvent+0x3d8>
   30538:	movzbl 0x2(%rdi,%r11,1),%eax
   3053e:	mov    %al,(%rsi,%r11,1)
   30542:	mov    %rdx,%rax
   30545:	sub    %r11,%rax
   30548:	cmp    $0x3,%rax
   3054c:	jne    304a2 <XPutBackEvent+0x302>
   30552:	movzbl (%rdi,%r9,1),%eax
   30557:	mov    %al,(%rsi,%r10,1)
   3055b:	test   %r11,%r11
   3055e:	jg     304ab <XPutBackEvent+0x30b>
   30564:	mov    %rsi,%r10
   30567:	jmp    304fc <XPutBackEvent+0x35c>
   30569:	movzbl 0x2(%rdi,%r11,1),%eax
   3056f:	mov    %al,(%rsi,%r11,1)
   30573:	jmpq   30485 <XPutBackEvent+0x2e5>
   30578:	mov    %rdx,%rax
   3057b:	sub    %r11,%rax
   3057e:	cmp    $0x3,%rax
   30582:	jne    304a2 <XPutBackEvent+0x302>
   30588:	movzbl (%rdi,%r9,1),%eax
   3058d:	mov    %al,(%rsi,%r10,1)
   30591:	jmp    3055b <XPutBackEvent+0x3bb>
   30593:	data16 data16 data16 nopw %cs:0x0(%rax,%rax,1)
   305a0:	sub    %rdx,%rcx
   305a3:	sub    %rdx,%r8
   305a6:	test   %r9d,%r9d
   305a9:	je     305fd <XPutBackEvent+0x45d>
   305ab:	push   %rbx
   305ac:	xor    %r11d,%r11d
   305af:	mov    %r9d,%ebx
   305b2:	nopw   0x0(%rax,%rax,1)
   305b8:	test   %rdx,%rdx
   305bb:	jle    305ed <XPutBackEvent+0x44d>
   305bd:	lea    0x6f6fc(%rip),%r10        # 9fcc0 <_Xevent_to_mask+0x28c0>
   305c4:	xor    %eax,%eax
   305c6:	nopw   %cs:0x0(%rax,%rax,1)
   305d0:	movzbl (%rdi,%rax,1),%r9d
   305d5:	movzbl (%r10,%r9,1),%r9d
   305da:	mov    %r9b,(%rsi,%rax,1)
   305de:	add    $0x1,%rax
   305e2:	cmp    %rdx,%rax
   305e5:	jne    305d0 <XPutBackEvent+0x430>
   305e7:	add    %rdx,%rsi
   305ea:	add    %rdx,%rdi
   305ed:	add    $0x1,%r11
   305f1:	add    %rcx,%rdi
   305f4:	add    %r8,%rsi
   305f7:	cmp    %rbx,%r11
   305fa:	jne    305b8 <XPutBackEvent+0x418>
   305fc:	pop    %rbx
   305fd:	repz retq 
   305ff:	nop
   30600:	push   %r13
   30602:	mov    %r9d,%r9d
   30605:	push   %r12
   30607:	push   %rbp
   30608:	push   %rbx
   30609:	lea    0x1(%rdx),%rbx
   3060d:	lea    -0x1(%r9),%rbp
   30611:	mov    0x28(%rsp),%r12d
   30616:	and    $0xfffffffffffffffe,%rbx
   3061a:	sub    %rbx,%rcx
   3061d:	sub    %rbx,%r8
   30620:	cmp    $0xffffffffffffffff,%rbp
   30624:	je     306c1 <XPutBackEvent+0x521>
   3062a:	nopw   0x0(%rax,%rax,1)
   30630:	cmp    %rbx,%rdx
   30633:	je     3065c <XPutBackEvent+0x4bc>
   30635:	test   %rbp,%rbp
   30638:	jne    3065c <XPutBackEvent+0x4bc>
   3063a:	sub    $0x2,%rbx
   3063e:	cmp    $0x1,%r12d
   30642:	je     306d0 <XPutBackEvent+0x530>
   30648:	movzbl (%rdi,%rbx,1),%eax
   3064c:	lea    0x6f66d(%rip),%r9        # 9fcc0 <_Xevent_to_mask+0x28c0>
   30653:	movzbl (%r9,%rax,1),%eax
   30658:	mov    %al,0x1(%rsi,%rbx,1)
   3065c:	test   %rbx,%rbx
   3065f:	jle    306ed <XPutBackEvent+0x54d>
   30665:	lea    -0x1(%rbx),%rax
   30669:	lea    0x6f650(%rip),%r9        # 9fcc0 <_Xevent_to_mask+0x28c0>
   30670:	shr    %rax
   30673:	lea    0x2(%rax,%rax,1),%r13
   30678:	mov    %rsi,%rax
   3067b:	lea    (%rdi,%r13,1),%r11
   3067f:	nop
   30680:	movzbl 0x1(%rdi),%r10d
   30685:	add    $0x2,%rdi
   30689:	add    $0x2,%rax
   3068d:	movzbl (%r9,%r10,1),%r10d
   30692:	mov    %r10b,-0x2(%rax)
   30696:	movzbl -0x2(%rdi),%r10d
   3069b:	cmp    %r11,%rdi
   3069e:	movzbl (%r9,%r10,1),%r10d
   306a3:	mov    %r10b,-0x1(%rax)
   306a7:	jne    30680 <XPutBackEvent+0x4e0>
   306a9:	add    %r13,%rsi
   306ac:	sub    $0x1,%rbp
   306b0:	add    %r8,%rsi
   306b3:	lea    (%r11,%rcx,1),%rdi
   306b7:	cmp    $0xffffffffffffffff,%rbp
   306bb:	jne    30630 <XPutBackEvent+0x490>
   306c1:	pop    %rbx
   306c2:	pop    %rbp
   306c3:	pop    %r12
   306c5:	pop    %r13
   306c7:	retq   
   306c8:	nopl   0x0(%rax,%rax,1)
   306d0:	movzbl 0x1(%rdi,%rbx,1),%eax
   306d5:	lea    0x6f5e4(%rip),%r9        # 9fcc0 <_Xevent_to_mask+0x28c0>
   306dc:	test   %rbx,%rbx
   306df:	movzbl (%r9,%rax,1),%eax
   306e4:	mov    %al,(%rsi,%rbx,1)
   306e7:	jg     30665 <XPutBackEvent+0x4c5>
   306ed:	mov    %rdi,%r11
   306f0:	jmp    306ac <XPutBackEvent+0x50c>
   306f2:	data16 data16 data16 data16 nopw %cs:0x0(%rax,%rax,1)
   30700:	push   %r14
   30702:	mov    %r9d,%r9d
   30705:	push   %r13
   30707:	push   %r12
   30709:	push   %rbp
   3070a:	lea    -0x1(%r9),%rbp
   3070e:	push   %rbx
   3070f:	lea    0x3(%rdx),%rbx
   30713:	mov    %rdx,%r14
   30716:	and    $0x2,%r14d
   3071a:	mov    0x30(%rsp),%r13d
   3071f:	and    $0xfffffffffffffffc,%rbx
   30723:	sub    %rbx,%rcx
   30726:	sub    %rbx,%r8
   30729:	cmp    $0xffffffffffffffff,%rbp
   3072d:	je     3081d <XPutBackEvent+0x67d>
   30733:	nopl   0x0(%rax,%rax,1)
   30738:	cmp    %rbx,%rdx
   3073b:	je     30790 <XPutBackEvent+0x5f0>
   3073d:	test   %rbp,%rbp
   30740:	jne    30790 <XPutBackEvent+0x5f0>
   30742:	sub    $0x4,%rbx
   30746:	cmp    $0x1,%r13d
   3074a:	je     30830 <XPutBackEvent+0x690>
   30750:	test   %r13d,%r13d
   30753:	jne    30790 <XPutBackEvent+0x5f0>
   30755:	mov    %rdx,%rax
   30758:	lea    0x6f561(%rip),%r9        # 9fcc0 <_Xevent_to_mask+0x28c0>
   3075f:	sub    %rbx,%rax
   30762:	cmp    $0x3,%rax
   30766:	je     30888 <XPutBackEvent+0x6e8>
   3076c:	test   %r14,%r14
   3076f:	je     3077f <XPutBackEvent+0x5df>
   30771:	movzbl 0x1(%rdi,%rbx,1),%eax
   30776:	movzbl (%r9,%rax,1),%eax
   3077b:	mov    %al,0x2(%rsi,%rbx,1)
   3077f:	movzbl (%rdi,%rbx,1),%eax
   30783:	lea    0x3(%rbx),%r10
   30787:	movzbl (%r9,%rax,1),%eax
   3078c:	mov    %al,(%rsi,%r10,1)
   30790:	test   %rbx,%rbx
   30793:	jle    30883 <XPutBackEvent+0x6e3>
   30799:	lea    -0x1(%rbx),%rax
   3079d:	lea    0x6f51c(%rip),%r9        # 9fcc0 <_Xevent_to_mask+0x28c0>
   307a4:	shr    $0x2,%rax
   307a8:	lea    0x4(,%rax,4),%r12
   307b0:	mov    %rdi,%rax
   307b3:	lea    (%rsi,%r12,1),%r11
   307b7:	nopw   0x0(%rax,%rax,1)
   307c0:	movzbl 0x3(%rax),%r10d
   307c5:	add    $0x4,%rsi
   307c9:	add    $0x4,%rax
   307cd:	movzbl (%r9,%r10,1),%r10d
   307d2:	mov    %r10b,-0x4(%rsi)
   307d6:	movzbl -0x2(%rax),%r10d
   307db:	movzbl (%r9,%r10,1),%r10d
   307e0:	mov    %r10b,-0x3(%rsi)
   307e4:	movzbl -0x3(%rax),%r10d
   307e9:	movzbl (%r9,%r10,1),%r10d
   307ee:	mov    %r10b,-0x2(%rsi)
   307f2:	movzbl -0x4(%rax),%r10d
   307f7:	cmp    %r11,%rsi
   307fa:	movzbl (%r9,%r10,1),%r10d
   307ff:	mov    %r10b,-0x1(%rsi)
   30803:	jne    307c0 <XPutBackEvent+0x620>
   30805:	add    %r12,%rdi
   30808:	sub    $0x1,%rbp
   3080c:	add    %rcx,%rdi
   3080f:	lea    (%r11,%r8,1),%rsi
   30813:	cmp    $0xffffffffffffffff,%rbp
   30817:	jne    30738 <XPutBackEvent+0x598>
   3081d:	pop    %rbx
   3081e:	pop    %rbp
   3081f:	pop    %r12
   30821:	pop    %r13
   30823:	pop    %r14
   30825:	retq   
   30826:	nopw   %cs:0x0(%rax,%rax,1)
   30830:	movzbl 0x3(%rdi,%rbx,1),%r9d
   30836:	lea    0x6f483(%rip),%rax        # 9fcc0 <_Xevent_to_mask+0x28c0>
   3083d:	test   %r14,%r14
   30840:	movzbl (%rax,%r9,1),%r9d
   30845:	mov    %r9b,(%rsi,%rbx,1)
   30849:	je     308a2 <XPutBackEvent+0x702>
   3084b:	movzbl 0x2(%rdi,%rbx,1),%r9d
   30851:	movzbl (%rax,%r9,1),%r9d
   30856:	mov    %r9b,0x1(%rsi,%rbx,1)
   3085b:	mov    %rdx,%r9
   3085e:	sub    %rbx,%r9
   30861:	cmp    $0x3,%r9
   30865:	jne    30790 <XPutBackEvent+0x5f0>
   3086b:	movzbl 0x1(%rdi,%rbx,1),%r9d
   30871:	movzbl (%rax,%r9,1),%eax
   30876:	mov    %al,0x2(%rsi,%rbx,1)
   3087a:	test   %rbx,%rbx
   3087d:	jg     30799 <XPutBackEvent+0x5f9>
   30883:	mov    %rsi,%r11
   30886:	jmp    30808 <XPutBackEvent+0x668>
   30888:	movzbl 0x2(%rdi,%rbx,1),%eax
   3088d:	lea    0x6f42c(%rip),%r9        # 9fcc0 <_Xevent_to_mask+0x28c0>
   30894:	movzbl (%r9,%rax,1),%eax
   30899:	mov    %al,0x1(%rsi,%rbx,1)
   3089d:	jmpq   3076c <XPutBackEvent+0x5cc>
   308a2:	mov    %rdx,%r9
   308a5:	sub    %rbx,%r9
   308a8:	cmp    $0x3,%r9
   308ac:	jne    30790 <XPutBackEvent+0x5f0>
   308b2:	movzbl 0x1(%rdi,%rbx,1),%r9d
   308b8:	movzbl (%rax,%r9,1),%eax
   308bd:	mov    %al,0x2(%rsi,%rbx,1)
   308c1:	jmp    3087a <XPutBackEvent+0x6da>
   308c3:	data16 data16 data16 nopw %cs:0x0(%rax,%rax,1)
   308d0:	push   %r14
   308d2:	mov    %r9d,%r9d
   308d5:	push   %r13
   308d7:	push   %r12
   308d9:	push   %rbp
   308da:	lea    -0x1(%r9),%rbp
   308de:	push   %rbx
   308df:	lea    0x3(%rdx),%rbx
   308e3:	mov    %rdx,%r14
   308e6:	and    $0x2,%r14d
   308ea:	mov    0x30(%rsp),%r13d
   308ef:	and    $0xfffffffffffffffc,%rbx
   308f3:	sub    %rbx,%rcx
   308f6:	sub    %rbx,%r8
   308f9:	cmp    $0xffffffffffffffff,%rbp
   308fd:	je     309ed <XPutBackEvent+0x84d>
   30903:	nopl   0x0(%rax,%rax,1)
   30908:	cmp    %rbx,%rdx
   3090b:	je     30960 <XPutBackEvent+0x7c0>
   3090d:	test   %rbp,%rbp
   30910:	jne    30960 <XPutBackEvent+0x7c0>
   30912:	sub    $0x4,%rbx
   30916:	cmp    $0x1,%r13d
   3091a:	je     30a00 <XPutBackEvent+0x860>
   30920:	test   %r13d,%r13d
   30923:	jne    30960 <XPutBackEvent+0x7c0>
   30925:	mov    %rdx,%rax
   30928:	lea    0x6f391(%rip),%r9        # 9fcc0 <_Xevent_to_mask+0x28c0>
   3092f:	sub    %rbx,%rax
   30932:	cmp    $0x3,%rax
   30936:	je     30a62 <XPutBackEvent+0x8c2>
   3093c:	test   %r14,%r14
   3093f:	je     3094f <XPutBackEvent+0x7af>
   30941:	movzbl 0x1(%rdi,%rbx,1),%eax
   30946:	movzbl (%r9,%rax,1),%eax
   3094b:	mov    %al,0x3(%rsi,%rbx,1)
   3094f:	movzbl (%rdi,%rbx,1),%eax
   30953:	lea    0x2(%rbx),%r10
   30957:	movzbl (%r9,%rax,1),%eax
   3095c:	mov    %al,(%rsi,%r10,1)
   30960:	test   %rbx,%rbx
   30963:	jle    30a5a <XPutBackEvent+0x8ba>
   30969:	lea    -0x1(%rbx),%rax
   3096d:	lea    0x6f34c(%rip),%r9        # 9fcc0 <_Xevent_to_mask+0x28c0>
   30974:	shr    $0x2,%rax
   30978:	lea    0x4(,%rax,4),%r12
   30980:	mov    %rdi,%rax
   30983:	lea    (%rsi,%r12,1),%r11
   30987:	nopw   0x0(%rax,%rax,1)
   30990:	movzbl 0x2(%rax),%r10d
   30995:	add    $0x4,%rsi
   30999:	add    $0x4,%rax
   3099d:	movzbl (%r9,%r10,1),%r10d
   309a2:	mov    %r10b,-0x4(%rsi)
   309a6:	movzbl -0x1(%rax),%r10d
   309ab:	movzbl (%r9,%r10,1),%r10d
   309b0:	mov    %r10b,-0x3(%rsi)
   309b4:	movzbl -0x4(%rax),%r10d
   309b9:	movzbl (%r9,%r10,1),%r10d
   309be:	mov    %r10b,-0x2(%rsi)
   309c2:	movzbl -0x3(%rax),%r10d
   309c7:	cmp    %r11,%rsi
   309ca:	movzbl (%r9,%r10,1),%r10d
   309cf:	mov    %r10b,-0x1(%rsi)
   309d3:	jne    30990 <XPutBackEvent+0x7f0>
   309d5:	add    %r12,%rdi
   309d8:	sub    $0x1,%rbp
   309dc:	add    %rcx,%rdi
   309df:	lea    (%r11,%r8,1),%rsi
   309e3:	cmp    $0xffffffffffffffff,%rbp
   309e7:	jne    30908 <XPutBackEvent+0x768>
   309ed:	pop    %rbx
   309ee:	pop    %rbp
   309ef:	pop    %r12
   309f1:	pop    %r13
   309f3:	pop    %r14
   309f5:	retq   
   309f6:	nopw   %cs:0x0(%rax,%rax,1)
   30a00:	movzbl 0x3(%rdi,%rbx,1),%r9d
   30a06:	lea    0x6f2b3(%rip),%rax        # 9fcc0 <_Xevent_to_mask+0x28c0>
   30a0d:	test   %r14,%r14
   30a10:	lea    0x1(%rbx),%r10
   30a14:	lea    0x3(%rbx),%r11
   30a18:	movzbl (%rax,%r9,1),%r9d
   30a1d:	mov    %r9b,0x1(%rsi,%rbx,1)
   30a22:	je     30a7b <XPutBackEvent+0x8db>
   30a24:	movzbl 0x2(%rdi,%rbx,1),%r9d
   30a2a:	movzbl (%rax,%r9,1),%r9d
   30a2f:	mov    %r9b,(%rsi,%rbx,1)
   30a33:	mov    %rdx,%r9
   30a36:	sub    %rbx,%r9
   30a39:	cmp    $0x3,%r9
   30a3d:	jne    30960 <XPutBackEvent+0x7c0>
   30a43:	movzbl (%rdi,%r10,1),%r9d
   30a48:	movzbl (%rax,%r9,1),%eax
   30a4d:	mov    %al,(%rsi,%r11,1)
   30a51:	test   %rbx,%rbx
   30a54:	jg     30969 <XPutBackEvent+0x7c9>
   30a5a:	mov    %rsi,%r11
   30a5d:	jmpq   309d8 <XPutBackEvent+0x838>
   30a62:	movzbl 0x2(%rdi,%rbx,1),%eax
   30a67:	lea    0x6f252(%rip),%r9        # 9fcc0 <_Xevent_to_mask+0x28c0>
   30a6e:	movzbl (%r9,%rax,1),%eax
   30a73:	mov    %al,(%rsi,%rbx,1)
   30a76:	jmpq   3093c <XPutBackEvent+0x79c>
   30a7b:	mov    %rdx,%r9
   30a7e:	sub    %rbx,%r9
   30a81:	cmp    $0x3,%r9
   30a85:	jne    30960 <XPutBackEvent+0x7c0>
   30a8b:	movzbl (%rdi,%r10,1),%r9d
   30a90:	movzbl (%rax,%r9,1),%eax
   30a95:	mov    %al,(%rsi,%r11,1)
   30a99:	jmp    30a51 <XPutBackEvent+0x8b1>
   30a9b:	nopl   0x0(%rax,%rax,1)
   30aa0:	cmp    %r8,%rcx
   30aa3:	push   %r14
   30aa5:	mov    %rsi,%r10
   30aa8:	push   %r13
   30aaa:	mov    %r9d,%r9d
   30aad:	push   %r12
   30aaf:	mov    %r8,%r13
   30ab2:	push   %rbp
   30ab3:	mov    %rcx,%r12
   30ab6:	push   %rbx
   30ab7:	mov    %rdi,%rbp
   30aba:	je     30afa <XPutBackEvent+0x95a>
   30abc:	lea    -0x1(%r9),%rbx
   30ac0:	movslq %edx,%r14
   30ac3:	cmp    $0xffffffffffffffff,%rbx
   30ac7:	je     30af1 <XPutBackEvent+0x951>
   30ac9:	nopl   0x0(%rax)
   30ad0:	mov    %rbp,%rsi
   30ad3:	mov    %r10,%rdi
   30ad6:	mov    %r14,%rdx
   30ad9:	callq  18450 <memcpy@plt>
   30ade:	sub    $0x1,%rbx
   30ae2:	mov    %rax,%r10
   30ae5:	add    %r12,%rbp
   30ae8:	add    %r13,%r10
   30aeb:	cmp    $0xffffffffffffffff,%rbx
   30aef:	jne    30ad0 <XPutBackEvent+0x930>
   30af1:	pop    %rbx
   30af2:	pop    %rbp
   30af3:	pop    %r12
   30af5:	pop    %r13
   30af7:	pop    %r14
   30af9:	retq   
   30afa:	sub    $0x1,%r9
   30afe:	mov    %rdi,%rsi
   30b01:	mov    %r10,%rdi
   30b04:	imul   %ecx,%r9d
   30b08:	pop    %rbx
   30b09:	pop    %rbp
   30b0a:	pop    %r12
   30b0c:	pop    %r13
   30b0e:	pop    %r14
   30b10:	add    %r9d,%edx
   30b13:	movslq %edx,%rdx
   30b16:	jmpq   18450 <memcpy@plt>
   30b1b:	nopl   0x0(%rax,%rax,1)
   30b20:	push   %r15
   30b22:	push   %r14
   30b24:	mov    %r9d,%r15d
   30b27:	push   %r13
   30b29:	push   %r12
   30b2b:	mov    %rdi,%r12
   30b2e:	push   %rbp
   30b2f:	push   %rbx
   30b30:	mov    %rcx,%rbx
   30b33:	sub    $0x88,%rsp
   30b3a:	mov    0xc0(%rsp),%eax
   30b41:	mov    %rdx,0x28(%rsp)
   30b46:	mov    0xc8(%rsp),%r14d
   30b4e:	mov    0xd0(%rsp),%r13d
   30b56:	mov    0xd8(%rsp),%ebp
   30b5d:	mov    %rsi,0x20(%rsp)
   30b62:	mov    %eax,0x18(%rsp)
   30b66:	mov    0xe0(%rsp),%eax
   30b6d:	mov    %r8d,0x8(%rsp)
   30b72:	movslq %eax,%rdx
   30b75:	mov    0xe8(%rsp),%eax
   30b7c:	mov    %edx,0x30(%rsp)
   30b80:	mov    %rdx,0x48(%rsp)
   30b85:	mov    %eax,0x38(%rsp)
   30b89:	sub    $0x1,%eax
   30b8c:	cltq   
   30b8e:	mov    %rax,0x40(%rsp)
   30b93:	not    %rax
   30b96:	mov    %rax,0x50(%rsp)
   30b9b:	test   %ebp,%ebp
   30b9d:	je     30c7e <XPutBackEvent+0xade>
   30ba3:	test   %r13d,%r13d
   30ba6:	je     30c7e <XPutBackEvent+0xade>
   30bac:	mov    0xc0(%r12),%eax
   30bb4:	cmp    $0x10000,%eax
   30bb9:	ja     30c90 <XPutBackEvent+0xaf0>
   30bbf:	lea    -0x18(,%rax,4),%edx
   30bc6:	mov    %edx,%eax
   30bc8:	cmpl   $0x1,0x30(%rbx)
   30bcc:	je     30bd8 <XPutBackEvent+0xa38>
   30bce:	cmpl   $0x2,0xc(%rbx)
   30bd2:	je     30ca0 <XPutBackEvent+0xb00>
   30bd8:	mov    0x54(%r12),%edi
   30bdd:	mov    0x8(%rsp),%esi
   30be1:	add    0x8(%rbx),%esi
   30be4:	lea    -0x1(%rdi),%ecx
   30be7:	mov    0x58(%r12),%edi
   30bec:	and    %ecx,%esi
   30bee:	lea    -0x1(%rdi),%ecx
   30bf1:	movslq %esi,%r8
   30bf4:	mov    %r13d,%edi
   30bf7:	add    %r8,%rdi
   30bfa:	movslq %ecx,%rcx
   30bfd:	add    %rcx,%rdi
   30c00:	not    %rcx
   30c03:	and    %rdi,%rcx
   30c06:	sar    $0x3,%rcx
   30c0a:	imul   0x28(%rbx),%ecx
   30c0e:	mov    %ecx,%edi
   30c10:	imul   %ebp,%edi
   30c13:	cmp    %edx,%edi
   30c15:	jbe    30cc6 <XPutBackEvent+0xb26>
   30c1b:	cmp    $0x1,%ebp
   30c1e:	jbe    31230 <XPutBackEvent+0x1090>
   30c24:	cltd   
   30c25:	mov    0x38(%rsp),%esi
   30c29:	mov    %r15d,%r9d
   30c2c:	idiv   %ecx
   30c2e:	mov    $0x1,%edx
   30c33:	mov    %rbx,%rcx
   30c36:	mov    %r12,%rdi
   30c39:	push   %rsi
   30c3a:	test   %eax,%eax
   30c3c:	cmove  %edx,%eax
   30c3f:	mov    0x38(%rsp),%edx
   30c43:	push   %rdx
   30c44:	push   %rax
   30c45:	mov    %eax,0x28(%rsp)
   30c49:	push   %r13
   30c4b:	push   %r14
   30c4d:	mov    0x40(%rsp),%eax
   30c51:	push   %rax
   30c52:	mov    0x38(%rsp),%r8d
   30c57:	mov    0x58(%rsp),%rdx
   30c5c:	mov    0x50(%rsp),%rsi
   30c61:	callq  30b20 <XPutBackEvent+0x980>
   30c66:	mov    0x40(%rsp),%eax
   30c6a:	add    $0x30,%rsp
   30c6e:	sub    %eax,%ebp
   30c70:	add    %eax,%r14d
   30c73:	add    %eax,%r15d
   30c76:	test   %ebp,%ebp
   30c78:	jne    30ba3 <XPutBackEvent+0xa03>
   30c7e:	add    $0x88,%rsp
   30c85:	pop    %rbx
   30c86:	pop    %rbp
   30c87:	pop    %r12
   30c89:	pop    %r13
   30c8b:	pop    %r14
   30c8d:	pop    %r15
   30c8f:	retq   
   30c90:	mov    $0x3ffe8,%edx
   30c95:	mov    $0x3ffe8,%eax
   30c9a:	jmpq   30bc8 <XPutBackEvent+0xa28>
   30c9f:	nop
   30ca0:	mov    %r13d,%ecx
   30ca3:	xor    %esi,%esi
   30ca5:	imul   0x48(%rsp),%rcx
   30cab:	add    0x40(%rsp),%rcx
   30cb0:	and    0x50(%rsp),%rcx
   30cb5:	shr    $0x3,%rcx
   30cb9:	mov    %ecx,%edi
   30cbb:	imul   %ebp,%edi
   30cbe:	cmp    %edx,%edi
   30cc0:	ja     30c1b <XPutBackEvent+0xa7b>
   30cc6:	mov    $0x18,%edx
   30ccb:	mov    $0x48,%esi
   30cd0:	mov    %r12,%rdi
   30cd3:	callq  3eec0 <_XGetRequest>
   30cd8:	mov    0x20(%rsp),%edx
   30cdc:	mov    %rax,%rsi
   30cdf:	mov    %rax,0x40(%rsp)
   30ce4:	mov    %r13d,%r8d
   30ce7:	mov    %edx,0x4(%rax)
   30cea:	mov    0x28(%rsp),%rax
   30cef:	movzwl %bp,%edx
   30cf2:	mov    0x8(%rax),%rax
   30cf6:	mov    %r14w,0x12(%rsi)
   30cfb:	mov    %r13w,0xc(%rsi)
   30d00:	mov    %bp,0xe(%rsi)
   30d04:	mov    %eax,0x8(%rsi)
   30d07:	movzwl 0x18(%rsp),%eax
   30d0c:	mov    %ax,0x10(%rsi)
   30d10:	mov    0x28(%rbx),%eax
   30d13:	mov    %al,0x15(%rsi)
   30d16:	mov    0xc(%rbx),%ecx
   30d19:	mov    %cl,0x1(%rsi)
   30d1c:	cmpl   $0x1,0x30(%rbx)
   30d20:	je     30d2c <XPutBackEvent+0xb8c>
   30d22:	cmpl   $0x2,0xc(%rbx)
   30d26:	je     3133e <XPutBackEvent+0x119e>
   30d2c:	movzbl 0x54(%r12),%eax
   30d32:	mov    0x8(%rsp),%esi
   30d36:	add    0x8(%rbx),%esi
   30d39:	mov    0x40(%rsp),%rdi
   30d3e:	sub    $0x1,%eax
   30d41:	and    %esi,%eax
   30d43:	movzbl %al,%r10d
   30d47:	mov    %al,0x14(%rdi)
   30d4a:	sub    %r10d,%esi
   30d4d:	shr    $0x3,%esi
   30d50:	test   %al,%al
   30d52:	mov    %esi,0x50(%rsp)
   30d56:	mov    %rsi,0x28(%rsp)
   30d5b:	je     30d66 <XPutBackEvent+0xbc6>
   30d5d:	cmp    $0x2,%cl
   30d60:	je     31290 <XPutBackEvent+0x10f0>
   30d66:	mov    0x58(%r12),%esi
   30d6b:	movzwl %r8w,%edi
   30d6f:	movzbl %al,%ecx
   30d72:	mov    %rdi,%rax
   30d75:	add    %rcx,%rax
   30d78:	sub    $0x1,%esi
   30d7b:	movslq %esi,%rsi
   30d7e:	add    %rsi,%rax
   30d81:	not    %rsi
   30d84:	and    %rsi,%rax
   30d87:	mov    $0x2,%esi
   30d8c:	shr    $0x3,%rax
   30d90:	imul   %rax,%rdx
   30d94:	mov    %rax,0x10(%rsp)
   30d99:	mov    %rdx,0x18(%rsp)
   30d9e:	mov    %rdx,%rax
   30da1:	movslq 0x28(%rbx),%rdx
   30da5:	imul   %rax,%rdx
   30da9:	lea    0x3(%rdx),%rax
   30dad:	mov    %rdx,0x48(%rsp)
   30db2:	mov    0x40(%rsp),%rdx
   30db7:	mov    %rax,0x8(%rsp)
   30dbc:	sar    $0x2,%rax
   30dc0:	add    %ax,0x2(%rdx)
   30dc4:	mov    0x1c(%rbx),%r9d
   30dc8:	cmp    $0x20,%r9d
   30dcc:	je     30dd8 <XPutBackEvent+0xc38>
   30dce:	xor    %esi,%esi
   30dd0:	cmp    $0x10,%r9d
   30dd4:	sete   %sil
   30dd8:	mov    0x20(%rbx),%r11d
   30ddc:	mov    0x18(%rbx),%r14d
   30de0:	xor    %ecx,%ecx
   30de2:	mov    $0x0,%edx
   30de7:	mov    $0x6,%eax
   30dec:	mov    0x54(%r12),%edi
   30df1:	cmp    $0x1,%r11d
   30df5:	setne  %cl
   30df8:	cmp    $0x1,%r14d
   30dfc:	lea    (%rcx,%rcx,2),%ecx
   30dff:	cmove  %edx,%eax
   30e02:	mov    $0x2,%dl
   30e04:	add    %ecx,%eax
   30e06:	add    %esi,%eax
   30e08:	cmp    $0x20,%edi
   30e0b:	mov    %eax,0x20(%rsp)
   30e0f:	je     30e19 <XPutBackEvent+0xc79>
   30e11:	xor    %edx,%edx
   30e13:	cmp    $0x10,%edi
   30e16:	sete   %dl
   30e19:	mov    0x5c(%r12),%eax
   30e1e:	mov    0x50(%r12),%r13d
   30e23:	xor    %esi,%esi
   30e25:	mov    $0x0,%ecx
   30e2a:	cmp    $0x1,%eax
   30e2d:	mov    %eax,0x38(%rsp)
   30e31:	mov    $0x6,%eax
   30e36:	setne  %sil
   30e3a:	cmp    $0x1,%r13d
   30e3e:	cmovne %eax,%ecx
   30e41:	movslq 0x20(%rsp),%rax
   30e46:	lea    (%rsi,%rsi,2),%esi
   30e49:	add    %esi,%ecx
   30e4b:	add    %edx,%ecx
   30e4d:	lea    0x3022ec(%rip),%rdx        # 333140 <_XcmsCIEXYZ_prefix+0x21e22b>
   30e54:	cmp    $0x20,%r9d
   30e58:	lea    (%rax,%rax,2),%rax
   30e5c:	movslq %ecx,%rcx
   30e5f:	lea    (%rcx,%rax,4),%rax
   30e63:	mov    (%rdx,%rax,8),%rax
   30e67:	mov    %rax,0x30(%rsp)
   30e6c:	mov    $0x2,%eax
   30e71:	je     30e7c <XPutBackEvent+0xcdc>
   30e73:	xor    %eax,%eax
   30e75:	cmp    $0x10,%r9d
   30e79:	sete   %al
   30e7c:	xor    %ecx,%ecx
   30e7e:	cmp    $0x1,%r11d
   30e82:	mov    $0x6,%esi
   30e87:	setne  %cl
   30e8a:	mov    $0x0,%edx
   30e8f:	cmp    $0x1,%r14d
   30e93:	lea    (%rcx,%rcx,2),%ecx
   30e96:	cmovne %esi,%edx
   30e99:	add    %ecx,%edx
   30e9b:	add    %eax,%edx
   30e9d:	lea    0x6ecdc(%rip),%rax        # 9fb80 <_Xevent_to_mask+0x2780>
   30ea4:	movslq %edx,%rdx
   30ea7:	mov    (%rax,%rdx,4),%r14d
   30eab:	cmp    $0x1,%r14d
   30eaf:	je     312f8 <XPutBackEvent+0x1158>
   30eb5:	mov    0x2c(%rbx),%eax
   30eb8:	lea    -0x41f(%rip),%rdx        # 30aa0 <XPutBackEvent+0x900>
   30ebf:	mov    %eax,%r13d
   30ec2:	imul   %r15d,%r13d
   30ec6:	movslq %r13d,%r13
   30ec9:	add    0x28(%rsp),%r13
   30ece:	add    0x10(%rbx),%r13
   30ed2:	cmp    %rdx,0x30(%rsp)
   30ed7:	je     314fc <XPutBackEvent+0x135c>
   30edd:	mov    0x8(%rsp),%rdx
   30ee2:	and    $0xfffffffffffffffc,%rdx
   30ee6:	mov    %rdx,%rsi
   30ee9:	mov    %rdx,0x48(%rsp)
   30eee:	mov    0xb0(%r12),%rdx
   30ef6:	mov    %rdx,0x38(%rsp)
   30efb:	add    %rsi,%rdx
   30efe:	cmp    %rdx,0xb8(%r12)
   30f06:	jb     312c0 <XPutBackEvent+0x1120>
   30f0c:	movslq 0x4(%rbx),%r15
   30f10:	movslq %eax,%rbp
   30f13:	movzwl %r8w,%edx
   30f17:	lea    -0x1(%r9),%eax
   30f1b:	lea    0x7(%rdx,%r10,1),%edx
   30f20:	sar    $0x3,%eax
   30f23:	shr    $0x3,%edx
   30f26:	imul   %rbp,%r15
   30f2a:	cltq   
   30f2c:	and    0x28(%rsp),%rax
   30f31:	mov    %rdx,0x20(%rsp)
   30f36:	mov    %r15,0x8(%rsp)
   30f3b:	mov    %rax,0x58(%rsp)
   30f40:	je     312a0 <XPutBackEvent+0x1100>
   30f46:	mov    0x18(%rbx),%ecx
   30f49:	mov    0x20(%rbx),%r8d
   30f4d:	cmp    %r8d,%ecx
   30f50:	je     312a0 <XPutBackEvent+0x1100>
   30f56:	mov    %r13,%r10
   30f59:	mov    %rdx,%rbp
   30f5c:	movslq 0x28(%rbx),%rsi
   30f60:	add    %rax,%rbp
   30f63:	sub    %rax,%r10
   30f66:	mov    0x40(%rsp),%rax
   30f6b:	mov    0xb0(%r12),%r13
   30f73:	movzwl 0xe(%rax),%eax
   30f77:	mov    %rsi,%r15
   30f7a:	imul   %rbp,%rax
   30f7e:	imul   %rax,%rsi
   30f82:	mov    %rax,0x28(%rsp)
   30f87:	add    $0x3,%rsi
   30f8b:	and    $0xfffffffffffffffc,%rsi
   30f8f:	cmp    0x38(%rsp),%r13
   30f94:	je     315e3 <XPutBackEvent+0x1443>
   30f9a:	test   %rsi,%rsi
   30f9d:	mov    $0x1,%edi
   30fa2:	mov    %r10,0x78(%rsp)
   30fa7:	cmovne %rsi,%rdi
   30fab:	mov    %r8d,0x74(%rsp)
   30fb0:	mov    %ecx,0x68(%rsp)
   30fb4:	mov    %r9d,0x30(%rsp)
   30fb9:	callq  18510 <malloc@plt>
   30fbe:	test   %rax,%rax
   30fc1:	mov    %rax,0x60(%rsp)
   30fc6:	mov    %rax,0x50(%rsp)
   30fcb:	mov    0x30(%rsp),%r9d
   30fd0:	mov    0x68(%rsp),%ecx
   30fd4:	mov    0x74(%rsp),%r8d
   30fd9:	mov    0x78(%rsp),%r10
   30fde:	je     317a3 <XPutBackEvent+0x1603>
   30fe4:	cmp    $0x20,%r9d
   30fe8:	mov    $0x2,%esi
   30fed:	je     30ff9 <XPutBackEvent+0xe59>
   30fef:	xor    %esi,%esi
   30ff1:	cmp    $0x10,%r9d
   30ff5:	sete   %sil
   30ff9:	xor    %edi,%edi
   30ffb:	cmp    $0x1,%r8d
   30fff:	mov    $0x6,%eax
   31004:	setne  %dil
   31008:	cmp    $0x1,%ecx
   3100b:	mov    $0x0,%ecx
   31010:	lea    (%rdi,%rdi,2),%edi
   31013:	cmove  %ecx,%eax
   31016:	add    %edi,%eax
   31018:	mov    $0x2,%edi
   3101d:	add    %eax,%esi
   3101f:	cmp    $0x20,%r9d
   31023:	je     3102f <XPutBackEvent+0xe8f>
   31025:	xor    %edi,%edi
   31027:	cmp    $0x10,%r9d
   3102b:	sete   %dil
   3102f:	mov    0x50(%r12),%ecx
   31034:	xor    %eax,%eax
   31036:	movslq %esi,%rsi
   31039:	lea    (%rsi,%rsi,2),%rsi
   3103d:	lea    0x3020fc(%rip),%rdx        # 333140 <_XcmsCIEXYZ_prefix+0x21e22b>
   31044:	cmp    $0x1,%ecx
   31047:	setne  %al
   3104a:	lea    (%rax,%rax,8),%eax
   3104d:	add    %edi,%eax
   3104f:	sub    $0x1,%r15d
   31053:	cltq   
   31055:	lea    (%rax,%rsi,4),%rax
   31059:	mov    (%rdx,%rax,8),%rax
   3105d:	mov    %rax,0x30(%rsp)
   31062:	js     310ca <XPutBackEvent+0xf2a>
   31064:	mov    0x60(%rsp),%r13
   31069:	mov    %r12,0x68(%rsp)
   3106e:	mov    %r13,%r12
   31071:	mov    %r10,%r13
   31074:	nopl   0x0(%rax)
   31078:	sub    $0x8,%rsp
   3107c:	movslq 0x2c(%rbx),%rcx
   31080:	sub    $0x1,%r15d
   31084:	push   %r14
   31086:	mov    0x50(%rsp),%rax
   3108b:	mov    %rbp,%rdx
   3108e:	mov    %r12,%rsi
   31091:	mov    %r13,%rdi
   31094:	mov    %rbp,%r8
   31097:	movzwl 0xe(%rax),%r9d
   3109c:	mov    0x40(%rsp),%rax
   310a1:	callq  *%rax
   310a3:	add    0x18(%rsp),%r13
   310a8:	add    0x38(%rsp),%r12
   310ad:	cmp    $0xffffffff,%r15d
   310b1:	pop    %rax
   310b2:	pop    %rdx
   310b3:	jne    31078 <XPutBackEvent+0xed8>
   310b5:	mov    0x68(%rsp),%r12
   310ba:	mov    0x28(%rbx),%eax
   310bd:	mov    0x1c(%rbx),%r9d
   310c1:	mov    0x50(%r12),%ecx
   310c6:	lea    -0x1(%rax),%r15d
   310ca:	cmp    $0x20,%r9d
   310ce:	mov    $0x2,%esi
   310d3:	je     310df <XPutBackEvent+0xf3f>
   310d5:	xor    %esi,%esi
   310d7:	cmp    $0x10,%r9d
   310db:	sete   %sil
   310df:	xor    %edx,%edx
   310e1:	cmp    $0x1,%ecx
   310e4:	mov    $0x2,%edi
   310e9:	setne  %dl
   310ec:	lea    (%rdx,%rdx,8),%edx
   310ef:	add    %edx,%esi
   310f1:	mov    0x54(%r12),%edx
   310f6:	cmp    $0x20,%edx
   310f9:	je     31104 <XPutBackEvent+0xf64>
   310fb:	xor    %edi,%edi
   310fd:	cmp    $0x10,%edx
   31100:	sete   %dil
   31104:	xor    %edx,%edx
   31106:	cmpl   $0x1,0x5c(%r12)
   3110c:	setne  %dl
   3110f:	cmp    $0x1,%ecx
   31112:	lea    (%rdx,%rdx,2),%edx
   31115:	je     31570 <XPutBackEvent+0x13d0>
   3111b:	lea    0x6(%rdi,%rdx,1),%ecx
   3111f:	movslq %esi,%rdx
   31122:	lea    0x302017(%rip),%rax        # 333140 <_XcmsCIEXYZ_prefix+0x21e22b>
   31129:	lea    (%rdx,%rdx,2),%rdx
   3112d:	cmp    $0x20,%r9d
   31131:	movslq %ecx,%rcx
   31134:	lea    (%rcx,%rdx,4),%rdx
   31138:	mov    (%rax,%rdx,8),%rax
   3113c:	mov    $0xb,%edx
   31141:	mov    %rax,0x30(%rsp)
   31146:	je     31154 <XPutBackEvent+0xfb4>
   31148:	xor    %edx,%edx
   3114a:	cmp    $0x10,%r9d
   3114e:	sete   %dl
   31151:	add    $0x9,%edx
   31154:	lea    0x6ea25(%rip),%rax        # 9fb80 <_Xevent_to_mask+0x2780>
   3115b:	movslq %edx,%rdx
   3115e:	mov    0x60(%rsp),%r13
   31163:	add    0x58(%rsp),%r13
   31168:	test   %r15d,%r15d
   3116b:	mov    (%rax,%rdx,4),%r14d
   3116f:	js     311e0 <XPutBackEvent+0x1040>
   31171:	mov    0x28(%rsp),%rax
   31176:	mov    %rax,0x8(%rsp)
   3117b:	mov    0x38(%rsp),%rbx
   31180:	mov    %rbp,0x28(%rsp)
   31185:	mov    %r13,%rbp
   31188:	mov    %r15d,%r13d
   3118b:	mov    %rbx,%r15
   3118e:	mov    0x30(%rsp),%rbx
   31193:	mov    %r12,0x30(%rsp)
   31198:	mov    0x40(%rsp),%r12
   3119d:	nopl   (%rax)
   311a0:	sub    $0x8,%rsp
   311a4:	sub    $0x1,%r13d
   311a8:	mov    %r15,%rsi
   311ab:	push   %r14
   311ad:	movzwl 0xe(%r12),%r9d
   311b3:	mov    %rbp,%rdi
   311b6:	mov    0x20(%rsp),%r8
   311bb:	mov    0x38(%rsp),%rcx
   311c0:	mov    0x30(%rsp),%rdx
   311c5:	callq  *%rbx
   311c7:	add    0x18(%rsp),%rbp
   311cc:	add    0x28(%rsp),%r15
   311d1:	cmp    $0xffffffff,%r13d
   311d5:	pop    %r10
   311d7:	pop    %r11
   311d9:	jne    311a0 <XPutBackEvent+0x1000>
   311db:	mov    0x30(%rsp),%r12
   311e0:	mov    0x50(%rsp),%rax
   311e5:	test   %rax,%rax
   311e8:	je     311f2 <XPutBackEvent+0x1052>
   311ea:	mov    %rax,%rdi
   311ed:	callq  18060 <free@plt>
   311f2:	mov    0x38(%rsp),%rax
   311f7:	cmp    0xb0(%r12),%rax
   311ff:	je     314ea <XPutBackEvent+0x134a>
   31205:	mov    0x48(%rsp),%rdx
   3120a:	mov    0x38(%rsp),%rsi
   3120f:	add    $0x88,%rsp
   31216:	mov    %r12,%rdi
   31219:	pop    %rbx
   3121a:	pop    %rbp
   3121b:	pop    %r12
   3121d:	pop    %r13
   3121f:	pop    %r14
   31221:	pop    %r15
   31223:	jmpq   3bfb0 <_XSend>
   31228:	nopl   0x0(%rax,%rax,1)
   31230:	mov    0x38(%rsp),%edi
   31234:	shl    $0x3,%eax
   31237:	mov    %r15d,%r9d
   3123a:	cltd   
   3123b:	mov    %rbx,%rcx
   3123e:	idiv   %edi
   31240:	push   %rdi
   31241:	imul   %edi,%eax
   31244:	mov    %r12,%rdi
   31247:	mov    %eax,%ebp
   31249:	mov    0x38(%rsp),%eax
   3124d:	sub    %esi,%ebp
   3124f:	sub    %ebp,%r13d
   31252:	push   %rax
   31253:	pushq  $0x1
   31255:	push   %rbp
   31256:	push   %r14
   31258:	mov    0x40(%rsp),%eax
   3125c:	push   %rax
   3125d:	mov    0x38(%rsp),%r8d
   31262:	mov    0x58(%rsp),%rdx
   31267:	mov    0x50(%rsp),%rsi
   3126c:	callq  30b20 <XPutBackEvent+0x980>
   31271:	add    %ebp,0x48(%rsp)
   31275:	add    %ebp,0x38(%rsp)
   31279:	add    $0x30,%rsp
   3127d:	mov    $0x1,%ebp
   31282:	jmpq   30b9b <XPutBackEvent+0x9fb>
   31287:	nopw   0x0(%rax,%rax,1)
   31290:	movb   $0x1,0x1(%rdi)
   31294:	jmpq   30d66 <XPutBackEvent+0xbc6>
   31299:	nopl   0x0(%rax)
   312a0:	mov    0x28(%rbx),%eax
   312a3:	movq   $0x0,0x50(%rsp)
   312ac:	sub    $0x1,%eax
   312af:	mov    %eax,%r15d
   312b2:	jns    3117b <XPutBackEvent+0xfdb>
   312b8:	jmpq   311f2 <XPutBackEvent+0x1052>
   312bd:	nopl   (%rax)
   312c0:	mov    %r12,%rdi
   312c3:	callq  3eac0 <_XAllocScratch>
   312c8:	test   %rax,%rax
   312cb:	mov    %rax,0x38(%rsp)
   312d0:	je     317ca <XPutBackEvent+0x162a>
   312d6:	mov    0x40(%rsp),%rdx
   312db:	mov    0x2c(%rbx),%eax
   312de:	mov    0x1c(%rbx),%r9d
   312e2:	movzwl 0xc(%rdx),%r8d
   312e7:	movzbl 0x14(%rdx),%r10d
   312ec:	jmpq   30f0c <XPutBackEvent+0xd6c>
   312f1:	nopl   0x0(%rax)
   312f8:	cmp    $0x20,%edi
   312fb:	mov    $0x2,%eax
   31300:	je     3130a <XPutBackEvent+0x116a>
   31302:	xor    %eax,%eax
   31304:	cmp    $0x10,%edi
   31307:	sete   %al
   3130a:	xor    %ecx,%ecx
   3130c:	cmpl   $0x1,0x38(%rsp)
   31311:	mov    $0x6,%esi
   31316:	mov    $0x0,%edx
   3131b:	setne  %cl
   3131e:	cmp    $0x1,%r13d
   31322:	lea    (%rcx,%rcx,2),%ecx
   31325:	cmovne %esi,%edx
   31328:	add    %ecx,%edx
   3132a:	add    %edx,%eax
   3132c:	lea    0x6e80d(%rip),%rdx        # 9fb40 <_Xevent_to_mask+0x2740>
   31333:	cltq   
   31335:	mov    (%rdx,%rax,4),%r14d
   31339:	jmpq   30eb5 <XPutBackEvent+0xd15>
   3133e:	mov    0x40(%rsp),%rsi
   31343:	movzwl %r13w,%r11d
   31347:	movslq 0x30(%rsp),%rcx
   3134c:	mov    0x8(%rsp),%r13d
   31351:	movb   $0x0,0x14(%rsi)
   31355:	movslq 0x30(%rbx),%rax
   31359:	imul   %r11,%rax
   3135d:	imul   %rcx,%r11
   31361:	add    $0x7,%rax
   31365:	sar    $0x3,%rax
   31369:	mov    %rax,0x18(%rsp)
   3136e:	mov    0x38(%rsp),%eax
   31372:	sub    $0x1,%eax
   31375:	cltq   
   31377:	add    %rax,%r11
   3137a:	not    %rax
   3137d:	and    %rax,%r11
   31380:	sar    $0x3,%r11
   31384:	mov    %r11,%r14
   31387:	mov    %r11,0x10(%rsp)
   3138c:	imul   %rdx,%r14
   31390:	lea    0x3(%r14),%rax
   31394:	mov    %rax,0x20(%rsp)
   31399:	sar    $0x2,%rax
   3139d:	add    %ax,0x2(%rsi)
   313a1:	movslq 0x2c(%rbx),%rsi
   313a5:	mov    0x30(%rbx),%r10d
   313a9:	imul   %r10d,%r13d
   313ad:	mov    %esi,%eax
   313af:	imul   %r15d,%eax
   313b3:	sar    $0x3,%r13d
   313b7:	movslq %r13d,%r13
   313ba:	cltq   
   313bc:	add    %rax,%r13
   313bf:	add    0x10(%rbx),%r13
   313c3:	cmp    $0x4,%r10d
   313c7:	je     31688 <XPutBackEvent+0x14e8>
   313cd:	mov    0x18(%rbx),%edi
   313d0:	xor    %ebp,%ebp
   313d2:	mov    0x50(%r12),%eax
   313d7:	cmp    %edi,%eax
   313d9:	je     31620 <XPutBackEvent+0x1480>
   313df:	cmp    $0x8,%r10d
   313e3:	je     31620 <XPutBackEvent+0x1480>
   313e9:	mov    0x20(%rsp),%r10
   313ee:	mov    0xb0(%r12),%r15
   313f6:	and    $0xfffffffffffffffc,%r10
   313fa:	lea    (%r15,%r10,1),%rdx
   313fe:	cmp    %rdx,0xb8(%r12)
   31406:	jb     31765 <XPutBackEvent+0x15c5>
   3140c:	cmp    %eax,%edi
   3140e:	je     315aa <XPutBackEvent+0x140a>
   31414:	mov    0x30(%rbx),%eax
   31417:	cmp    $0x8,%eax
   3141a:	je     315aa <XPutBackEvent+0x140a>
   31420:	cmp    $0x20,%eax
   31423:	je     31807 <XPutBackEvent+0x1667>
   31429:	cmp    $0x18,%eax
   3142c:	je     3183f <XPutBackEvent+0x169f>
   31432:	cmp    $0x10,%eax
   31435:	je     3192a <XPutBackEvent+0x178a>
   3143b:	mov    0x40(%rsp),%rax
   31440:	mov    0x10(%rsp),%r11
   31445:	movzwl 0xe(%rax),%ebx
   31449:	mov    0x18(%rsp),%rax
   3144e:	sub    %rax,%rsi
   31451:	sub    %rax,%r11
   31454:	test   %bx,%bx
   31457:	je     314ac <XPutBackEvent+0x130c>
   31459:	mov    %r15,%rcx
   3145c:	xor    %r9d,%r9d
   3145f:	mov    %rax,%rdi
   31462:	nopw   0x0(%rax,%rax,1)
   31468:	test   %rdi,%rdi
   3146b:	jle    3149d <XPutBackEvent+0x12fd>
   3146d:	lea    0x6e74c(%rip),%r8        # 9fbc0 <_Xevent_to_mask+0x27c0>
   31474:	xor    %eax,%eax
   31476:	nopw   %cs:0x0(%rax,%rax,1)
   31480:	movzbl 0x0(%r13,%rax,1),%edx
   31486:	movzbl (%r8,%rdx,1),%edx
   3148b:	mov    %dl,(%rcx,%rax,1)
   3148e:	add    $0x1,%rax
   31492:	cmp    %rdi,%rax
   31495:	jne    31480 <XPutBackEvent+0x12e0>
   31497:	add    %rdi,%rcx
   3149a:	add    %rdi,%r13
   3149d:	add    $0x1,%r9
   314a1:	add    %rsi,%r13
   314a4:	add    %r11,%rcx
   314a7:	cmp    %rbx,%r9
   314aa:	jne    31468 <XPutBackEvent+0x12c8>
   314ac:	cmp    0xb0(%r12),%r15
   314b4:	je     31793 <XPutBackEvent+0x15f3>
   314ba:	mov    %r10,%rdx
   314bd:	mov    %r15,%rsi
   314c0:	mov    %r12,%rdi
   314c3:	callq  3bfb0 <_XSend>
   314c8:	test   %rbp,%rbp
   314cb:	je     30c7e <XPutBackEvent+0xade>
   314d1:	add    $0x88,%rsp
   314d8:	mov    %rbp,%rdi
   314db:	pop    %rbx
   314dc:	pop    %rbp
   314dd:	pop    %r12
   314df:	pop    %r13
   314e1:	pop    %r14
   314e3:	pop    %r15
   314e5:	jmpq   18060 <free@plt>
   314ea:	add    0x48(%rsp),%rax
   314ef:	mov    %rax,0xb0(%r12)
   314f7:	jmpq   30c7e <XPutBackEvent+0xade>
   314fc:	movslq %eax,%rdx
   314ff:	cmp    %rdx,0x10(%rsp)
   31504:	jne    30edd <XPutBackEvent+0xd3d>
   3150a:	mov    0x50(%rsp),%ecx
   3150e:	test   %ecx,%ecx
   31510:	jne    317e1 <XPutBackEvent+0x1641>
   31516:	cmpl   $0x1,0x28(%rbx)
   3151a:	je     31528 <XPutBackEvent+0x1388>
   3151c:	movzwl %bp,%ebp
   3151f:	cmp    %ebp,0x4(%rbx)
   31522:	jne    30edd <XPutBackEvent+0xd3d>
   31528:	mov    0xb0(%r12),%rdi
   31530:	mov    0x48(%rsp),%rax
   31535:	add    %rdi,%rax
   31538:	cmp    %rax,0xb8(%r12)
   31540:	jb     31962 <XPutBackEvent+0x17c2>
   31546:	movslq 0x48(%rsp),%rdx
   3154b:	mov    %r13,%rsi
   3154e:	callq  18450 <memcpy@plt>
   31553:	mov    0x8(%rsp),%rax
   31558:	and    $0xfffffffffffffffc,%rax
   3155c:	add    %rax,0xb0(%r12)
   31564:	jmpq   30c7e <XPutBackEvent+0xade>
   31569:	nopl   0x0(%rax)
   31570:	add    %edi,%edx
   31572:	lea    0x301bc7(%rip),%rax        # 333140 <_XcmsCIEXYZ_prefix+0x21e22b>
   31579:	movslq %edx,%rcx
   3157c:	movslq %esi,%rdx
   3157f:	lea    (%rdx,%rdx,2),%rdx
   31583:	lea    (%rcx,%rdx,4),%rdx
   31587:	mov    $0x2,%ecx
   3158c:	mov    (%rax,%rdx,8),%rax
   31590:	xor    %edx,%edx
   31592:	cmp    $0x10,%r9d
   31596:	sete   %dl
   31599:	cmp    $0x20,%r9d
   3159d:	cmove  %ecx,%edx
   315a0:	mov    %rax,0x30(%rsp)
   315a5:	jmpq   31154 <XPutBackEvent+0xfb4>
   315aa:	mov    %r10,0x8(%rsp)
   315af:	sub    $0x8,%rsp
   315b3:	movslq %esi,%rcx
   315b6:	push   %rdi
   315b7:	mov    0x50(%rsp),%rax
   315bc:	mov    %r13,%rdi
   315bf:	mov    0x20(%rsp),%r8
   315c4:	mov    0x28(%rsp),%rdx
   315c9:	mov    %r15,%rsi
   315cc:	movzwl 0xe(%rax),%r9d
   315d1:	callq  30aa0 <XPutBackEvent+0x900>
   315d6:	pop    %rdi
   315d7:	pop    %r8
   315d9:	mov    0x8(%rsp),%r10
   315de:	jmpq   314ac <XPutBackEvent+0x130c>
   315e3:	mov    %r12,%rdi
   315e6:	mov    %r10,0x30(%rsp)
   315eb:	callq  3eac0 <_XAllocScratch>
   315f0:	test   %rax,%rax
   315f3:	mov    %rax,0x60(%rsp)
   315f8:	mov    0x30(%rsp),%r10
   315fd:	je     317ca <XPutBackEvent+0x162a>
   31603:	mov    0x1c(%rbx),%r9d
   31607:	mov    0x20(%rbx),%r8d
   3160b:	mov    0x18(%rbx),%ecx
   3160e:	mov    0x28(%rbx),%r15d
   31612:	movq   $0x0,0x50(%rsp)
   3161b:	jmpq   30fe4 <XPutBackEvent+0xe44>
   31620:	movslq %esi,%rdx
   31623:	cmp    %rdx,0x10(%rsp)
   31628:	jne    313e9 <XPutBackEvent+0x1249>
   3162e:	mov    0x8(%rsp),%r9d
   31633:	test   %r9d,%r9d
   31636:	je     3164d <XPutBackEvent+0x14ad>
   31638:	mov    0x40(%rsp),%rdx
   3163d:	movzwl 0xe(%rdx),%edx
   31641:	add    %r15d,%edx
   31644:	cmp    0x4(%rbx),%edx
   31647:	jae    313e9 <XPutBackEvent+0x1249>
   3164d:	mov    0xb0(%r12),%rdi
   31655:	lea    (%rdi,%r14,1),%rax
   31659:	cmp    %rax,0xb8(%r12)
   31661:	jb     31917 <XPutBackEvent+0x1777>
   31667:	movslq %r14d,%rdx
   3166a:	mov    %r13,%rsi
   3166d:	callq  18450 <memcpy@plt>
   31672:	mov    0x20(%rsp),%r10
   31677:	and    $0xfffffffffffffffc,%r10
   3167b:	add    %r10,0xb0(%r12)
   31683:	jmpq   314c8 <XPutBackEvent+0x1328>
   31688:	testb  $0x1,0x8(%rsp)
   3168d:	je     313cd <XPutBackEvent+0x122d>
   31693:	movzwl %bp,%eax
   31696:	mov    $0x1,%edi
   3169b:	mov    %r10d,0x38(%rsp)
   316a0:	imul   %esi,%eax
   316a3:	mov    %rdx,0x30(%rsp)
   316a8:	mov    %esi,0x28(%rsp)
   316ac:	test   %eax,%eax
   316ae:	movslq %eax,%rcx
   316b1:	cmovne %rcx,%rdi
   316b5:	callq  18510 <malloc@plt>
   316ba:	test   %rax,%rax
   316bd:	mov    %rax,%rbp
   316c0:	movslq 0x28(%rsp),%rsi
   316c5:	mov    0x30(%rsp),%rdx
   316ca:	mov    0x38(%rsp),%r10d
   316cf:	je     317ca <XPutBackEvent+0x162a>
   316d5:	mov    0x18(%rbx),%edi
   316d8:	mov    0x18(%rsp),%r9
   316dd:	movslq %esi,%rax
   316e0:	sub    %r9,%rax
   316e3:	cmp    $0x1,%edi
   316e6:	mov    %rax,0x30(%rsp)
   316eb:	je     3196f <XPutBackEvent+0x17cf>
   316f1:	lea    -0x1(%rdx),%r11
   316f5:	cmp    $0xffffffffffffffff,%r11
   316f9:	je     3175d <XPutBackEvent+0x15bd>
   316fb:	mov    %r14,0x28(%rsp)
   31700:	mov    %rbp,%rcx
   31703:	mov    %esi,0x30(%rsp)
   31707:	mov    %rax,%r14
   3170a:	test   %r9,%r9
   3170d:	jle    317ff <XPutBackEvent+0x165f>
   31713:	lea    (%rcx,%r9,1),%r8
   31717:	mov    %r13,%rsi
   3171a:	nopw   0x0(%rax,%rax,1)
   31720:	add    $0x1,%rsi
   31724:	movzbl -0x1(%rsi),%edx
   31728:	movzbl (%rsi),%eax
   3172b:	add    $0x1,%rcx
   3172f:	shr    $0x4,%dl
   31732:	shl    $0x4,%eax
   31735:	or     %edx,%eax
   31737:	cmp    %r8,%rcx
   3173a:	mov    %al,-0x1(%rcx)
   3173d:	jne    31720 <XPutBackEvent+0x1580>
   3173f:	add    %r9,%r13
   31742:	sub    $0x1,%r11
   31746:	add    %r14,%r13
   31749:	lea    (%r8,%r14,1),%rcx
   3174d:	cmp    $0xffffffffffffffff,%r11
   31751:	jne    3170a <XPutBackEvent+0x156a>
   31753:	movslq 0x30(%rsp),%rsi
   31758:	mov    0x28(%rsp),%r14
   3175d:	mov    %rbp,%r13
   31760:	jmpq   313d2 <XPutBackEvent+0x1232>
   31765:	mov    %r10,%rsi
   31768:	mov    %r12,%rdi
   3176b:	mov    %r10,0x8(%rsp)
   31770:	callq  3eac0 <_XAllocScratch>
   31775:	test   %rax,%rax
   31778:	mov    %rax,%r15
   3177b:	je     317bd <XPutBackEvent+0x161d>
   3177d:	mov    0x18(%rbx),%edi
   31780:	mov    0x50(%r12),%eax
   31785:	movslq 0x2c(%rbx),%rsi
   31789:	mov    0x8(%rsp),%r10
   3178e:	jmpq   3140c <XPutBackEvent+0x126c>
   31793:	add    %r15,%r10
   31796:	mov    %r10,0xb0(%r12)
   3179e:	jmpq   314c8 <XPutBackEvent+0x1328>
   317a3:	sub    $0x18,%r13
   317a7:	subq   $0x1,0x98(%r12)
   317b0:	mov    %r13,0xb0(%r12)
   317b8:	jmpq   30c7e <XPutBackEvent+0xade>
   317bd:	test   %rbp,%rbp
   317c0:	je     317ca <XPutBackEvent+0x162a>
   317c2:	mov    %rbp,%rdi
   317c5:	callq  18060 <free@plt>
   317ca:	subq   $0x18,0xb0(%r12)
   317d3:	subq   $0x1,0x98(%r12)
   317dc:	jmpq   30c7e <XPutBackEvent+0xade>
   317e1:	cmpl   $0x1,0x28(%rbx)
   317e5:	jne    30edd <XPutBackEvent+0xd3d>
   317eb:	movzwl %bp,%edx
   317ee:	add    %r15d,%edx
   317f1:	cmp    0x4(%rbx),%edx
   317f4:	jae    30edd <XPutBackEvent+0xd3d>
   317fa:	jmpq   31528 <XPutBackEvent+0x1388>
   317ff:	mov    %rcx,%r8
   31802:	jmpq   31742 <XPutBackEvent+0x15a2>
   31807:	mov    %r10,0x8(%rsp)
   3180c:	sub    $0x8,%rsp
   31810:	movslq %esi,%rcx
   31813:	push   %rdi
   31814:	mov    0x50(%rsp),%rax
   31819:	mov    %r15,%rsi
   3181c:	mov    0x20(%rsp),%r8
   31821:	mov    0x28(%rsp),%rdx
   31826:	mov    %r13,%rdi
   31829:	movzwl 0xe(%rax),%r9d
   3182e:	callq  302b0 <XPutBackEvent+0x110>
   31833:	pop    %rcx
   31834:	pop    %rsi
   31835:	mov    0x8(%rsp),%r10
   3183a:	jmpq   314ac <XPutBackEvent+0x130c>
   3183f:	mov    0x18(%rsp),%rbx
   31844:	movabs $0x5555555555555556,%rdx
   3184e:	mov    0x10(%rsp),%r11
   31853:	lea    0x2(%rbx),%rcx
   31857:	mov    %rcx,%rax
   3185a:	sar    $0x3f,%rcx
   3185e:	imul   %rdx
   31861:	mov    %rdx,%rax
   31864:	sub    %rcx,%rax
   31867:	lea    (%rax,%rax,2),%r8
   3186b:	mov    0x40(%rsp),%rax
   31870:	sub    %r8,%rsi
   31873:	sub    %r8,%r11
   31876:	movzwl 0xe(%rax),%r9d
   3187b:	sub    $0x1,%r9
   3187f:	cmp    $0xffffffffffffffff,%r9
   31883:	je     314ac <XPutBackEvent+0x130c>
   31889:	mov    %r15,%rax
   3188c:	cmp    %r8,%rbx
   3188f:	je     318b6 <XPutBackEvent+0x1716>
   31891:	test   %r9,%r9
   31894:	jne    318b6 <XPutBackEvent+0x1716>
   31896:	sub    $0x3,%r8
   3189a:	mov    %rbx,%rdx
   3189d:	sub    %r8,%rdx
   318a0:	cmp    $0x2,%rdx
   318a4:	je     3190a <XPutBackEvent+0x176a>
   318a6:	cmp    $0x1,%edi
   318a9:	je     318fe <XPutBackEvent+0x175e>
   318ab:	movzbl 0x0(%r13,%r8,1),%edx
   318b1:	mov    %dl,0x2(%rax,%r8,1)
   318b6:	test   %r8,%r8
   318b9:	jle    318e9 <XPutBackEvent+0x1749>
   318bb:	mov    %r8,%rdx
   318be:	xchg   %ax,%ax
   318c0:	movzbl 0x2(%r13),%ecx
   318c5:	sub    $0x3,%rdx
   318c9:	add    $0x3,%rax
   318cd:	add    $0x3,%r13
   318d1:	mov    %cl,-0x3(%rax)
   318d4:	movzbl -0x2(%r13),%ecx
   318d9:	mov    %cl,-0x2(%rax)
   318dc:	movzbl -0x3(%r13),%ecx
   318e1:	test   %rdx,%rdx
   318e4:	mov    %cl,-0x1(%rax)
   318e7:	jg     318c0 <XPutBackEvent+0x1720>
   318e9:	sub    $0x1,%r9
   318ed:	add    %rsi,%r13
   318f0:	add    %r11,%rax
   318f3:	cmp    $0xffffffffffffffff,%r9
   318f7:	jne    3188c <XPutBackEvent+0x16ec>
   318f9:	jmpq   314ac <XPutBackEvent+0x130c>
   318fe:	movzbl 0x2(%r13,%r8,1),%edx
   31904:	mov    %dl,(%rax,%r8,1)
   31908:	jmp    318b6 <XPutBackEvent+0x1716>
   3190a:	movzbl 0x1(%r13,%r8,1),%edx
   31910:	mov    %dl,0x1(%rax,%r8,1)
   31915:	jmp    318a6 <XPutBackEvent+0x1706>
   31917:	mov    %r14,%rdx
   3191a:	mov    %r13,%rsi
   3191d:	mov    %r12,%rdi
   31920:	callq  3bfb0 <_XSend>
   31925:	jmpq   314c8 <XPutBackEvent+0x1328>
   3192a:	mov    %r10,0x8(%rsp)
   3192f:	sub    $0x8,%rsp
   31933:	movslq %esi,%rcx
   31936:	push   %rdi
   31937:	mov    0x50(%rsp),%rax
   3193c:	mov    %r15,%rsi
   3193f:	mov    0x20(%rsp),%r8
   31944:	mov    0x28(%rsp),%rdx
   31949:	mov    %r13,%rdi
   3194c:	movzwl 0xe(%rax),%r9d
   31951:	callq  301f0 <XPutBackEvent+0x50>
   31956:	pop    %rax
   31957:	pop    %rdx
   31958:	mov    0x8(%rsp),%r10
   3195d:	jmpq   314ac <XPutBackEvent+0x130c>
   31962:	mov    0x48(%rsp),%rdx
   31967:	mov    %r13,%rsi
   3196a:	jmpq   3120f <XPutBackEvent+0x106f>
   3196f:	lea    -0x1(%rdx),%rax
   31973:	cmp    $0xffffffffffffffff,%rax
   31977:	mov    %rax,0x28(%rsp)
   3197c:	je     3175d <XPutBackEvent+0x15bd>
   31982:	mov    0x18(%rsp),%r11
   31987:	mov    %rbp,%rcx
   3198a:	test   %r11,%r11
   3198d:	jle    319e6 <XPutBackEvent+0x1846>
   3198f:	lea    (%rcx,%r11,1),%r9
   31993:	mov    %r13,%r8
   31996:	nopw   %cs:0x0(%rax,%rax,1)
   319a0:	add    $0x1,%r8
   319a4:	movzbl (%r8),%edx
   319a8:	movzbl -0x1(%r8),%eax
   319ad:	add    $0x1,%rcx
   319b1:	shr    $0x4,%dl
   319b4:	shl    $0x4,%eax
   319b7:	or     %edx,%eax
   319b9:	cmp    %r9,%rcx
   319bc:	mov    %al,-0x1(%rcx)
   319bf:	jne    319a0 <XPutBackEvent+0x1800>
   319c1:	add    %r11,%r13
   319c4:	mov    0x30(%rsp),%rax
   319c9:	subq   $0x1,0x28(%rsp)
   319cf:	add    %rax,%r13
   319d2:	lea    (%r9,%rax,1),%rcx
   319d6:	mov    0x28(%rsp),%rax
   319db:	cmp    $0xffffffffffffffff,%rax
   319df:	jne    3198a <XPutBackEvent+0x17ea>
   319e1:	jmpq   3175d <XPutBackEvent+0x15bd>
   319e6:	mov    %rcx,%r9
   319e9:	jmp    319c4 <XPutBackEvent+0x1824>
   319eb:	nopl   0x0(%rax,%rax,1)
