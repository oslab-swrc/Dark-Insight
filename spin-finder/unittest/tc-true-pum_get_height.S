// TC_OUT pum_get_height@@Base,0x1598b0,0x1598d6,0x0(0x0(%rbp))
// TC_OUT pum_get_height@@Base,0x15a1e0,0x15a206,0x0(0x1f8(%r12))
0000000000159110 <pum_get_height@@Base>:
  159110:	mov    0x34c1d6(%rip),%eax        # 4a52ec <current_funccal@@Base+0x39e4>
  159116:	retq   
  159117:	nopw   0x0(%rax,%rax,1)
  159120:	movzbl (%rdi),%eax
  159123:	test   %al,%al
  159125:	je     159199 <pum_get_height@@Base+0x89>
  159127:	cmp    $0x1,%edx
  15912a:	jle    159199 <pum_get_height@@Base+0x89>
  15912c:	lea    -0x2(%rdx),%r9d
  159130:	mov    $0x1,%ecx
  159135:	add    $0x2,%r9
  159139:	jmp    15915f <pum_get_height@@Base+0x4f>
  15913b:	nopl   0x0(%rax,%rax,1)
  159140:	mov    %al,-0x1(%rsi,%rcx,1)
  159144:	movzbl 0x1(%rdi),%eax
  159148:	lea    0x1(%rdi),%rdx
  15914c:	movslq %ecx,%r8
  15914f:	test   %al,%al
  159151:	je     159193 <pum_get_height@@Base+0x83>
  159153:	mov    %rdx,%rdi
  159156:	add    $0x1,%rcx
  15915a:	cmp    %r9,%rcx
  15915d:	je     159193 <pum_get_height@@Base+0x83>
  15915f:	cmp    $0xa,%al
  159161:	jne    159140 <pum_get_height@@Base+0x30>
  159163:	movb   $0x20,-0x1(%rsi,%rcx,1)
  159168:	nopl   0x0(%rax,%rax,1)
  159170:	add    $0x1,%rdi
  159174:	movzbl (%rdi),%eax
  159177:	test   %al,%al
  159179:	je     159190 <pum_get_height@@Base+0x80>
  15917b:	lea    -0x9(%rax),%edx
  15917e:	cmp    $0x1,%dl
  159181:	jbe    159170 <pum_get_height@@Base+0x60>
  159183:	cmp    $0x20,%al
  159185:	je     159170 <pum_get_height@@Base+0x60>
  159187:	movslq %ecx,%r8
  15918a:	jmp    159156 <pum_get_height@@Base+0x46>
  15918c:	nopl   0x0(%rax)
  159190:	movslq %ecx,%r8
  159193:	movb   $0x0,(%rsi,%r8,1)
  159198:	retq   
  159199:	xor    %r8d,%r8d
  15919c:	jmp    159193 <pum_get_height@@Base+0x83>
  15919e:	xchg   %ax,%ax
  1591a0:	mov    0x3569d9(%rip),%rax        # 4afb80 <firstwin@@Base>
  1591a7:	test   %rax,%rax
  1591aa:	je     1591e4 <pum_get_height@@Base+0xd4>
  1591ac:	lea    0x34c1ad(%rip),%rcx        # 4a5360 <current_funccal@@Base+0x3a58>
  1591b3:	jmp    1591c1 <pum_get_height@@Base+0xb1>
  1591b5:	nopl   (%rax)
  1591b8:	mov    0x20(%rax),%rax
  1591bc:	test   %rax,%rax
  1591bf:	je     159200 <pum_get_height@@Base+0xf0>
  1591c1:	mov    0x8(%rax),%rdx
  1591c5:	test   %rdx,%rdx
  1591c8:	je     1591b8 <pum_get_height@@Base+0xa8>
  1591ca:	mov    0x13c8(%rdx),%rdx
  1591d1:	cmpb   $0x71,(%rdx)
  1591d4:	jne    1591b8 <pum_get_height@@Base+0xa8>
  1591d6:	cmp    %rcx,%rdi
  1591d9:	je     1591f0 <pum_get_height@@Base+0xe0>
  1591db:	cmp    0x1858(%rax),%rdi
  1591e2:	jne    1591b8 <pum_get_height@@Base+0xa8>
  1591e4:	repz retq 
  1591e6:	nopw   %cs:0x0(%rax,%rax,1)
  1591f0:	cmpq   $0x0,0x1858(%rax)
  1591f8:	jne    1591b8 <pum_get_height@@Base+0xa8>
  1591fa:	repz retq 
  1591fc:	nopl   0x0(%rax)
  159200:	repz retq 
  159202:	nopl   0x0(%rax)
  159206:	nopw   %cs:0x0(%rax,%rax,1)
  159210:	mov    0x356129(%rip),%r8        # 4af340 <first_tabpage@@Base>
  159217:	test   %r8,%r8
  15921a:	je     159288 <pum_get_height@@Base+0x178>
  15921c:	mov    0x35612d(%rip),%r9        # 4af350 <curtab@@Base>
  159223:	mov    0x356956(%rip),%r10        # 4afb80 <firstwin@@Base>
  15922a:	lea    0x34c12f(%rip),%rsi        # 4a5360 <current_funccal@@Base+0x3a58>
  159231:	cmp    %r8,%r9
  159234:	je     159290 <pum_get_height@@Base+0x180>
  159236:	mov    0x20(%r8),%rdx
  15923a:	jmp    159244 <pum_get_height@@Base+0x134>
  15923c:	nopl   0x0(%rax)
  159240:	mov    0x20(%rdx),%rdx
  159244:	test   %rdx,%rdx
  159247:	je     159280 <pum_get_height@@Base+0x170>
  159249:	mov    0x8(%rdx),%rax
  15924d:	test   %rax,%rax
  159250:	je     159240 <pum_get_height@@Base+0x130>
  159252:	mov    0x13c8(%rax),%rcx
  159259:	cmpb   $0x71,(%rcx)
  15925c:	jne    159240 <pum_get_height@@Base+0x130>
  15925e:	cmp    %rsi,%rdi
  159261:	je     159270 <pum_get_height@@Base+0x160>
  159263:	cmp    0x1858(%rdx),%rdi
  15926a:	jne    159240 <pum_get_height@@Base+0x130>
  15926c:	repz retq 
  15926e:	xchg   %ax,%ax
  159270:	cmpq   $0x0,0x1858(%rdx)
  159278:	jne    159240 <pum_get_height@@Base+0x130>
  15927a:	repz retq 
  15927c:	nopl   0x0(%rax)
  159280:	mov    (%r8),%r8
  159283:	test   %r8,%r8
  159286:	jne    159231 <pum_get_height@@Base+0x121>
  159288:	xor    %eax,%eax
  15928a:	retq   
  15928b:	nopl   0x0(%rax,%rax,1)
  159290:	mov    %r10,%rdx
  159293:	jmp    159244 <pum_get_height@@Base+0x134>
  159295:	nop
  159296:	nopw   %cs:0x0(%rax,%rax,1)
  1592a0:	push   %rbp
  1592a1:	push   %rbx
  1592a2:	sub    $0x8,%rsp
  1592a6:	mov    (%rdi),%rbx
  1592a9:	test   %rbx,%rbx
  1592ac:	je     1592d9 <pum_get_height@@Base+0x1c9>
  1592ae:	mov    %rdi,%rbp
  1592b1:	nopl   0x0(%rax)
  1592b8:	mov    (%rbx),%rax
  1592bb:	mov    0x8(%rbx),%rdi
  1592bf:	mov    %rax,0x0(%rbp)
  1592c3:	callq  11c7f0 <vim_free@@Base>
  1592c8:	mov    %rbx,%rdi
  1592cb:	callq  11c7f0 <vim_free@@Base>
  1592d0:	mov    0x0(%rbp),%rbx
  1592d4:	test   %rbx,%rbx
  1592d7:	jne    1592b8 <pum_get_height@@Base+0x1a8>
  1592d9:	add    $0x8,%rsp
  1592dd:	pop    %rbx
  1592de:	pop    %rbp
  1592df:	retq   
  1592e0:	push   %r15
  1592e2:	movslq %esi,%r15
  1592e5:	push   %r14
  1592e7:	push   %r13
  1592e9:	lea    (%r15,%r15,2),%r13
  1592ed:	push   %r12
  1592ef:	push   %rbp
  1592f0:	push   %rbx
  1592f1:	mov    %rdi,%r14
  1592f4:	shl    $0x4,%r13
  1592f8:	add    %rdi,%r13
  1592fb:	sub    $0x8,%rsp
  1592ff:	mov    0x28(%r13),%eax
  159303:	test   %eax,%eax
  159305:	je     159403 <pum_get_height@@Base+0x2f3>
  15930b:	mov    0x10(%r13),%rbx
  15930f:	test   %rbx,%rbx
  159312:	je     159403 <pum_get_height@@Base+0x2f3>
  159318:	mov    0x38(%r13),%rdi
  15931c:	mov    %r13,%r12
  15931f:	jmp    15936d <pum_get_height@@Base+0x25d>
  159321:	nopl   0x0(%rax)
  159328:	mov    0x30(%rbx),%rdi
  15932c:	callq  11c7f0 <vim_free@@Base>
  159331:	mov    0x28(%rbx),%rdi
  159335:	callq  11c7f0 <vim_free@@Base>
  15933a:	mov    %rbx,%rdi
  15933d:	callq  11c7f0 <vim_free@@Base>
  159342:	cmp    %rbx,%rbp
  159345:	je     1593e0 <pum_get_height@@Base+0x2d0>
  15934b:	mov    0x28(%r12),%eax
  159350:	mov    0x38(%r13),%rdi
  159354:	mov    %rbp,0x10(%r12)
  159359:	sub    $0x1,%eax
  15935c:	test   %eax,%eax
  15935e:	mov    %eax,0x28(%r12)
  159363:	je     15938b <pum_get_height@@Base+0x27b>
  159365:	test   %rbp,%rbp
  159368:	mov    %rbp,%rbx
  15936b:	je     15938b <pum_get_height@@Base+0x27b>
  15936d:	test   %rdi,%rdi
  159370:	mov    (%rbx),%rbp
  159373:	jne    159328 <pum_get_height@@Base+0x218>
  159375:	mov    0x28(%r12),%eax
  15937a:	mov    %rbp,0x10(%r12)
  15937f:	sub    $0x1,%eax
  159382:	test   %eax,%eax
  159384:	mov    %eax,0x28(%r12)
  159389:	jne    159365 <pum_get_height@@Base+0x255>
  15938b:	callq  11c7f0 <vim_free@@Base>
  159390:	lea    0x3(%r15,%r15,2),%rax
  159395:	lea    0x1f8(%r14),%rdi
  15939c:	shl    $0x4,%rax
  1593a0:	movq   $0x0,0x8(%r14,%rax,1)
  1593a9:	lea    (%r15,%r15,2),%rax
  1593ad:	shl    $0x4,%rax
  1593b1:	movl   $0x0,0x2c(%r14,%rax,1)
  1593ba:	callq  1592a0 <pum_get_height@@Base+0x190>
  1593bf:	add    $0x8,%rsp
  1593c3:	lea    0x208(%r14),%rdi
  1593ca:	pop    %rbx
  1593cb:	pop    %rbp
  1593cc:	pop    %r12
  1593ce:	pop    %r13
  1593d0:	pop    %r14
  1593d2:	pop    %r15
  1593d4:	jmpq   1592a0 <pum_get_height@@Base+0x190>
  1593d9:	nopl   0x0(%rax)
  1593e0:	lea    (%r15,%r15,2),%rax
  1593e4:	shl    $0x4,%rax
  1593e8:	add    %r14,%rax
  1593eb:	movl   $0x1,0x28(%rax)
  1593f2:	mov    0x38(%r13),%rdi
  1593f6:	mov    %rbx,0x10(%rax)
  1593fa:	movl   $0x0,0x28(%rax)
  159401:	jmp    15938b <pum_get_height@@Base+0x27b>
  159403:	lea    0x3(%r15,%r15,2),%rax
  159408:	shl    $0x4,%rax
  15940c:	mov    0x8(%r14,%rax,1),%rdi
  159411:	jmpq   15938b <pum_get_height@@Base+0x27b>
  159416:	nopw   %cs:0x0(%rax,%rax,1)
  159420:	push   %rbp
  159421:	push   %rbx
  159422:	sub    $0x8,%rsp
  159426:	mov    (%rdi),%rbp
  159429:	test   %rbp,%rbp
  15942c:	je     159442 <pum_get_height@@Base+0x332>
  15942e:	mov    0x0(%rbp),%eax
  159431:	movq   $0x0,(%rdi)
  159438:	sub    $0x1,%eax
  15943b:	test   %eax,%eax
  15943d:	mov    %eax,0x0(%rbp)
  159440:	jle    159450 <pum_get_height@@Base+0x340>
  159442:	add    $0x8,%rsp
  159446:	pop    %rbx
  159447:	pop    %rbp
  159448:	retq   
  159449:	nopl   0x0(%rax)
  159450:	mov    0x4(%rbp),%eax
  159453:	xor    %ebx,%ebx
  159455:	test   %eax,%eax
  159457:	jle    159472 <pum_get_height@@Base+0x362>
  159459:	nopl   0x0(%rax)
  159460:	mov    %ebx,%esi
  159462:	mov    %rbp,%rdi
  159465:	add    $0x1,%ebx
  159468:	callq  1592e0 <pum_get_height@@Base+0x1d0>
  15946d:	cmp    %ebx,0x4(%rbp)
  159470:	jg     159460 <pum_get_height@@Base+0x350>
  159472:	add    $0x8,%rsp
  159476:	mov    %rbp,%rdi
  159479:	pop    %rbx
  15947a:	pop    %rbp
  15947b:	jmpq   11c7f0 <vim_free@@Base>
  159480:	push   %rbp
  159481:	push   %rbx
  159482:	sub    $0x8,%rsp
  159486:	mov    (%rdi),%rbp
  159489:	test   %rbp,%rbp
  15948c:	je     1594c0 <pum_get_height@@Base+0x3b0>
  15948e:	mov    0x0(%rbp),%rax
  159492:	mov    %rdi,%rbx
  159495:	mov    %rax,(%rdi)
  159498:	mov    0x8(%rbp),%rdi
  15949c:	callq  11c7f0 <vim_free@@Base>
  1594a1:	mov    %rbp,%rdi
  1594a4:	callq  11c7f0 <vim_free@@Base>
  1594a9:	mov    (%rbx),%rax
  1594ac:	test   %rax,%rax
  1594af:	je     1594c0 <pum_get_height@@Base+0x3b0>
  1594b1:	mov    0x8(%rax),%rax
  1594b5:	add    $0x8,%rsp
  1594b9:	pop    %rbx
  1594ba:	pop    %rbp
  1594bb:	retq   
  1594bc:	nopl   0x0(%rax)
  1594c0:	add    $0x8,%rsp
  1594c4:	xor    %eax,%eax
  1594c6:	pop    %rbx
  1594c7:	pop    %rbp
  1594c8:	retq   
  1594c9:	nopl   0x0(%rax)
  1594d0:	sub    $0x8,%rsp
  1594d4:	mov    $0x228,%edi
  1594d9:	callq  121d10 <alloc@@Base>
  1594de:	test   %rax,%rax
  1594e1:	mov    %rax,%rdx
  1594e4:	je     159517 <pum_get_height@@Base+0x407>
  1594e6:	lea    0x8(%rax),%rdi
  1594ea:	mov    %rax,%rcx
  1594ed:	movq   $0x0,(%rax)
  1594f4:	movq   $0x0,0x220(%rax)
  1594ff:	xor    %eax,%eax
  159501:	and    $0xfffffffffffffff8,%rdi
  159505:	sub    %rdi,%rcx
  159508:	add    $0x228,%ecx
  15950e:	shr    $0x3,%ecx
  159511:	rep stos %rax,%es:(%rdi)
  159514:	addl   $0x1,(%rdx)
  159517:	mov    %rdx,%rax
  15951a:	add    $0x8,%rsp
  15951e:	retq   
  15951f:	nop
  159520:	push   %rbp
  159521:	push   %rbx
  159522:	mov    $0xfff,%eax
  159527:	mov    %rdi,%rbx
  15952a:	mov    %rsi,%rbp
  15952d:	sub    $0x18,%rsp
  159531:	cmp    $0x1001,%edx
  159537:	cmovge %eax,%edx
  15953a:	mov    (%rdi),%rax
  15953d:	mov    %edx,(%rcx)
  15953f:	test   %rax,%rax
  159542:	je     159580 <pum_get_height@@Base+0x470>
  159544:	cmp    (%rsi),%edx
  159546:	jg     159550 <pum_get_height@@Base+0x440>
  159548:	add    $0x18,%rsp
  15954c:	pop    %rbx
  15954d:	pop    %rbp
  15954e:	retq   
  15954f:	nop
  159550:	add    $0x1,%edx
  159553:	mov    %rax,%rdi
  159556:	mov    %rcx,0x8(%rsp)
  15955b:	movslq %edx,%rsi
  15955e:	callq  4f078 <_init@@Base+0x488>
  159563:	test   %rax,%rax
  159566:	mov    %rax,(%rbx)
  159569:	je     15959a <pum_get_height@@Base+0x48a>
  15956b:	mov    0x8(%rsp),%rcx
  159570:	mov    (%rcx),%edx
  159572:	mov    %edx,0x0(%rbp)
  159575:	add    $0x18,%rsp
  159579:	pop    %rbx
  15957a:	pop    %rbp
  15957b:	retq   
  15957c:	nopl   0x0(%rax)
  159580:	lea    0x1(%rdx),%edi
  159583:	mov    %rcx,0x8(%rsp)
  159588:	callq  121d10 <alloc@@Base>
  15958d:	test   %rax,%rax
  159590:	mov    %rax,(%rbx)
  159593:	mov    0x8(%rsp),%rcx
  159598:	jne    159570 <pum_get_height@@Base+0x460>
  15959a:	xor    %eax,%eax
  15959c:	jmp    159548 <pum_get_height@@Base+0x438>
  15959e:	xchg   %ax,%ax
  1595a0:	mov    %edi,%eax
  1595a2:	and    $0xffffffdf,%eax
  1595a5:	cmp    $0x57,%eax
  1595a8:	je     1595c0 <pum_get_height@@Base+0x4b0>
  1595aa:	cmp    $0x49,%eax
  1595ad:	jne    159600 <pum_get_height@@Base+0x4f0>
  1595af:	test   %esi,%esi
  1595b1:	lea    0xc1ee9(%rip),%rax        # 21b4a1 <_IO_stdin_used@@Base+0x4ee1>
  1595b8:	jg     1595cb <pum_get_height@@Base+0x4bb>
  1595ba:	retq   
  1595bb:	nopl   0x0(%rax,%rax,1)
  1595c0:	lea    0xd17bd(%rip),%rax        # 22ad84 <_IO_stdin_used@@Base+0x147c4>
  1595c7:	test   %esi,%esi
  1595c9:	jle    1595ba <pum_get_height@@Base+0x4aa>
  1595cb:	lea    0xd17bb(%rip),%rcx        # 22ad8d <_IO_stdin_used@@Base+0x147cd>
  1595d2:	lea    0x34bd57(%rip),%rdi        # 4a5330 <current_funccal@@Base+0x3a28>
  1595d9:	sub    $0x8,%rsp
  1595dd:	mov    %esi,%r9d
  1595e0:	mov    %rax,%r8
  1595e3:	mov    $0x14,%edx
  1595e8:	xor    %esi,%esi
  1595ea:	xor    %eax,%eax
  1595ec:	callq  4f260 <_init@@Base+0x670>
  1595f1:	lea    0x34bd38(%rip),%rax        # 4a5330 <current_funccal@@Base+0x3a28>
  1595f8:	add    $0x8,%rsp
  1595fc:	retq   
  1595fd:	nopl   (%rax)
  159600:	cmp    $0x45,%eax
  159603:	je     159640 <pum_get_height@@Base+0x530>
  159605:	test   %edi,%edi
  159607:	jne    159614 <pum_get_height@@Base+0x504>
  159609:	test   %esi,%esi
  15960b:	lea    0xcab23(%rip),%rax        # 224135 <_IO_stdin_used@@Base+0xdb75>
  159612:	jg     1595cb <pum_get_height@@Base+0x4bb>
  159614:	cmp    $0x1,%edi
  159617:	lea    0xcc537(%rip),%rax        # 225b55 <_IO_stdin_used@@Base+0xf595>
  15961e:	jbe    1595c7 <pum_get_height@@Base+0x4b7>
  159620:	movb   $0x20,0x34bd1d(%rip)        # 4a5344 <current_funccal@@Base+0x3a3c>
  159627:	mov    %dil,0x34bd17(%rip)        # 4a5345 <current_funccal@@Base+0x3a3d>
  15962e:	lea    0x34bd0f(%rip),%rax        # 4a5344 <current_funccal@@Base+0x3a3c>
  159635:	movb   $0x0,0x34bd0a(%rip)        # 4a5346 <current_funccal@@Base+0x3a3e>
  15963c:	jmp    1595c7 <pum_get_height@@Base+0x4b7>
  15963e:	xchg   %ax,%ax
  159640:	lea    0xcaaee(%rip),%rax        # 224135 <_IO_stdin_used@@Base+0xdb75>
  159647:	jmpq   1595c7 <pum_get_height@@Base+0x4b7>
  15964c:	nopl   0x0(%rax)
  159650:	test   %rsi,%rsi
  159653:	je     1596ae <pum_get_height@@Base+0x59e>
  159655:	push   %rbp
  159656:	push   %rbx
  159657:	mov    %rdi,%rbp
  15965a:	mov    %rsi,%rdi
  15965d:	mov    %rsi,%rbx
  159660:	sub    $0x8,%rsp
  159664:	callq  4ed80 <_init@@Base+0x190>
  159669:	lea    0x2(%rax),%edi
  15966c:	callq  121d10 <alloc@@Base>
  159671:	movslq 0x8(%rbp),%rdx
  159675:	lea    0x3(%rdx,%rdx,2),%rdx
  15967a:	shl    $0x4,%rdx
  15967e:	test   %rax,%rax
  159681:	mov    %rax,0x8(%rbp,%rdx,1)
  159686:	je     1596a8 <pum_get_height@@Base+0x598>
  159688:	add    $0x8,%rsp
  15968c:	mov    %rbx,%rdx
  15968f:	lea    0xd16fe(%rip),%rsi        # 22ad94 <_IO_stdin_used@@Base+0x147d4>
  159696:	pop    %rbx
  159697:	pop    %rbp
  159698:	mov    %rax,%rdi
  15969b:	xor    %eax,%eax
  15969d:	jmpq   4f1a8 <_init@@Base+0x5b8>
  1596a2:	nopw   0x0(%rax,%rax,1)
  1596a8:	add    $0x8,%rsp
  1596ac:	pop    %rbx
  1596ad:	pop    %rbp
  1596ae:	repz retq 
  1596b0:	push   %rbp
  1596b1:	push   %rbx
  1596b2:	mov    %rsi,%rbp
  1596b5:	mov    %rdi,%rbx
  1596b8:	sub    $0x8,%rsp
  1596bc:	movslq 0x4(%rdi),%rsi
  1596c0:	mov    0x8(%rdi),%eax
  1596c3:	add    $0x1,%eax
  1596c6:	cmp    %eax,%esi
  1596c8:	jle    1596ec <pum_get_height@@Base+0x5dc>
  1596ca:	nopw   0x0(%rax,%rax,1)
  1596d0:	sub    $0x1,%esi
  1596d3:	mov    %rbx,%rdi
  1596d6:	mov    %esi,0x4(%rbx)
  1596d9:	callq  1592e0 <pum_get_height@@Base+0x1d0>
  1596de:	movslq 0x4(%rbx),%rsi
  1596e2:	mov    0x8(%rbx),%eax
  1596e5:	add    $0x1,%eax
  1596e8:	cmp    %eax,%esi
  1596ea:	jg     1596d0 <pum_get_height@@Base+0x5c0>
  1596ec:	cmp    $0xa,%esi
  1596ef:	je     159740 <pum_get_height@@Base+0x630>
  1596f1:	lea    0x1(%rsi),%eax
  1596f4:	mov    %esi,0x8(%rbx)
  1596f7:	mov    %eax,0x4(%rbx)
  1596fa:	lea    (%rsi,%rsi,2),%rax
  1596fe:	shl    $0x4,%rax
  159702:	add    $0x10,%rax
  159706:	add    %rbx,%rax
  159709:	mov    %rbp,%rsi
  15970c:	lea    0x8(%rax),%rdi
  159710:	movq   $0x0,(%rax)
  159717:	movq   $0x0,0x28(%rax)
  15971f:	and    $0xfffffffffffffff8,%rdi
  159723:	sub    %rdi,%rax
  159726:	lea    0x30(%rax),%ecx
  159729:	xor    %eax,%eax
  15972b:	shr    $0x3,%ecx
  15972e:	rep stos %rax,%es:(%rdi)
  159731:	add    $0x8,%rsp
  159735:	mov    %rbx,%rdi
  159738:	pop    %rbx
  159739:	pop    %rbp
  15973a:	jmpq   159650 <pum_get_height@@Base+0x540>
  15973f:	nop
  159740:	xor    %esi,%esi
  159742:	mov    %rbx,%rdi
  159745:	callq  1592e0 <pum_get_height@@Base+0x1d0>
  15974a:	lea    0x10(%rbx),%rax
  15974e:	lea    0x1c0(%rbx),%rcx
  159755:	nopl   (%rax)
  159758:	mov    0x30(%rax),%rdx
  15975c:	add    $0x30,%rax
  159760:	mov    %rdx,-0x30(%rax)
  159764:	mov    0x8(%rax),%rdx
  159768:	mov    %rdx,-0x28(%rax)
  15976c:	mov    0x10(%rax),%rdx
  159770:	mov    %rdx,-0x20(%rax)
  159774:	mov    0x18(%rax),%rdx
  159778:	mov    %rdx,-0x18(%rax)
  15977c:	mov    0x20(%rax),%rdx
  159780:	mov    %rdx,-0x10(%rax)
  159784:	mov    0x28(%rax),%rdx
  159788:	mov    %rdx,-0x8(%rax)
  15978c:	cmp    %rax,%rcx
  15978f:	jne    159758 <pum_get_height@@Base+0x648>
  159791:	movl   $0x9,0x8(%rbx)
  159798:	mov    $0x1c0,%eax
  15979d:	jmpq   159706 <pum_get_height@@Base+0x5f6>
  1597a2:	nopl   0x0(%rax)
  1597a6:	nopw   %cs:0x0(%rax,%rax,1)
  1597b0:	push   %rbp
  1597b1:	push   %rbx
  1597b2:	sub    $0x8,%rsp
  1597b6:	mov    (%rdi),%rbx
  1597b9:	test   %rbx,%rbx
  1597bc:	je     1597e9 <pum_get_height@@Base+0x6d9>
  1597be:	mov    %rdi,%rbp
  1597c1:	nopl   0x0(%rax)
  1597c8:	mov    0x8(%rbx),%rax
  1597cc:	mov    (%rbx),%rdi
  1597cf:	mov    %rax,0x0(%rbp)
  1597d3:	callq  17fe70 <vim_regfree@@Base>
  1597d8:	mov    %rbx,%rdi
  1597db:	callq  11c7f0 <vim_free@@Base>
  1597e0:	mov    0x0(%rbp),%rbx
  1597e4:	test   %rbx,%rbx
  1597e7:	jne    1597c8 <pum_get_height@@Base+0x6b8>
  1597e9:	add    $0x8,%rsp
  1597ed:	pop    %rbx
  1597ee:	pop    %rbp
  1597ef:	retq   
  1597f0:	push   %r14
  1597f2:	push   %r13
  1597f4:	mov    %rdi,%r13
  1597f7:	push   %r12
  1597f9:	push   %rbp
  1597fa:	mov    $0x10,%edi
  1597ff:	push   %rbx
  159800:	mov    %rsi,%rbp
  159803:	mov    %edx,%r14d
  159806:	sub    $0x10,%rsp
  15980a:	callq  121d10 <alloc@@Base>
  15980f:	test   %rax,%rax
  159812:	je     159948 <pum_get_height@@Base+0x838>
  159818:	mov    0x0(%rbp),%rdx
  15981c:	mov    %r13,%rdi
  15981f:	mov    %rdx,(%rax)
  159822:	mov    %rax,0x0(%rbp)
  159826:	callq  1de820 <vim_isAbsName@@Base>
  15982b:	test   %eax,%eax
  15982d:	mov    0x0(%rbp),%r12
  159831:	jne    159900 <pum_get_height@@Base+0x7f0>
  159837:	mov    (%r12),%rbx
  15983b:	test   %rbx,%rbx
  15983e:	je     159900 <pum_get_height@@Base+0x7f0>
  159844:	test   %r14d,%r14d
  159847:	jne    159900 <pum_get_height@@Base+0x7f0>
  15984d:	movq   $0x0,0x8(%r12)
  159856:	xor    %edi,%edi
  159858:	jmp    159864 <pum_get_height@@Base+0x754>
  15985a:	nopw   0x0(%rax,%rax,1)
  159860:	mov    0x8(%rax),%rdi
  159864:	callq  11c7f0 <vim_free@@Base>
  159869:	mov    0x0(%rbp),%r12
  15986d:	mov    0x8(%rbx),%rdi
  159871:	mov    $0x1,%edx
  159876:	mov    %r13,%rsi
  159879:	callq  113320 <concat_fnames@@Base>
  15987e:	mov    %rax,0x8(%r12)
  159883:	mov    0x0(%rbp),%rax
  159887:	mov    0x8(%rax),%rdi
  15988b:	callq  154870 <mch_isdir@@Base>
  159890:	cmp    $0x1,%eax
  159893:	je     159930 <pum_get_height@@Base+0x820>
  159899:	mov    (%rbx),%rbx
  15989c:	mov    0x0(%rbp),%rax
  1598a0:	test   %rbx,%rbx
  1598a3:	jne    159860 <pum_get_height@@Base+0x750>
  1598a5:	mov    (%rax),%r12
  1598a8:	test   %r12,%r12
  1598ab:	je     1598dd <pum_get_height@@Base+0x7cd>
  1598ad:	nopl   (%rax)
  1598b0:	mov    (%r12),%rdx
  1598b4:	mov    0x8(%r12),%rdi
  1598b9:	mov    %rdx,(%rax)
  1598bc:	callq  11c7f0 <vim_free@@Base>
  1598c1:	mov    %r12,%rdi
  1598c4:	callq  11c7f0 <vim_free@@Base>
  1598c9:	mov    0x0(%rbp),%rax
  1598cd:	mov    (%rax),%r12
  1598d0:	mov    %rax,%rdi
  1598d3:	cmp    %rbx,%r12
  1598d6:	jne    1598b0 <pum_get_height@@Base+0x7a0>
  1598d8:	test   %r12,%r12
  1598db:	jne    159911 <pum_get_height@@Base+0x801>
  1598dd:	mov    0x8(%rax),%rdi
  1598e1:	callq  11c7f0 <vim_free@@Base>
  1598e6:	mov    0x0(%rbp),%rbx
  1598ea:	mov    %r13,%rdi
  1598ed:	callq  11f220 <vim_strsave@@Base>
  1598f2:	mov    0x0(%rbp),%rdi
  1598f6:	mov    %rax,0x8(%rbx)
  1598fa:	jmp    159911 <pum_get_height@@Base+0x801>
  1598fc:	nopl   0x0(%rax)
  159900:	mov    %r13,%rdi
  159903:	callq  11f220 <vim_strsave@@Base>
  159908:	mov    0x0(%rbp),%rdi
  15990c:	mov    %rax,0x8(%r12)
  159911:	mov    0x8(%rdi),%rax
  159915:	test   %rax,%rax
  159918:	je     15994c <pum_get_height@@Base+0x83c>
  15991a:	add    $0x10,%rsp
  15991e:	pop    %rbx
  15991f:	pop    %rbp
  159920:	pop    %r12
  159922:	pop    %r13
  159924:	pop    %r14
  159926:	retq   
  159927:	nopw   0x0(%rax,%rax,1)
  159930:	mov    0x0(%rbp),%rdi
  159934:	mov    (%rdi),%r12
  159937:	mov    %rdi,%rax
  15993a:	cmp    %rbx,%r12
  15993d:	jne    1598b0 <pum_get_height@@Base+0x7a0>
  159943:	jmp    159911 <pum_get_height@@Base+0x801>
  159945:	nopl   (%rax)
  159948:	xor    %eax,%eax
  15994a:	jmp    15991a <pum_get_height@@Base+0x80a>
  15994c:	mov    (%rdi),%rdx
  15994f:	mov    %rax,0x8(%rsp)
  159954:	mov    %rdx,0x0(%rbp)
  159958:	callq  11c7f0 <vim_free@@Base>
  15995d:	mov    0x8(%rsp),%rax
  159962:	jmp    15991a <pum_get_height@@Base+0x80a>
  159964:	xchg   %ax,%ax
  159966:	nopw   %cs:0x0(%rax,%rax,1)
  159970:	push   %r15
  159972:	push   %r14
  159974:	push   %r13
  159976:	push   %r12
  159978:	mov    %rdi,%r12
  15997b:	push   %rbp
  15997c:	push   %rbx
  15997d:	sub    $0x28,%rsp
  159981:	mov    0x355829(%rip),%ecx        # 4af1b0 <KeyTyped@@Base>
  159987:	test   %rdx,%rdx
  15998a:	mov    %rsi,(%rsp)
  15998e:	mov    %rdx,0x18(%rsp)
  159993:	mov    %ecx,0x14(%rsp)
  159997:	je     159cb0 <pum_get_height@@Base+0xba0>
  15999d:	movslq 0x8(%rdi),%rax
  1599a1:	cmp    %eax,0x4(%rdi)
  1599a4:	jg     1599d0 <pum_get_height@@Base+0x8c0>
  1599a6:	mov    $0x1,%edi
  1599ab:	callq  1de960 <check_lnums@@Base>
  1599b0:	mov    0x14(%rsp),%eax
  1599b4:	mov    %eax,0x3557f6(%rip)        # 4af1b0 <KeyTyped@@Base>
  1599ba:	add    $0x28,%rsp
  1599be:	pop    %rbx
  1599bf:	pop    %rbp
  1599c0:	pop    %r12
  1599c2:	pop    %r13
  1599c4:	pop    %r14
  1599c6:	pop    %r15
  1599c8:	retq   
  1599c9:	nopl   0x0(%rax)
  1599d0:	mov    0x18(%rsp),%rcx
  1599d5:	mov    (%rcx),%r15
  1599d8:	mov    (%rsp),%rcx
  1599dc:	mov    (%rcx),%rbp
  1599df:	jmpq   159af9 <pum_get_height@@Base+0x9e9>
  1599e4:	nopl   0x0(%rax)
  1599e8:	mov    %r14,%rdi
  1599eb:	add    0x35563e(%rip),%rdi        # 4af030 <IObuff@@Base>
  1599f2:	lea    0xc1c4a(%rip),%rsi        # 21b643 <_IO_stdin_used@@Base+0x5083>
  1599f9:	xor    %eax,%eax
  1599fb:	callq  4f1a8 <_init@@Base+0x5b8>
  159a00:	mov    0x355629(%rip),%r13        # 4af030 <IObuff@@Base>
  159a07:	lea    0x0(%r13,%r14,1),%rdi
  159a0c:	callq  4ed80 <_init@@Base+0x190>
  159a11:	mov    0x1c(%r15),%edx
  159a15:	add    %eax,%ebx
  159a17:	test   %edx,%edx
  159a19:	jle    159a42 <pum_get_height@@Base+0x932>
  159a1b:	movslq %ebx,%r14
  159a1e:	lea    0xd1401(%rip),%rsi        # 22ae26 <_IO_stdin_used@@Base+0x14866>
  159a25:	xor    %eax,%eax
  159a27:	lea    0x0(%r13,%r14,1),%rdi
  159a2c:	callq  4f1a8 <_init@@Base+0x5b8>
  159a31:	mov    %r14,%rdi
  159a34:	add    0x3555f5(%rip),%rdi        # 4af030 <IObuff@@Base>
  159a3b:	callq  4ed80 <_init@@Base+0x190>
  159a40:	add    %eax,%ebx
  159a42:	movzbl 0x3a(%r15),%edi
  159a47:	mov    0x20(%r15),%esi
  159a4b:	movslq %ebx,%r14
  159a4e:	callq  1595a0 <pum_get_height@@Base+0x490>
  159a53:	mov    %r14,%rdi
  159a56:	add    0x3555d3(%rip),%rdi        # 4af030 <IObuff@@Base>
  159a5d:	mov    %rax,%rsi
  159a60:	callq  4eca0 <_init@@Base+0xb0>
  159a65:	mov    0x3555c4(%rip),%r13        # 4af030 <IObuff@@Base>
  159a6c:	lea    0x0(%r13,%r14,1),%rdi
  159a71:	callq  4ed80 <_init@@Base+0x190>
  159a76:	add    %eax,%ebx
  159a78:	movslq %ebx,%r14
  159a7b:	movb   $0x7c,0x0(%r13,%r14,1)
  159a81:	mov    0x3555a8(%rip),%rdx        # 4af030 <IObuff@@Base>
  159a88:	lea    0x2(%rbx),%eax
  159a8b:	add    $0x1,%ebx
  159a8e:	movslq %ebx,%rbx
  159a91:	movslq %eax,%rsi
  159a94:	movb   $0x20,(%rdx,%rbx,1)
  159a98:	mov    $0x401,%edx
  159a9d:	add    0x35558c(%rip),%rsi        # 4af030 <IObuff@@Base>
  159aa4:	sub    %eax,%edx
  159aa6:	cmp    $0x3,%eax
  159aa9:	jg     159bc0 <pum_get_height@@Base+0xab0>
  159aaf:	mov    0x30(%r15),%rdi
  159ab3:	callq  159120 <pum_get_height@@Base+0x10>
  159ab8:	mov    0x355571(%rip),%rbx        # 4af030 <IObuff@@Base>
  159abf:	mov    %rbx,%rdi
  159ac2:	callq  4ed80 <_init@@Base+0x190>
  159ac7:	mov    (%rsp),%rdi
  159acb:	lea    0x1(%rax),%ecx
  159ace:	xor    %r8d,%r8d
  159ad1:	mov    %rbx,%rdx
  159ad4:	mov    %rbp,%rsi
  159ad7:	callq  1008d0 <ml_append_buf@@Base>
  159adc:	test   %eax,%eax
  159ade:	je     159be8 <pum_get_height@@Base+0xad8>
  159ae4:	mov    (%r15),%r15
  159ae7:	add    $0x1,%rbp
  159aeb:	test   %r15,%r15
  159aee:	je     159be8 <pum_get_height@@Base+0xad8>
  159af4:	movslq 0x8(%r12),%rax
  159af9:	lea    (%rax,%rax,2),%rax
  159afd:	shl    $0x4,%rax
  159b01:	movslq 0x28(%r12,%rax,1),%rax
  159b06:	cmp    %rax,%rbp
  159b09:	jge    159be8 <pum_get_height@@Base+0xad8>
  159b0f:	mov    0x18(%r15),%edi
  159b13:	test   %edi,%edi
  159b15:	jne    159b70 <pum_get_height@@Base+0xa60>
  159b17:	mov    0x355512(%rip),%r13        # 4af030 <IObuff@@Base>
  159b1e:	mov    $0x1,%r14d
  159b24:	xor    %eax,%eax
  159b26:	mov    $0x1,%ebx
  159b2b:	movb   $0x7c,0x0(%r13,%rax,1)
  159b31:	mov    0x10(%r15),%rdx
  159b35:	test   %rdx,%rdx
  159b38:	jg     1599e8 <pum_get_height@@Base+0x8d8>
  159b3e:	mov    0x28(%r15),%rdi
  159b42:	mov    0x3554e7(%rip),%r13        # 4af030 <IObuff@@Base>
  159b49:	test   %rdi,%rdi
  159b4c:	je     159a7b <pum_get_height@@Base+0x96b>
  159b52:	mov    %r14,%rsi
  159b55:	add    0x3554d4(%rip),%rsi        # 4af030 <IObuff@@Base>
  159b5c:	mov    $0x401,%edx
  159b61:	sub    %ebx,%edx
  159b63:	callq  159120 <pum_get_height@@Base+0x10>
  159b68:	jmpq   159a65 <pum_get_height@@Base+0x955>
  159b6d:	nopl   (%rax)
  159b70:	callq  55f40 <buflist_findnr@@Base>
  159b75:	test   %rax,%rax
  159b78:	je     159b17 <pum_get_height@@Base+0xa07>
  159b7a:	mov    0x98(%rax),%rsi
  159b81:	test   %rsi,%rsi
  159b84:	je     159b17 <pum_get_height@@Base+0xa07>
  159b86:	cmpb   $0x1,0x3a(%r15)
  159b8b:	je     159c90 <pum_get_height@@Base+0xb80>
  159b91:	mov    0x355498(%rip),%rdi        # 4af030 <IObuff@@Base>
  159b98:	callq  4eca0 <_init@@Base+0xb0>
  159b9d:	mov    0x35548c(%rip),%r13        # 4af030 <IObuff@@Base>
  159ba4:	mov    %r13,%rdi
  159ba7:	callq  4ed80 <_init@@Base+0x190>
  159bac:	lea    0x1(%rax),%ebx
  159baf:	cltq   
  159bb1:	movslq %ebx,%r14
  159bb4:	jmpq   159b2b <pum_get_height@@Base+0xa1b>
  159bb9:	nopl   0x0(%rax)
  159bc0:	mov    0x30(%r15),%rdi
  159bc4:	mov    %rsi,0x8(%rsp)
  159bc9:	mov    %edx,0x10(%rsp)
  159bcd:	callq  607e0 <skipwhite@@Base>
  159bd2:	mov    0x10(%rsp),%edx
  159bd6:	mov    %rax,%rdi
  159bd9:	mov    0x8(%rsp),%rsi
  159bde:	jmpq   159ab3 <pum_get_height@@Base+0x9a3>
  159be3:	nopl   0x0(%rax,%rax,1)
  159be8:	cmpq   $0x0,0x18(%rsp)
  159bee:	jne    1599a6 <pum_get_height@@Base+0x896>
  159bf4:	lea    0x1(%rbp),%rdi
  159bf8:	xor    %esi,%esi
  159bfa:	callq  100950 <ml_delete@@Base>
  159bff:	mov    $0x1,%edi
  159c04:	callq  1de960 <check_lnums@@Base>
  159c09:	lea    0xcee90(%rip),%rdx        # 228aa0 <_IO_stdin_used@@Base+0x124e0>
  159c10:	lea    0xccc6c(%rip),%rdi        # 226883 <_IO_stdin_used@@Base+0x102c3>
  159c17:	xor    %esi,%esi
  159c19:	mov    $0x4,%ecx
  159c1e:	callq  151c40 <set_option_value@@Base>
  159c23:	mov    0x35414e(%rip),%r8        # 4add78 <curbuf@@Base>
  159c2a:	lea    0xd9b33(%rip),%rsi        # 233764 <_IO_stdin_used@@Base+0x1d1a4>
  159c31:	xor    %ecx,%ecx
  159c33:	xor    %edx,%edx
  159c35:	mov    $0x9,%edi
  159c3a:	movl   $0x1,0x35419c(%rip)        # 4adde0 <keep_filetype@@Base>
  159c44:	movl   $0x0,0x14e0(%r8)
  159c4f:	callq  d7810 <apply_autocmds@@Base>
  159c54:	mov    0x35411d(%rip),%r8        # 4add78 <curbuf@@Base>
  159c5b:	lea    0xd9b02(%rip),%rsi        # 233764 <_IO_stdin_used@@Base+0x1d1a4>
  159c62:	xor    %ecx,%ecx
  159c64:	xor    %edx,%edx
  159c66:	mov    $0xe,%edi
  159c6b:	callq  d7810 <apply_autocmds@@Base>
  159c70:	mov    $0x28,%edi
  159c75:	movl   $0x0,0x354161(%rip)        # 4adde0 <keep_filetype@@Base>
  159c7f:	callq  181060 <redraw_curbuf_later@@Base>
  159c84:	jmpq   1599b0 <pum_get_height@@Base+0x8a0>
  159c89:	nopl   0x0(%rax)
  159c90:	mov    %rsi,%rdi
  159c93:	callq  1127f0 <gettail@@Base>
  159c98:	mov    0x355391(%rip),%rdi        # 4af030 <IObuff@@Base>
  159c9f:	mov    %rax,%rsi
  159ca2:	callq  4eca0 <_init@@Base+0xb0>
  159ca7:	jmpq   159b9d <pum_get_height@@Base+0xa8d>
  159cac:	nopl   0x0(%rax)
  159cb0:	cmp    %rsi,0x3540c1(%rip)        # 4add78 <curbuf@@Base>
  159cb7:	mov    %rsi,%rax
  159cba:	je     159d03 <pum_get_height@@Base+0xbf3>
  159cbc:	lea    0x34621d(%rip),%rsi        # 49fee0 <e_intern2@@Base>
  159cc3:	xor    %edi,%edi
  159cc5:	mov    $0x5,%edx
  159cca:	callq  4ed78 <_init@@Base+0x188>
  159ccf:	add    $0x28,%rsp
  159cd3:	lea    0xd10be(%rip),%rsi        # 22ad98 <_IO_stdin_used@@Base+0x147d8>
  159cda:	mov    %rax,%rdi
  159cdd:	pop    %rbx
  159cde:	pop    %rbp
  159cdf:	pop    %r12
  159ce1:	pop    %r13
  159ce3:	pop    %r14
  159ce5:	pop    %r15
  159ce7:	jmpq   107390 <emsg2@@Base>
  159cec:	nopl   0x0(%rax)
  159cf0:	xor    %esi,%esi
  159cf2:	mov    $0x1,%edi
  159cf7:	callq  100950 <ml_delete@@Base>
  159cfc:	mov    0x354075(%rip),%rax        # 4add78 <curbuf@@Base>
  159d03:	testb  $0x1,0x10(%rax)
  159d07:	je     159cf0 <pum_get_height@@Base+0xbe0>
  159d09:	movslq 0x8(%r12),%rax
  159d0e:	cmp    0x4(%r12),%eax
  159d13:	jge    159d29 <pum_get_height@@Base+0xc19>
  159d15:	lea    (%rax,%rax,2),%rdx
  159d19:	xor    %ebp,%ebp
  159d1b:	shl    $0x4,%rdx
  159d1f:	mov    0x10(%r12,%rdx,1),%r15
  159d24:	jmpq   159af9 <pum_get_height@@Base+0x9e9>
  159d29:	mov    $0x1,%edi
  159d2e:	callq  1de960 <check_lnums@@Base>
  159d33:	jmpq   159c09 <pum_get_height@@Base+0xaf9>
  159d38:	nopl   0x0(%rax,%rax,1)
  159d40:	push   %rbp
  159d41:	push   %rbx
  159d42:	sub    $0x8,%rsp
  159d46:	movslq 0x8(%rdi),%rax
  159d4a:	lea    (%rax,%rax,2),%rax
  159d4e:	shl    $0x4,%rax
  159d52:	mov    0x2c(%rdi,%rax,1),%r8d
  159d57:	callq  1591a0 <pum_get_height@@Base+0x90>
  159d5c:	test   %rax,%rax
  159d5f:	mov    %rax,%rbx
  159d62:	je     159ddd <pum_get_height@@Base+0xccd>
  159d64:	mov    0x8(%rbx),%rdx
  159d68:	movslq %r8d,%rax
  159d6b:	cmp    (%rdx),%rax
  159d6e:	jg     159ddd <pum_get_height@@Base+0xccd>
  159d70:	cmp    %esi,%r8d
  159d73:	je     159ddd <pum_get_height@@Base+0xccd>
  159d75:	cmp    %esi,%r8d
  159d78:	mov    0x354991(%rip),%rbp        # 4ae710 <curwin@@Base>
  159d7f:	mov    %rdx,0x353ff2(%rip)        # 4add78 <curbuf@@Base>
  159d86:	mov    %rbx,0x354983(%rip)        # 4ae710 <curwin@@Base>
  159d8d:	jg     159df0 <pum_get_height@@Base+0xce0>
  159d8f:	movslq %esi,%rsi
  159d92:	mov    %rax,0x130(%rbx)
  159d99:	mov    %rsi,0x138(%rbx)
  159da0:	mov    %rax,0x38(%rbx)
  159da4:	movl   $0x0,0x40(%rbx)
  159dab:	callq  1239f0 <update_topline@@Base>
  159db0:	mov    $0xa,%edi
  159db5:	callq  180f60 <redraw_later@@Base>
  159dba:	mov    0x35494f(%rip),%rax        # 4ae710 <curwin@@Base>
  159dc1:	mov    %rbp,0x354948(%rip)        # 4ae710 <curwin@@Base>
  159dc8:	movl   $0x1,0x140(%rax)
  159dd2:	mov    0x8(%rbp),%rax
  159dd6:	mov    %rax,0x353f9b(%rip)        # 4add78 <curbuf@@Base>
  159ddd:	xor    %eax,%eax
  159ddf:	test   %rbx,%rbx
  159de2:	setne  %al
  159de5:	add    $0x8,%rsp
  159de9:	pop    %rbx
  159dea:	pop    %rbp
  159deb:	retq   
  159dec:	nopl   0x0(%rax)
  159df0:	movslq %esi,%rsi
  159df3:	mov    %rax,0x138(%rbx)
  159dfa:	mov    %rsi,0x130(%rbx)
  159e01:	jmp    159da0 <pum_get_height@@Base+0xc90>
  159e03:	nopl   (%rax)
  159e06:	nopw   %cs:0x0(%rax,%rax,1)
  159e10:	push   %r15
  159e12:	push   %r14
  159e14:	push   %r13
  159e16:	push   %r12
  159e18:	mov    %rsi,%r12
  159e1b:	push   %rbp
  159e1c:	push   %rbx
  159e1d:	mov    %rdi,%rbx
  159e20:	sub    $0x48,%rsp
  159e24:	mov    %fs:0x28,%rax
  159e2d:	mov    %rax,0x38(%rsp)
  159e32:	xor    %eax,%eax
  159e34:	callq  159210 <pum_get_height@@Base+0x100>
  159e39:	test   %rax,%rax
  159e3c:	je     159ebc <pum_get_height@@Base+0xdac>
  159e3e:	test   %r12,%r12
  159e41:	mov    %rax,%rbp
  159e44:	mov    (%rax),%r13
  159e47:	je     159f30 <pum_get_height@@Base+0xe20>
  159e4d:	callq  1591a0 <pum_get_height@@Base+0x90>
  159e52:	test   %rax,%rax
  159e55:	je     159ef7 <pum_get_height@@Base+0xde7>
  159e5b:	mov    0x3548ae(%rip),%r15        # 4ae710 <curwin@@Base>
  159e62:	mov    %rax,0x3548a7(%rip)        # 4ae710 <curwin@@Base>
  159e69:	movslq 0x8(%rdi),%rax
  159e6d:	lea    0x3(%rax,%rax,2),%rax
  159e72:	shl    $0x4,%rax
  159e76:	mov    0x8(%rdi,%rax,1),%rsi
  159e7b:	test   %rsi,%rsi
  159e7e:	je     159ef0 <pum_get_height@@Base+0xde0>
  159e80:	lea    0xd0f22(%rip),%rdi        # 22ada9 <_IO_stdin_used@@Base+0x147e9>
  159e87:	callq  967b0 <set_internal_string_var@@Base>
  159e8c:	mov    %r12,%rdx
  159e8f:	mov    %rbp,%rsi
  159e92:	mov    %rbx,%rdi
  159e95:	mov    %r15,0x354874(%rip)        # 4ae710 <curwin@@Base>
  159e9c:	callq  159970 <pum_get_height@@Base+0x860>
  159ea1:	test   %r12,%r12
  159ea4:	je     159f10 <pum_get_height@@Base+0xe00>
  159ea6:	mov    %rbx,%rdi
  159ea9:	callq  1591a0 <pum_get_height@@Base+0x90>
  159eae:	test   %rax,%rax
  159eb1:	je     159ebc <pum_get_height@@Base+0xdac>
  159eb3:	cmp    0xe8(%rax),%r13
  159eba:	jl     159ee0 <pum_get_height@@Base+0xdd0>
  159ebc:	mov    0x38(%rsp),%rax
  159ec1:	xor    %fs:0x28,%rax
  159eca:	jne    159f8a <pum_get_height@@Base+0xe7a>
  159ed0:	add    $0x48,%rsp
  159ed4:	pop    %rbx
  159ed5:	pop    %rbp
  159ed6:	pop    %r12
  159ed8:	pop    %r13
  159eda:	pop    %r14
  159edc:	pop    %r15
  159ede:	retq   
  159edf:	nop
  159ee0:	mov    $0x28,%esi
  159ee5:	mov    %rbp,%rdi
  159ee8:	callq  181010 <redraw_buf_later@@Base>
  159eed:	jmp    159ebc <pum_get_height@@Base+0xdac>
  159eef:	nop
  159ef0:	mov    %r15,0x354819(%rip)        # 4ae710 <curwin@@Base>
  159ef7:	mov    %r12,%rdx
  159efa:	mov    %rbp,%rsi
  159efd:	mov    %rbx,%rdi
  159f00:	callq  159970 <pum_get_height@@Base+0x860>
  159f05:	jmp    159ea6 <pum_get_height@@Base+0xd96>
  159f07:	nopw   0x0(%rax,%rax,1)
  159f10:	mov    %rsp,%r14
  159f13:	mov    %rbx,%rdi
  159f16:	xor    %esi,%esi
  159f18:	callq  159d40 <pum_get_height@@Base+0xc30>
  159f1d:	mov    %r14,%rdi
  159f20:	callq  d7ca0 <aucmd_restbuf@@Base>
  159f25:	jmpq   159ea6 <pum_get_height@@Base+0xd96>
  159f2a:	nopw   0x0(%rax,%rax,1)
  159f30:	mov    %rax,%rsi
  159f33:	mov    %rsp,%rdi
  159f36:	mov    %rsp,%r14
  159f39:	callq  d7a80 <aucmd_prepbuf@@Base>
  159f3e:	mov    %rbx,%rdi
  159f41:	callq  1591a0 <pum_get_height@@Base+0x90>
  159f46:	test   %rax,%rax
  159f49:	je     159f7b <pum_get_height@@Base+0xe6b>
  159f4b:	mov    0x3547be(%rip),%r15        # 4ae710 <curwin@@Base>
  159f52:	mov    %rax,0x3547b7(%rip)        # 4ae710 <curwin@@Base>
  159f59:	movslq 0x8(%rbx),%rax
  159f5d:	lea    0x3(%rax,%rax,2),%rax
  159f62:	shl    $0x4,%rax
  159f66:	mov    0x8(%rbx,%rax,1),%rsi
  159f6b:	test   %rsi,%rsi
  159f6e:	jne    159e80 <pum_get_height@@Base+0xd70>
  159f74:	mov    %r15,0x354795(%rip)        # 4ae710 <curwin@@Base>
  159f7b:	xor    %edx,%edx
  159f7d:	mov    %rbp,%rsi
  159f80:	mov    %rbx,%rdi
  159f83:	callq  159970 <pum_get_height@@Base+0x860>
  159f88:	jmp    159f13 <pum_get_height@@Base+0xe03>
  159f8a:	callq  4ed90 <_init@@Base+0x1a0>
  159f8f:	nop
  159f90:	push   %rbp
  159f91:	push   %rbx
  159f92:	mov    %rdi,%rbp
  159f95:	mov    $0x1000,%edi
  159f9a:	sub    $0xc8,%rsp
  159fa1:	mov    %fs:0x28,%rax
  159faa:	mov    %rax,0xb8(%rsp)
  159fb2:	xor    %eax,%eax
  159fb4:	callq  121d10 <alloc@@Base>
  159fb9:	test   %rax,%rax
  159fbc:	je     159fe5 <pum_get_height@@Base+0xed5>
  159fbe:	mov    %rax,%rbx
  159fc1:	mov    $0x1000,%esi
  159fc6:	mov    %rax,%rdi
  159fc9:	callq  154290 <mch_dirname@@Base>
  159fce:	mov    %rbx,%rsi
  159fd1:	mov    %rbp,%rdi
  159fd4:	callq  4eef0 <_init@@Base+0x300>
  159fd9:	test   %eax,%eax
  159fdb:	jne    15a008 <pum_get_height@@Base+0xef8>
  159fdd:	mov    %rbx,%rdi
  159fe0:	callq  11c7f0 <vim_free@@Base>
  159fe5:	mov    0xb8(%rsp),%rax
  159fed:	xor    %fs:0x28,%rax
  159ff6:	jne    15a032 <pum_get_height@@Base+0xf22>
  159ff8:	add    $0xc8,%rsp
  159fff:	pop    %rbx
  15a000:	pop    %rbp
  15a001:	retq   
  15a002:	nopw   0x0(%rax,%rax,1)
  15a008:	mov    0x354701(%rip),%rax        # 4ae710 <curwin@@Base>
  15a00f:	mov    %rsp,%rdi
  15a012:	mov    %rbp,(%rsp)
  15a016:	cmpq   $0x1,0x190(%rax)
  15a01e:	sbb    %eax,%eax
  15a020:	and    $0x67,%al
  15a022:	add    $0xd0,%eax
  15a027:	mov    %eax,0x20(%rsp)
  15a02b:	callq  b93d0 <ex_cd@@Base>
  15a030:	jmp    159fdd <pum_get_height@@Base+0xecd>
  15a032:	callq  4ed90 <_init@@Base+0x1a0>
  15a037:	nopw   0x0(%rax,%rax,1)
  15a040:	push   %r12
  15a042:	push   %rbp
  15a043:	push   %rbx
  15a044:	sub    $0x20,%rsp
  15a048:	mov    %fs:0x28,%rax
  15a051:	mov    %rax,0x18(%rsp)
  15a056:	xor    %eax,%eax
  15a058:	cmp    %rdi,0x353d19(%rip)        # 4add78 <curbuf@@Base>
  15a05f:	je     15a089 <pum_get_height@@Base+0xf79>
  15a061:	mov    %rdi,%rbx
  15a064:	mov    %rsp,%rdi
  15a067:	mov    %rsi,%r12
  15a06a:	callq  c3fe0 <enter_cleanup@@Base>
  15a06f:	xor    %esi,%esi
  15a071:	mov    %rbx,%rdi
  15a074:	callq  5dbb0 <wipe_buffer@@Base>
  15a079:	mov    %rsp,%rdi
  15a07c:	callq  c4100 <leave_cleanup@@Base>
  15a081:	mov    %r12,%rdi
  15a084:	callq  159f90 <pum_get_height@@Base+0xe80>
  15a089:	mov    0x18(%rsp),%rax
  15a08e:	xor    %fs:0x28,%rax
  15a097:	jne    15a0a2 <pum_get_height@@Base+0xf92>
  15a099:	add    $0x20,%rsp
  15a09d:	pop    %rbx
  15a09e:	pop    %rbp
  15a09f:	pop    %r12
  15a0a1:	retq   
  15a0a2:	callq  4ed90 <_init@@Base+0x1a0>
  15a0a7:	nopw   0x0(%rax,%rax,1)
  15a0b0:	push   %r13
  15a0b2:	push   %r12
  15a0b4:	push   %rbp
  15a0b5:	push   %rbx
  15a0b6:	mov    %rdx,%rbx
  15a0b9:	sub    $0x18,%rsp
  15a0bd:	test   %rsi,%rsi
  15a0c0:	je     15a0d4 <pum_get_height@@Base+0xfc4>
  15a0c2:	mov    %rdi,%r12
  15a0c5:	mov    %rdx,%rdi
  15a0c8:	mov    %rsi,%rbp
  15a0cb:	callq  1de820 <vim_isAbsName@@Base>
  15a0d0:	test   %eax,%eax
  15a0d2:	je     15a108 <pum_get_height@@Base+0xff8>
  15a0d4:	xor    %ecx,%ecx
  15a0d6:	xor    %edx,%edx
  15a0d8:	xor    %esi,%esi
  15a0da:	mov    %rbx,%rdi
  15a0dd:	callq  5c9b0 <buflist_new@@Base>
  15a0e2:	test   %rax,%rax
  15a0e5:	je     15a152 <pum_get_height@@Base+0x1042>
  15a0e7:	movl   $0x1,0x13d0(%rax)
  15a0f1:	mov    0xb8(%rax),%eax
  15a0f7:	add    $0x18,%rsp
  15a0fb:	pop    %rbx
  15a0fc:	pop    %rbp
  15a0fd:	pop    %r12
  15a0ff:	pop    %r13
  15a101:	retq   
  15a102:	nopw   0x0(%rax,%rax,1)
  15a108:	mov    %rbp,%rdi
  15a10b:	mov    $0x1,%edx
  15a110:	mov    %rbx,%rsi
  15a113:	callq  113320 <concat_fnames@@Base>
  15a118:	test   %rax,%rax
  15a11b:	mov    %rax,%rbp
  15a11e:	je     15a0d4 <pum_get_height@@Base+0xfc4>
  15a120:	mov    %rax,%rdi
  15a123:	callq  1545e0 <mch_getperm@@Base>
  15a128:	test   %rax,%rax
  15a12b:	js     15a160 <pum_get_height@@Base+0x1050>
  15a12d:	xor    %ecx,%ecx
  15a12f:	xor    %edx,%edx
  15a131:	xor    %esi,%esi
  15a133:	mov    %rbp,%rdi
  15a136:	callq  5c9b0 <buflist_new@@Base>
  15a13b:	mov    %rbp,%rdi
  15a13e:	mov    %rax,0x8(%rsp)
  15a143:	callq  11c7f0 <vim_free@@Base>
  15a148:	mov    0x8(%rsp),%rax
  15a14d:	test   %rax,%rax
  15a150:	jne    15a0e7 <pum_get_height@@Base+0xfd7>
  15a152:	add    $0x18,%rsp
  15a156:	xor    %eax,%eax
  15a158:	pop    %rbx
  15a159:	pop    %rbp
  15a15a:	pop    %r12
  15a15c:	pop    %r13
  15a15e:	retq   
  15a15f:	nop
  15a160:	mov    %rbp,%rdi
  15a163:	callq  11c7f0 <vim_free@@Base>
  15a168:	mov    0x1f8(%r12),%rax
  15a170:	test   %rax,%rax
  15a173:	je     15a245 <pum_get_height@@Base+0x1135>
  15a179:	mov    (%rax),%rbp
  15a17c:	xor    %r13d,%r13d
  15a17f:	test   %rbp,%rbp
  15a182:	je     15a1bf <pum_get_height@@Base+0x10af>
  15a184:	nopl   0x0(%rax)
  15a188:	mov    %r13,%rdi
  15a18b:	callq  11c7f0 <vim_free@@Base>
  15a190:	mov    0x8(%rbp),%rdi
  15a194:	mov    $0x1,%edx
  15a199:	mov    %rbx,%rsi
  15a19c:	callq  113320 <concat_fnames@@Base>
  15a1a1:	test   %rax,%rax
  15a1a4:	mov    %rax,%r13
  15a1a7:	je     15a1b6 <pum_get_height@@Base+0x10a6>
  15a1a9:	mov    %rax,%rdi
  15a1ac:	callq  1545e0 <mch_getperm@@Base>
  15a1b1:	test   %rax,%rax
  15a1b4:	jns    15a22b <pum_get_height@@Base+0x111b>
  15a1b6:	mov    0x0(%rbp),%rbp
  15a1ba:	test   %rbp,%rbp
  15a1bd:	jne    15a188 <pum_get_height@@Base+0x1078>
  15a1bf:	mov    %r13,%rdi
  15a1c2:	xor    %ebp,%ebp
  15a1c4:	callq  11c7f0 <vim_free@@Base>
  15a1c9:	mov    0x1f8(%r12),%rax
  15a1d1:	mov    (%rax),%r13
  15a1d4:	test   %r13,%r13
  15a1d7:	je     15a245 <pum_get_height@@Base+0x1135>
  15a1d9:	nopl   0x0(%rax)
  15a1e0:	mov    0x0(%r13),%rdx
  15a1e4:	mov    0x8(%r13),%rdi
  15a1e8:	mov    %rdx,(%rax)
  15a1eb:	callq  11c7f0 <vim_free@@Base>
  15a1f0:	mov    %r13,%rdi
  15a1f3:	callq  11c7f0 <vim_free@@Base>
  15a1f8:	mov    0x1f8(%r12),%rax
  15a200:	mov    (%rax),%r13
  15a203:	cmp    %rbp,%r13
  15a206:	jne    15a1e0 <pum_get_height@@Base+0x10d0>
  15a208:	test   %rbp,%rbp
  15a20b:	je     15a245 <pum_get_height@@Base+0x1135>
  15a20d:	mov    0x8(%rbp),%rdi
  15a211:	test   %rdi,%rdi
  15a214:	je     15a245 <pum_get_height@@Base+0x1135>
  15a216:	mov    $0x1,%edx
  15a21b:	mov    %rbx,%rsi
  15a21e:	callq  113320 <concat_fnames@@Base>
  15a223:	mov    %rax,%rbp
  15a226:	jmpq   15a12d <pum_get_height@@Base+0x101d>
  15a22b:	mov    %r13,%rdi
  15a22e:	callq  11c7f0 <vim_free@@Base>
  15a233:	mov    0x1f8(%r12),%rax
  15a23b:	mov    (%rax),%r13
  15a23e:	cmp    %r13,%rbp
  15a241:	jne    15a1e0 <pum_get_height@@Base+0x10d0>
  15a243:	jmp    15a20d <pum_get_height@@Base+0x10fd>
  15a245:	mov    %rbx,%rdi
  15a248:	callq  11f220 <vim_strsave@@Base>
  15a24d:	mov    %rax,%rbp
  15a250:	jmpq   15a12d <pum_get_height@@Base+0x101d>
  15a255:	nop
  15a256:	nopw   %cs:0x0(%rax,%rax,1)
  15a260:	push   %r15
  15a262:	push   %r14
  15a264:	mov    %rdx,%r15
  15a267:	push   %r13
  15a269:	push   %r12
  15a26b:	mov    %r8,%r13
  15a26e:	push   %rbp
  15a26f:	push   %rbx
  15a270:	mov    %rdi,%rbx
  15a273:	mov    $0x40,%edi
  15a278:	mov    %ecx,%ebp
  15a27a:	mov    %r9,%r14
  15a27d:	sub    $0x18,%rsp
  15a281:	mov    %rsi,0x8(%rsp)
  15a286:	callq  121d10 <alloc@@Base>
  15a28b:	test   %rax,%rax
  15a28e:	je     15a450 <pum_get_height@@Base+0x1340>
  15a294:	test   %ebp,%ebp
  15a296:	mov    %rax,%r12
  15a299:	jne    15a3d0 <pum_get_height@@Base+0x12c0>
  15a29f:	test   %r15,%r15
  15a2a2:	je     15a2ae <pum_get_height@@Base+0x119e>
  15a2a4:	cmpb   $0x0,(%r15)
  15a2a8:	jne    15a430 <pum_get_height@@Base+0x1320>
  15a2ae:	mov    %ebp,0x18(%r12)
  15a2b3:	mov    %r13,%rdi
  15a2b6:	callq  11f220 <vim_strsave@@Base>
  15a2bb:	test   %rax,%rax
  15a2be:	mov    %rax,0x30(%r12)
  15a2c3:	je     15a420 <pum_get_height@@Base+0x1310>
  15a2c9:	mov    0x50(%rsp),%eax
  15a2cd:	cmpq   $0x0,0x60(%rsp)
  15a2d3:	mov    %r14,0x10(%r12)
  15a2d8:	mov    %eax,0x1c(%r12)
  15a2dd:	mov    0x58(%rsp),%eax
  15a2e1:	mov    %al,0x38(%r12)
  15a2e6:	je     15a2f6 <pum_get_height@@Base+0x11e6>
  15a2e8:	mov    0x60(%rsp),%rax
  15a2ed:	cmpb   $0x0,(%rax)
  15a2f0:	jne    15a3f8 <pum_get_height@@Base+0x12e8>
  15a2f6:	movq   $0x0,0x28(%r12)
  15a2ff:	cmpl   $0x1,0x70(%rsp)
  15a304:	mov    0x68(%rsp),%eax
  15a308:	mov    %eax,0x20(%r12)
  15a30d:	mov    $0x1,%eax
  15a312:	je     15a32c <pum_get_height@@Base+0x121c>
  15a314:	mov    0x70(%rsp),%edi
  15a318:	callq  5f290 <vim_isprintc@@Base>
  15a31d:	movzbl 0x70(%rsp),%esi
  15a322:	test   %eax,%eax
  15a324:	mov    $0x0,%eax
  15a329:	cmovne %esi,%eax
  15a32c:	mov    %al,0x3a(%r12)
  15a331:	mov    0x78(%rsp),%eax
  15a335:	mov    %al,0x3b(%r12)
  15a33a:	movslq 0x8(%rbx),%rcx
  15a33e:	lea    (%rcx,%rcx,2),%rax
  15a342:	shl    $0x4,%rax
  15a346:	add    %rbx,%rax
  15a349:	mov    0x28(%rax),%edx
  15a34c:	test   %edx,%edx
  15a34e:	je     15a3b0 <pum_get_height@@Base+0x12a0>
  15a350:	mov    0x18(%rax),%rsi
  15a354:	mov    %rsi,0x8(%r12)
  15a359:	mov    0x18(%rax),%rax
  15a35d:	mov    %r12,(%rax)
  15a360:	lea    (%rcx,%rcx,2),%rax
  15a364:	movb   $0x0,0x39(%r12)
  15a36a:	add    $0x1,%edx
  15a36d:	movq   $0x0,(%r12)
  15a375:	shl    $0x4,%rax
  15a379:	add    %rax,%rbx
  15a37c:	mov    $0x1,%eax
  15a381:	mov    0x2c(%rbx),%ecx
  15a384:	mov    %r12,0x18(%rbx)
  15a388:	mov    %edx,0x28(%rbx)
  15a38b:	test   %ecx,%ecx
  15a38d:	jne    15a39e <pum_get_height@@Base+0x128e>
  15a38f:	cmpb   $0x0,0x3b(%r12)
  15a395:	je     15a39e <pum_get_height@@Base+0x128e>
  15a397:	mov    %edx,0x2c(%rbx)
  15a39a:	mov    %r12,0x20(%rbx)
  15a39e:	add    $0x18,%rsp
  15a3a2:	pop    %rbx
  15a3a3:	pop    %rbp
  15a3a4:	pop    %r12
  15a3a6:	pop    %r13
  15a3a8:	pop    %r14
  15a3aa:	pop    %r15
  15a3ac:	retq   
  15a3ad:	nopl   (%rax)
  15a3b0:	mov    %r12,0x10(%rax)
  15a3b4:	mov    %r12,0x20(%rax)
  15a3b8:	movl   $0x0,0x2c(%rax)
  15a3bf:	mov    0x28(%rax),%edx
  15a3c2:	movq   $0x0,0x8(%r12)
  15a3cb:	jmp    15a360 <pum_get_height@@Base+0x1250>
  15a3cd:	nopl   (%rax)
  15a3d0:	mov    %ebp,%edi
  15a3d2:	callq  55f40 <buflist_findnr@@Base>
  15a3d7:	test   %rax,%rax
  15a3da:	mov    %ebp,0x18(%r12)
  15a3df:	je     15a2b3 <pum_get_height@@Base+0x11a3>
  15a3e5:	movl   $0x1,0x13d0(%rax)
  15a3ef:	jmpq   15a2b3 <pum_get_height@@Base+0x11a3>
  15a3f4:	nopl   0x0(%rax)
  15a3f8:	mov    0x60(%rsp),%rdi
  15a3fd:	callq  11f220 <vim_strsave@@Base>
  15a402:	test   %rax,%rax
  15a405:	mov    %rax,0x28(%r12)
  15a40a:	jne    15a2ff <pum_get_height@@Base+0x11ef>
  15a410:	mov    0x30(%r12),%rdi
  15a415:	callq  11c7f0 <vim_free@@Base>
  15a41a:	nopw   0x0(%rax,%rax,1)
  15a420:	mov    %r12,%rdi
  15a423:	callq  11c7f0 <vim_free@@Base>
  15a428:	xor    %eax,%eax
  15a42a:	jmpq   15a39e <pum_get_height@@Base+0x128e>
  15a42f:	nop
  15a430:	mov    0x8(%rsp),%rsi
  15a435:	mov    %r15,%rdx
  15a438:	mov    %rbx,%rdi
  15a43b:	callq  15a0b0 <pum_get_height@@Base+0xfa0>
  15a440:	mov    %eax,%ebp
  15a442:	jmpq   15a2ae <pum_get_height@@Base+0x119e>
  15a447:	nopw   0x0(%rax,%rax,1)
  15a450:	add    $0x18,%rsp
  15a454:	xor    %eax,%eax
  15a456:	pop    %rbx
  15a457:	pop    %rbp
  15a458:	pop    %r12
  15a45a:	pop    %r13
  15a45c:	pop    %r14
  15a45e:	pop    %r15
  15a460:	retq   
  15a461:	nopl   0x0(%rax,%rax,1)
  15a466:	nopw   %cs:0x0(%rax,%rax,1)
  15a470:	push   %r15
  15a472:	push   %r14
  15a474:	mov    %rdi,%r14
  15a477:	push   %r13
  15a479:	push   %r12
  15a47b:	mov    $0x401,%edi
  15a480:	push   %rbp
  15a481:	push   %rbx
  15a482:	mov    %rsi,%rbx
  15a485:	mov    $0x3,%esi
  15a48a:	mov    %r9d,%ebp
  15a48d:	sub    $0x198,%rsp
  15a494:	mov    %rdx,0x98(%rsp)
  15a49c:	mov    %rcx,0x80(%rsp)
  15a4a4:	mov    %r8,0x10(%rsp)
  15a4a9:	mov    0x1e0(%rsp),%r12
  15a4b1:	mov    %fs:0x28,%rax
  15a4ba:	mov    %rax,0x188(%rsp)
  15a4c2:	xor    %eax,%eax
  15a4c4:	movq   $0x0,0xc0(%rsp)
  15a4d0:	movl   $0x0,0xb8(%rsp)
  15a4db:	movl   $0x0,0xbc(%rsp)
  15a4e6:	callq  121c60 <alloc_id@@Base>
  15a4eb:	mov    $0x4,%esi
  15a4f0:	mov    $0x401,%edi
  15a4f5:	mov    %rax,%r15
  15a4f8:	callq  121c60 <alloc_id@@Base>
  15a4fd:	mov    $0x5,%esi
  15a502:	mov    $0x401,%edi
  15a507:	mov    %rax,%r13
  15a50a:	mov    %rax,0x38(%rsp)
  15a50f:	callq  121c60 <alloc_id@@Base>
  15a514:	test   %r15,%r15
  15a517:	mov    %rax,%rcx
  15a51a:	mov    %rax,0x18(%rsp)
  15a51f:	sete   %dl
  15a522:	test   %r13,%r13
  15a525:	sete   %al
  15a528:	or     %al,%dl
  15a52a:	jne    15bf71 <pum_get_height@@Base+0x2e61>
  15a530:	test   %rcx,%rcx
  15a533:	je     15bf71 <pum_get_height@@Base+0x2e61>
  15a539:	test   %rbx,%rbx
  15a53c:	je     15ba6d <pum_get_height@@Base+0x295d>
  15a542:	lea    0xe0913(%rip),%rsi        # 23ae5c <_IO_stdin_used@@Base+0x2489c>
  15a549:	mov    %rbx,%rdi
  15a54c:	callq  4ef58 <_init@@Base+0x368>
  15a551:	test   %rax,%rax
  15a554:	mov    %rax,0x60(%rsp)
  15a559:	je     15bf98 <pum_get_height@@Base+0x2e88>
  15a55f:	test   %ebp,%ebp
  15a561:	jne    15b973 <pum_get_height@@Base+0x2863>
  15a567:	mov    0x8(%r14),%eax
  15a56b:	cmp    0x4(%r14),%eax
  15a56f:	je     15b973 <pum_get_height@@Base+0x2863>
  15a575:	movslq %eax,%rdx
  15a578:	movq   $0x0,0x90(%rsp)
  15a584:	lea    (%rdx,%rdx,2),%rdx
  15a588:	shl    $0x4,%rdx
  15a58c:	add    %r14,%rdx
  15a58f:	mov    0x28(%rdx),%ecx
  15a592:	test   %ecx,%ecx
  15a594:	jle    15a5a2 <pum_get_height@@Base+0x1492>
  15a596:	mov    0x18(%rdx),%rbx
  15a59a:	mov    %rbx,0x90(%rsp)
  15a5a2:	mov    0x10(%rsp),%rbx
  15a5a7:	cmp    %rbx,0x354312(%rip)        # 4ae8c0 <p_efm@@Base>
  15a5ae:	jne    15a5bf <pum_get_height@@Base+0x14af>
  15a5b0:	cmpq   $0x0,0x80(%rsp)
  15a5b9:	je     15bcc7 <pum_get_height@@Base+0x2bb7>
  15a5bf:	cmp    %eax,0x1f0(%r14)
  15a5c6:	je     15a61e <pum_get_height@@Base+0x150e>
  15a5c8:	lea    0x1f8(%r14),%rdi
  15a5cf:	mov    %eax,0x1f0(%r14)
  15a5d6:	callq  1592a0 <pum_get_height@@Base+0x190>
  15a5db:	lea    0x208(%r14),%rdi
  15a5e2:	movq   $0x0,0x200(%r14)
  15a5ed:	callq  1592a0 <pum_get_height@@Base+0x190>
  15a5f2:	movq   $0x0,0x210(%r14)
  15a5fd:	movl   $0x0,0x218(%r14)
  15a608:	movl   $0x0,0x21c(%r14)
  15a613:	movl   $0x0,0x220(%r14)
  15a61e:	mov    0x34ad2b(%rip),%rbx        # 4a5350 <current_funccal@@Base+0x3a48>
  15a625:	test   %rbx,%rbx
  15a628:	je     15ad55 <pum_get_height@@Base+0x1c45>
  15a62e:	mov    0x10(%rsp),%rsi
  15a633:	mov    %rbx,%rdi
  15a636:	callq  4eef0 <_init@@Base+0x300>
  15a63b:	test   %eax,%eax
  15a63d:	jne    15ad55 <pum_get_height@@Base+0x1c45>
  15a643:	cmpq   $0x0,0x34acfd(%rip)        # 4a5348 <current_funccal@@Base+0x3a40>
  15a64b:	je     15b236 <pum_get_height@@Base+0x2126>
  15a651:	mov    0x80(%rsp),%rax
  15a659:	movl   $0x0,0x35359d(%rip)        # 4adc00 <got_int@@Base>
  15a663:	movl   $0x1,0x178(%rsp)
  15a66e:	test   %rax,%rax
  15a671:	je     15bde1 <pum_get_height@@Base+0x2cd1>
  15a677:	mov    (%rax),%eax
  15a679:	cmp    $0x2,%eax
  15a67c:	je     15bb88 <pum_get_height@@Base+0x2a78>
  15a682:	cmp    $0x5,%eax
  15a685:	movq   $0x0,0x78(%rsp)
  15a68e:	movq   $0x0,0x88(%rsp)
  15a69a:	je     15bc89 <pum_get_height@@Base+0x2b79>
  15a6a0:	lea    0xbc(%rsp),%rax
  15a6a8:	xor    %ebp,%ebp
  15a6aa:	movl   $0x0,0x28(%rsp)
  15a6b2:	movl   $0x0,0x10(%rsp)
  15a6ba:	movb   $0x0,0x20(%rsp)
  15a6bf:	xor    %r12d,%r12d
  15a6c2:	mov    %rax,0xa0(%rsp)
  15a6ca:	lea    0xb8(%rsp),%rax
  15a6d2:	movl   $0x401,0x5c(%rsp)
  15a6da:	mov    %rbp,0x8(%rsp)
  15a6df:	mov    %rax,0xa8(%rsp)
  15a6e7:	lea    0xd0(%rsp),%rax
  15a6ef:	mov    %rax,0x30(%rsp)
  15a6f4:	mov    0x353506(%rip),%eax        # 4adc00 <got_int@@Base>
  15a6fa:	test   %eax,%eax
  15a6fc:	jne    15acf3 <pum_get_height@@Base+0x1be3>
  15a702:	cmpq   $0x0,0x60(%rsp)
  15a708:	je     15b1c9 <pum_get_height@@Base+0x20b9>
  15a70e:	mov    0x60(%rsp),%rdx
  15a713:	mov    0x354916(%rip),%rdi        # 4af030 <IObuff@@Base>
  15a71a:	mov    $0x401,%esi
  15a71f:	callq  4eec0 <_init@@Base+0x2d0>
  15a724:	test   %rax,%rax
  15a727:	je     15acfb <pum_get_height@@Base+0x1beb>
  15a72d:	mov    0x3548fc(%rip),%rax        # 4af030 <IObuff@@Base>
  15a734:	mov    %rax,%rdi
  15a737:	mov    %rax,0x8(%rsp)
  15a73c:	callq  4ed80 <_init@@Base+0x190>
  15a741:	cmp    $0x400,%eax
  15a746:	mov    %eax,%ebx
  15a748:	mov    %eax,0xbc(%rsp)
  15a74f:	je     15b089 <pum_get_height@@Base+0x1f79>
  15a755:	test   %ebx,%ebx
  15a757:	jle    15a76f <pum_get_height@@Base+0x165f>
  15a759:	mov    0x8(%rsp),%rax
  15a75e:	movslq %ebx,%rbx
  15a761:	lea    -0x1(%rax,%rbx,1),%rax
  15a766:	cmpb   $0xa,(%rax)
  15a769:	je     15b1c1 <pum_get_height@@Base+0x20b1>
  15a76f:	mov    0x8(%rsp),%rdi
  15a774:	callq  126ab0 <remove_bom@@Base>
  15a779:	test   %rbp,%rbp
  15a77c:	cmove  0x34abc4(%rip),%rbp        # 4a5348 <current_funccal@@Base+0x3a40>
  15a784:	lea    0x208(%r14),%rax
  15a78b:	movq   $0x0,0x40(%rsp)
  15a794:	movl   $0x1,0x48(%rsp)
  15a79c:	mov    %rax,0x68(%rsp)
  15a7a1:	nopl   0x0(%rax)
  15a7a8:	test   %rbp,%rbp
  15a7ab:	je     15ac10 <pum_get_height@@Base+0x1b00>
  15a7b1:	mov    0x220(%r14),%r13d
  15a7b8:	movzbl 0x1a(%rbp),%ebx
  15a7bc:	test   %r13d,%r13d
  15a7bf:	jne    15aee0 <pum_get_height@@Base+0x1dd0>
  15a7c5:	mov    0x18(%rsp),%rax
  15a7ca:	movb   $0x0,(%r15)
  15a7ce:	movb   $0x0,(%rax)
  15a7d1:	mov    0x220(%r14),%r12d
  15a7d8:	test   %r12d,%r12d
  15a7db:	jne    15a7e5 <pum_get_height@@Base+0x16d5>
  15a7dd:	mov    0x38(%rsp),%rax
  15a7e2:	movb   $0x0,(%rax)
  15a7e5:	mov    0x0(%rbp),%rax
  15a7e9:	mov    0x8(%rsp),%rsi
  15a7ee:	xor    %edx,%edx
  15a7f0:	mov    0x30(%rsp),%rdi
  15a7f5:	mov    %rax,0xd0(%rsp)
  15a7fd:	callq  17ff00 <vim_regexec@@Base>
  15a802:	mov    %eax,%r12d
  15a805:	mov    0xd0(%rsp),%rax
  15a80d:	test   %r12d,%r12d
  15a810:	mov    %rax,0x0(%rbp)
  15a814:	je     15aec0 <pum_get_height@@Base+0x1db0>
  15a81a:	cmp    $0x43,%ebx
  15a81d:	je     15a824 <pum_get_height@@Base+0x1714>
  15a81f:	cmp    $0x5a,%ebx
  15a822:	jne    15a834 <pum_get_height@@Base+0x1724>
  15a824:	mov    0x218(%r14),%r12d
  15a82b:	test   %r12d,%r12d
  15a82e:	je     15aec0 <pum_get_height@@Base+0x1db0>
  15a834:	lea    0xd059b(%rip),%rdi        # 22add6 <_IO_stdin_used@@Base+0x14816>
  15a83b:	mov    %ebx,%esi
  15a83d:	callq  11c810 <vim_strchr@@Base>
  15a842:	test   %rax,%rax
  15a845:	mov    $0x0,%eax
  15a84a:	cmovne %ebx,%eax
  15a84d:	mov    %eax,0x10(%rsp)
  15a851:	movzbl 0x10(%rbp),%eax
  15a855:	test   %eax,%eax
  15a857:	je     15a8c9 <pum_get_height@@Base+0x17b9>
  15a859:	cmpq   $0x0,0xd8(%rsp,%rax,8)
  15a862:	je     15aea0 <pum_get_height@@Base+0x1d90>
  15a868:	lea    0xa(%rax),%r12
  15a86c:	mov    0xd8(%rsp,%r12,8),%rdx
  15a874:	test   %rdx,%rdx
  15a877:	je     15aea0 <pum_get_height@@Base+0x1d90>
  15a87d:	movzbl (%rdx),%r13d
  15a881:	movb   $0x0,(%rdx)
  15a884:	mov    %r15,%rsi
  15a887:	mov    0xd8(%rsp,%rax,8),%rdi
  15a88f:	mov    $0x400,%edx
  15a894:	callq  113df0 <expand_env@@Base>
  15a899:	mov    0xd8(%rsp,%r12,8),%rax
  15a8a1:	lea    0xd0529(%rip),%rdi        # 22add1 <_IO_stdin_used@@Base+0x14811>
  15a8a8:	mov    %ebx,%esi
  15a8aa:	mov    %r13b,(%rax)
  15a8ad:	callq  11c810 <vim_strchr@@Base>
  15a8b2:	test   %rax,%rax
  15a8b5:	je     15a8c9 <pum_get_height@@Base+0x17b9>
  15a8b7:	mov    %r15,%rdi
  15a8ba:	callq  1545e0 <mch_getperm@@Base>
  15a8bf:	cmp    $0xffffffffffffffff,%rax
  15a8c3:	je     15aea0 <pum_get_height@@Base+0x1d90>
  15a8c9:	movzbl 0x11(%rbp),%eax
  15a8cd:	test   %eax,%eax
  15a8cf:	je     15afa0 <pum_get_height@@Base+0x1e90>
  15a8d5:	mov    0xd8(%rsp,%rax,8),%rdi
  15a8dd:	test   %rdi,%rdi
  15a8e0:	je     15aea0 <pum_get_height@@Base+0x1d90>
  15a8e6:	xor    %esi,%esi
  15a8e8:	mov    $0xa,%edx
  15a8ed:	callq  4ef60 <_init@@Base+0x370>
  15a8f2:	mov    %eax,0x28(%rsp)
  15a8f6:	movzbl 0x12(%rbp),%eax
  15a8fa:	test   %eax,%eax
  15a8fc:	je     15afb4 <pum_get_height@@Base+0x1ea4>
  15a902:	mov    0xd8(%rsp,%rax,8),%rdi
  15a90a:	test   %rdi,%rdi
  15a90d:	je     15af00 <pum_get_height@@Base+0x1df0>
  15a913:	mov    $0xa,%edx
  15a918:	xor    %esi,%esi
  15a91a:	callq  4ef60 <_init@@Base+0x370>
  15a91f:	mov    %rax,0x50(%rsp)
  15a924:	movzbl 0x13(%rbp),%r12d
  15a929:	test   %r12d,%r12d
  15a92c:	je     15a94e <pum_get_height@@Base+0x183e>
  15a92e:	mov    0xd8(%rsp,%r12,8),%rdi
  15a936:	test   %rdi,%rdi
  15a939:	je     15af00 <pum_get_height@@Base+0x1df0>
  15a93f:	mov    $0xa,%edx
  15a944:	xor    %esi,%esi
  15a946:	callq  4ef60 <_init@@Base+0x370>
  15a94b:	mov    %eax,%r12d
  15a94e:	movzbl 0x14(%rbp),%eax
  15a952:	test   %eax,%eax
  15a954:	je     15a96e <pum_get_height@@Base+0x185e>
  15a956:	mov    0xd8(%rsp,%rax,8),%rax
  15a95e:	test   %rax,%rax
  15a961:	je     15afc8 <pum_get_height@@Base+0x1eb8>
  15a967:	movzbl (%rax),%eax
  15a96a:	mov    %eax,0x10(%rsp)
  15a96e:	cmpb   $0x2b,0x1b(%rbp)
  15a972:	je     15b000 <pum_get_height@@Base+0x1ef0>
  15a978:	movzbl 0x15(%rbp),%eax
  15a97c:	test   %eax,%eax
  15a97e:	je     15a9ef <pum_get_height@@Base+0x18df>
  15a980:	movslq %eax,%r13
  15a983:	mov    0xd8(%rsp,%r13,8),%rsi
  15a98b:	test   %rsi,%rsi
  15a98e:	je     15afc8 <pum_get_height@@Base+0x1eb8>
  15a994:	mov    0x128(%rsp,%r13,8),%rdx
  15a99c:	test   %rdx,%rdx
  15a99f:	je     15afc8 <pum_get_height@@Base+0x1eb8>
  15a9a5:	sub    %rsi,%rdx
  15a9a8:	cmp    %edx,0x5c(%rsp)
  15a9ac:	jge    15a9e2 <pum_get_height@@Base+0x18d2>
  15a9ae:	lea    0x1(%rdx),%eax
  15a9b1:	mov    0x38(%rsp),%rdi
  15a9b6:	mov    %rdx,0x20(%rsp)
  15a9bb:	movslq %eax,%rsi
  15a9be:	mov    %eax,0x5c(%rsp)
  15a9c2:	callq  4f078 <_init@@Base+0x488>
  15a9c7:	test   %rax,%rax
  15a9ca:	mov    %rax,0x38(%rsp)
  15a9cf:	je     15bdfb <pum_get_height@@Base+0x2ceb>
  15a9d5:	mov    0xd8(%rsp,%r13,8),%rsi
  15a9dd:	mov    0x20(%rsp),%rdx
  15a9e2:	mov    0x38(%rsp),%rdi
  15a9e7:	movslq %edx,%rdx
  15a9ea:	callq  11c750 <vim_strncpy@@Base>
  15a9ef:	movzbl 0x16(%rbp),%eax
  15a9f3:	test   %eax,%eax
  15a9f5:	je     15b070 <pum_get_height@@Base+0x1f60>
  15a9fb:	mov    0xd8(%rsp,%rax,8),%r13
  15aa03:	test   %r13,%r13
  15aa06:	je     15afc8 <pum_get_height@@Base+0x1eb8>
  15aa0c:	movzbl 0x17(%rbp),%eax
  15aa10:	test   %eax,%eax
  15aa12:	je     15b07f <pum_get_height@@Base+0x1f6f>
  15aa18:	movslq %eax,%rdx
  15aa1b:	mov    0xd8(%rsp,%rdx,8),%rax
  15aa23:	test   %rax,%rax
  15aa26:	je     15afc8 <pum_get_height@@Base+0x1eb8>
  15aa2c:	mov    0x128(%rsp,%rdx,8),%rcx
  15aa34:	test   %rcx,%rcx
  15aa37:	je     15afc8 <pum_get_height@@Base+0x1eb8>
  15aa3d:	cmp    %rcx,%rax
  15aa40:	je     15b3ab <pum_get_height@@Base+0x229b>
  15aa46:	xor    %r12d,%r12d
  15aa49:	nopl   0x0(%rax)
  15aa50:	lea    0x1(%r12),%edx
  15aa55:	add    $0x8,%r12d
  15aa59:	and    $0xfffffff8,%r12d
  15aa5d:	cmpb   $0x9,(%rax)
  15aa60:	cmovne %edx,%r12d
  15aa64:	add    $0x1,%rax
  15aa68:	cmp    %rax,%rcx
  15aa6b:	jne    15aa50 <pum_get_height@@Base+0x1940>
  15aa6d:	add    $0x1,%r12d
  15aa71:	movb   $0x1,0x20(%rsp)
  15aa76:	movzbl 0x18(%rbp),%eax
  15aa7a:	test   %eax,%eax
  15aa7c:	je     15aaa3 <pum_get_height@@Base+0x1993>
  15aa7e:	mov    0xd8(%rsp,%rax,8),%rdi
  15aa86:	test   %rdi,%rdi
  15aa89:	je     15aeb0 <pum_get_height@@Base+0x1da0>
  15aa8f:	mov    $0xa,%edx
  15aa94:	xor    %esi,%esi
  15aa96:	callq  4ef60 <_init@@Base+0x370>
  15aa9b:	movb   $0x1,0x20(%rsp)
  15aaa0:	mov    %eax,%r12d
  15aaa3:	movzbl 0x19(%rbp),%eax
  15aaa7:	test   %eax,%eax
  15aaa9:	je     15ab1c <pum_get_height@@Base+0x1a0c>
  15aaab:	movslq %eax,%rdx
  15aaae:	mov    0xd8(%rsp,%rdx,8),%rcx
  15aab6:	test   %rcx,%rcx
  15aab9:	je     15aeb0 <pum_get_height@@Base+0x1da0>
  15aabf:	mov    0x128(%rsp,%rdx,8),%rax
  15aac7:	test   %rax,%rax
  15aaca:	je     15aeb0 <pum_get_height@@Base+0x1da0>
  15aad0:	mov    0x18(%rsp),%rdi
  15aad5:	sub    %rcx,%rax
  15aad8:	mov    $0x3fb,%ecx
  15aadd:	cmp    $0x3fb,%eax
  15aae2:	cmovg  %ecx,%eax
  15aae5:	movl   $0x565c5e,(%rdi)
  15aaeb:	mov    0xd8(%rsp,%rdx,8),%rsi
  15aaf3:	movslq %eax,%rcx
  15aaf6:	mov    %rcx,%rdx
  15aaf9:	mov    %rcx,0x70(%rsp)
  15aafe:	callq  4ee40 <_init@@Base+0x250>
  15ab03:	mov    0x18(%rsp),%rdi
  15ab08:	mov    0x70(%rsp),%rcx
  15ab0d:	movb   $0x5c,0x3(%rdi,%rcx,1)
  15ab12:	movb   $0x24,0x4(%rdi,%rcx,1)
  15ab17:	movb   $0x0,0x5(%rdi,%rcx,1)
  15ab1c:	cmp    $0x44,%ebx
  15ab1f:	movl   $0x0,0x220(%r14)
  15ab2a:	sete   %al
  15ab2d:	je     15b1fa <pum_get_height@@Base+0x20ea>
  15ab33:	cmp    $0x58,%ebx
  15ab36:	je     15bdc9 <pum_get_height@@Base+0x2cb9>
  15ab3c:	mov    0x1c(%rbp),%r10d
  15ab40:	mov    0x40(%rsp),%rax
  15ab45:	lea    0xd0289(%rip),%rdi        # 22add5 <_IO_stdin_used@@Base+0x14815>
  15ab4c:	mov    %ebx,%esi
  15ab4e:	test   %r10d,%r10d
  15ab51:	cmovne %rbp,%rax
  15ab55:	mov    %rax,0x40(%rsp)
  15ab5a:	callq  11c810 <vim_strchr@@Base>
  15ab5f:	test   %rax,%rax
  15ab62:	jne    15b2d0 <pum_get_height@@Base+0x21c0>
  15ab68:	lea    0xd026b(%rip),%rdi        # 22adda <_IO_stdin_used@@Base+0x1481a>
  15ab6f:	mov    %ebx,%esi
  15ab71:	callq  11c810 <vim_strchr@@Base>
  15ab76:	test   %rax,%rax
  15ab79:	jne    15b2fa <pum_get_height@@Base+0x21ea>
  15ab7f:	lea    0xd024b(%rip),%rdi        # 22add1 <_IO_stdin_used@@Base+0x14811>
  15ab86:	mov    %ebx,%esi
  15ab88:	callq  11c810 <vim_strchr@@Base>
  15ab8d:	test   %rax,%rax
  15ab90:	je     15af66 <pum_get_height@@Base+0x1e56>
  15ab96:	cmpb   $0x0,(%r15)
  15ab9a:	jne    15af18 <pum_get_height@@Base+0x1e08>
  15aba0:	cmp    $0x51,%ebx
  15aba3:	je     15afe0 <pum_get_height@@Base+0x1ed0>
  15aba9:	test   %r13,%r13
  15abac:	movb   $0x0,(%r15)
  15abb0:	je     15af5e <pum_get_height@@Base+0x1e4e>
  15abb6:	cmpb   $0x0,0x0(%r13)
  15abbb:	je     15af5e <pum_get_height@@Base+0x1e4e>
  15abc1:	mov    %r13,%rdi
  15abc4:	callq  607e0 <skipwhite@@Base>
  15abc9:	mov    %rax,%rdi
  15abcc:	callq  4ed80 <_init@@Base+0x190>
  15abd1:	mov    %r13,%rdi
  15abd4:	mov    %rax,%rbx
  15abd7:	callq  607e0 <skipwhite@@Base>
  15abdc:	mov    0x35444d(%rip),%rdi        # 4af030 <IObuff@@Base>
  15abe3:	lea    0x1(%rbx),%rdx
  15abe7:	mov    %rax,%rsi
  15abea:	callq  4f0d0 <_init@@Base+0x4e0>
  15abef:	test   %rbp,%rbp
  15abf2:	movl   $0x1,0x220(%r14)
  15abfd:	movl   $0x0,0x48(%rsp)
  15ac05:	jne    15a7b1 <pum_get_height@@Base+0x16a1>
  15ac0b:	nopl   0x0(%rax,%rax,1)
  15ac10:	movl   $0x0,0x220(%r14)
  15ac1b:	movb   $0x0,(%r15)
  15ac1f:	mov    0xbc(%rsp),%eax
  15ac26:	cmp    0x5c(%rsp),%eax
  15ac2a:	jle    15ac58 <pum_get_height@@Base+0x1b48>
  15ac2c:	mov    0x38(%rsp),%rdi
  15ac31:	add    $0x1,%eax
  15ac34:	movslq %eax,%rsi
  15ac37:	callq  4f078 <_init@@Base+0x488>
  15ac3c:	test   %rax,%rax
  15ac3f:	mov    %rax,0x38(%rsp)
  15ac44:	je     15bdfb <pum_get_height@@Base+0x2ceb>
  15ac4a:	mov    0xbc(%rsp),%eax
  15ac51:	lea    0x1(%rax),%ebx
  15ac54:	mov    %ebx,0x5c(%rsp)
  15ac58:	mov    0x8(%rsp),%rsi
  15ac5d:	mov    0x38(%rsp),%rdi
  15ac62:	movslq %eax,%rdx
  15ac65:	callq  11c750 <vim_strncpy@@Base>
  15ac6a:	test   %rbp,%rbp
  15ac6d:	je     15ba8f <pum_get_height@@Base+0x297f>
  15ac73:	mov    0x40(%rsp),%rbp
  15ac78:	movq   $0x0,0x50(%rsp)
  15ac81:	movl   $0x0,0x48(%rsp)
  15ac89:	cmpb   $0x0,(%r15)
  15ac8d:	movzbl 0x20(%rsp),%eax
  15ac92:	mov    %r15,%rdx
  15ac95:	mov    0x200(%r14),%rsi
  15ac9c:	jne    15aca7 <pum_get_height@@Base+0x1b97>
  15ac9e:	test   %rsi,%rsi
  15aca1:	je     15b9c8 <pum_get_height@@Base+0x28b8>
  15aca7:	mov    0x48(%rsp),%ebx
  15acab:	xor    %ecx,%ecx
  15acad:	mov    %r14,%rdi
  15acb0:	push   %rbx
  15acb1:	mov    0x18(%rsp),%ebx
  15acb5:	push   %rbx
  15acb6:	mov    0x38(%rsp),%ebx
  15acba:	push   %rbx
  15acbb:	pushq  0x30(%rsp)
  15acbf:	push   %rax
  15acc0:	push   %r12
  15acc2:	mov    0x80(%rsp),%r9
  15acca:	mov    0x68(%rsp),%r8
  15accf:	callq  15a260 <pum_get_height@@Base+0x1150>
  15acd4:	add    $0x30,%rsp
  15acd8:	test   %eax,%eax
  15acda:	je     15b236 <pum_get_height@@Base+0x2126>
  15ace0:	callq  119f10 <line_breakcheck@@Base>
  15ace5:	mov    0x352f15(%rip),%eax        # 4adc00 <got_int@@Base>
  15aceb:	test   %eax,%eax
  15aced:	je     15a702 <pum_get_height@@Base+0x15f2>
  15acf3:	cmpq   $0x0,0x60(%rsp)
  15acf9:	je     15ad0d <pum_get_height@@Base+0x1bfd>
  15acfb:	mov    0x60(%rsp),%rdi
  15ad00:	callq  4ecc0 <_init@@Base+0xd0>
  15ad05:	test   %eax,%eax
  15ad07:	jne    15bce9 <pum_get_height@@Base+0x2bd9>
  15ad0d:	movslq 0x8(%r14),%rcx
  15ad11:	lea    (%rcx,%rcx,2),%rax
  15ad15:	shl    $0x4,%rax
  15ad19:	add    %r14,%rax
  15ad1c:	mov    0x2c(%rax),%edx
  15ad1f:	test   %edx,%edx
  15ad21:	je     15bca2 <pum_get_height@@Base+0x2b92>
  15ad27:	lea    0x3(%rcx,%rcx,2),%rdx
  15ad2c:	shl    $0x4,%rdx
  15ad30:	cmpq   $0x0,0x20(%rax)
  15ad35:	movl   $0x0,(%r14,%rdx,1)
  15ad3d:	je     15bf5f <pum_get_height@@Base+0x2e4f>
  15ad43:	lea    (%rcx,%rcx,2),%rax
  15ad47:	shl    $0x4,%rax
  15ad4b:	mov    0x28(%r14,%rax,1),%ebx
  15ad50:	jmpq   15b25a <pum_get_height@@Base+0x214a>
  15ad55:	mov    %rbx,%rdi
  15ad58:	callq  11c7f0 <vim_free@@Base>
  15ad5d:	lea    0x34a5e4(%rip),%rdi        # 4a5348 <current_funccal@@Base+0x3a40>
  15ad64:	movq   $0x0,0x34a5e1(%rip)        # 4a5350 <current_funccal@@Base+0x3a48>
  15ad6f:	callq  1597b0 <pum_get_height@@Base+0x6a0>
  15ad74:	mov    $0x4,%esi
  15ad79:	mov    $0x401,%edi
  15ad7e:	movq   $0x0,0xc8(%rsp)
  15ad8a:	callq  121c60 <alloc_id@@Base>
  15ad8f:	test   %rax,%rax
  15ad92:	mov    %rax,0x48(%rsp)
  15ad97:	je     15bd38 <pum_get_height@@Base+0x2c28>
  15ad9d:	mov    0x10(%rsp),%rdi
  15ada2:	lea    0x324f5f(%rip),%r12        # 47fd08 <_IO_stdin_used@@Base+0x269748>
  15ada9:	lea    0x324ec8(%rip),%rbp        # 47fc78 <_IO_stdin_used@@Base+0x2696b8>
  15adb0:	callq  4ed80 <_init@@Base+0x190>
  15adb5:	lea    0x1e(,%rax,4),%ebx
  15adbc:	mov    $0x3,%eax
  15adc1:	jmp    15add5 <pum_get_height@@Base+0x1cc5>
  15adc3:	nopl   0x0(%rax,%rax,1)
  15adc8:	mov    (%r12),%rdi
  15adcc:	sub    $0x10,%r12
  15add0:	callq  4ed80 <_init@@Base+0x190>
  15add5:	add    %eax,%ebx
  15add7:	cmp    %rbp,%r12
  15adda:	jne    15adc8 <pum_get_height@@Base+0x1cb8>
  15addc:	lea    0x2(%rbx),%edi
  15addf:	callq  121d10 <alloc@@Base>
  15ade4:	test   %rax,%rax
  15ade7:	mov    %rax,0x8(%rsp)
  15adec:	je     15b717 <pum_get_height@@Base+0x2607>
  15adf2:	mov    0x10(%rsp),%rbx
  15adf7:	add    $0x1,%rax
  15adfb:	xor    %ebp,%ebp
  15adfd:	mov    %rax,0x28(%rsp)
  15ae02:	cmpb   $0x0,(%rbx)
  15ae05:	mov    %rbx,%r13
  15ae08:	je     15b5a7 <pum_get_height@@Base+0x2497>
  15ae0e:	mov    %r15,0x30(%rsp)
  15ae13:	mov    %r14,0x40(%rsp)
  15ae18:	nopl   0x0(%rax,%rax,1)
  15ae20:	mov    $0x20,%edi
  15ae25:	callq  121cc0 <alloc_clear@@Base>
  15ae2a:	test   %rax,%rax
  15ae2d:	mov    %rax,%rbx
  15ae30:	je     15bb4b <pum_get_height@@Base+0x2a3b>
  15ae36:	cmpq   $0x0,0xc8(%rsp)
  15ae3f:	je     15b90b <pum_get_height@@Base+0x27fb>
  15ae45:	mov    %rax,0x8(%rbp)
  15ae49:	movzbl 0x0(%r13),%eax
  15ae4e:	test   %al,%al
  15ae50:	je     15b920 <pum_get_height@@Base+0x2810>
  15ae56:	cmp    $0x2c,%al
  15ae58:	je     15b920 <pum_get_height@@Base+0x2810>
  15ae5e:	xor    %edx,%edx
  15ae60:	xor    %ecx,%ecx
  15ae62:	jmp    15ae87 <pum_get_height@@Base+0x1d77>
  15ae64:	nopl   0x0(%rax)
  15ae68:	add    $0x1,%edx
  15ae6b:	movslq %edx,%rcx
  15ae6e:	lea    0x0(%r13,%rcx,1),%r14
  15ae73:	movzbl (%r14),%eax
  15ae77:	test   %al,%al
  15ae79:	je     15b440 <pum_get_height@@Base+0x2330>
  15ae7f:	cmp    $0x2c,%al
  15ae81:	je     15b440 <pum_get_height@@Base+0x2330>
  15ae87:	cmp    $0x5c,%al
  15ae89:	jne    15ae68 <pum_get_height@@Base+0x1d58>
  15ae8b:	cmpb   $0x1,0x1(%r13,%rcx,1)
  15ae91:	sbb    $0xffffffff,%edx
  15ae94:	jmp    15ae68 <pum_get_height@@Base+0x1d58>
  15ae96:	nopw   %cs:0x0(%rax,%rax,1)
  15aea0:	movl   $0xffffffff,0x28(%rsp)
  15aea8:	movb   $0x0,0x20(%rsp)
  15aead:	xor    %r12d,%r12d
  15aeb0:	mov    0x8(%rbp),%rbp
  15aeb4:	jmpq   15a7a8 <pum_get_height@@Base+0x1698>
  15aeb9:	nopl   0x0(%rax)
  15aec0:	movl   $0x0,0x10(%rsp)
  15aec8:	movl   $0xffffffff,0x28(%rsp)
  15aed0:	movb   $0x0,0x20(%rsp)
  15aed5:	mov    0x8(%rbp),%rbp
  15aed9:	jmpq   15a7a8 <pum_get_height@@Base+0x1698>
  15aede:	xchg   %ax,%ax
  15aee0:	lea    0xcfeea(%rip),%rdi        # 22add1 <_IO_stdin_used@@Base+0x14811>
  15aee7:	mov    %ebx,%esi
  15aee9:	callq  11c810 <vim_strchr@@Base>
  15aeee:	test   %rax,%rax
  15aef1:	jne    15a7c5 <pum_get_height@@Base+0x16b5>
  15aef7:	mov    0x8(%rbp),%rbp
  15aefb:	jmpq   15a7a8 <pum_get_height@@Base+0x1698>
  15af00:	movb   $0x0,0x20(%rsp)
  15af05:	xor    %r12d,%r12d
  15af08:	mov    0x8(%rbp),%rbp
  15af0c:	jmpq   15a7a8 <pum_get_height@@Base+0x1698>
  15af11:	nopl   0x0(%rax)
  15af18:	mov    %r15,%rdi
  15af1b:	callq  1545e0 <mch_getperm@@Base>
  15af20:	test   %rax,%rax
  15af23:	js     15af5e <pum_get_height@@Base+0x1e4e>
  15af25:	cmpb   $0x0,(%r15)
  15af29:	je     15aba0 <pum_get_height@@Base+0x1a90>
  15af2f:	cmp    $0x50,%ebx
  15af32:	jne    15aba0 <pum_get_height@@Base+0x1a90>
  15af38:	mov    0x68(%rsp),%rsi
  15af3d:	mov    $0x1,%edx
  15af42:	mov    %r15,%rdi
  15af45:	callq  1597f0 <pum_get_height@@Base+0x6e0>
  15af4a:	test   %r13,%r13
  15af4d:	mov    %rax,0x210(%r14)
  15af54:	movb   $0x0,(%r15)
  15af58:	jne    15abb6 <pum_get_height@@Base+0x1aa6>
  15af5e:	movl   $0x0,0x48(%rsp)
  15af66:	cmpb   $0x2d,0x1b(%rbp)
  15af6a:	mov    0x40(%rsp),%rbp
  15af6f:	jne    15ac89 <pum_get_height@@Base+0x1b79>
  15af75:	mov    0x218(%r14),%esi
  15af7c:	test   %esi,%esi
  15af7e:	je     15a6f4 <pum_get_height@@Base+0x15e4>
  15af84:	movl   $0x1,0x21c(%r14)
  15af8f:	mov    0x40(%rsp),%rbp
  15af94:	jmpq   15a6f4 <pum_get_height@@Base+0x15e4>
  15af99:	nopl   0x0(%rax)
  15afa0:	movzbl 0x12(%rbp),%eax
  15afa4:	movl   $0xffffffff,0x28(%rsp)
  15afac:	test   %eax,%eax
  15afae:	jne    15a902 <pum_get_height@@Base+0x17f2>
  15afb4:	movq   $0x0,0x50(%rsp)
  15afbd:	jmpq   15a924 <pum_get_height@@Base+0x1814>
  15afc2:	nopw   0x0(%rax,%rax,1)
  15afc8:	movb   $0x0,0x20(%rsp)
  15afcd:	mov    0x8(%rbp),%rbp
  15afd1:	jmpq   15a7a8 <pum_get_height@@Base+0x1698>
  15afd6:	nopw   %cs:0x0(%rax,%rax,1)
  15afe0:	mov    0x68(%rsp),%rdi
  15afe5:	callq  159480 <pum_get_height@@Base+0x370>
  15afea:	mov    %rax,0x210(%r14)
  15aff1:	jmpq   15aba9 <pum_get_height@@Base+0x1a99>
  15aff6:	nopw   %cs:0x0(%rax,%rax,1)
  15b000:	mov    0x220(%r14),%r11d
  15b007:	test   %r11d,%r11d
  15b00a:	jne    15a978 <pum_get_height@@Base+0x1868>
  15b010:	mov    0xbc(%rsp),%eax
  15b017:	cmp    %eax,0x5c(%rsp)
  15b01b:	jge    15b049 <pum_get_height@@Base+0x1f39>
  15b01d:	mov    0x38(%rsp),%rdi
  15b022:	add    $0x1,%eax
  15b025:	movslq %eax,%rsi
  15b028:	callq  4f078 <_init@@Base+0x488>
  15b02d:	test   %rax,%rax
  15b030:	mov    %rax,0x38(%rsp)
  15b035:	je     15bdfb <pum_get_height@@Base+0x2ceb>
  15b03b:	mov    0xbc(%rsp),%eax
  15b042:	lea    0x1(%rax),%edi
  15b045:	mov    %edi,0x5c(%rsp)
  15b049:	mov    0x8(%rsp),%rsi
  15b04e:	mov    0x38(%rsp),%rdi
  15b053:	movslq %eax,%rdx
  15b056:	callq  11c750 <vim_strncpy@@Base>
  15b05b:	movzbl 0x16(%rbp),%eax
  15b05f:	test   %eax,%eax
  15b061:	jne    15a9fb <pum_get_height@@Base+0x18eb>
  15b067:	nopw   0x0(%rax,%rax,1)
  15b070:	movzbl 0x17(%rbp),%eax
  15b074:	xor    %r13d,%r13d
  15b077:	test   %eax,%eax
  15b079:	jne    15aa18 <pum_get_height@@Base+0x1908>
  15b07f:	movb   $0x0,0x20(%rsp)
  15b084:	jmpq   15aa76 <pum_get_height@@Base+0x1966>
  15b089:	mov    0x8(%rsp),%rax
  15b08e:	cmpb   $0xa,0x3ff(%rax)
  15b095:	je     15a759 <pum_get_height@@Base+0x1649>
  15b09b:	mov    0xc0(%rsp),%rax
  15b0a3:	test   %rax,%rax
  15b0a6:	je     15bbaa <pum_get_height@@Base+0x2a9a>
  15b0ac:	mov    0x8(%rsp),%rbx
  15b0b1:	lea    0x8(%rax),%rdi
  15b0b5:	and    $0xfffffffffffffff8,%rdi
  15b0b9:	mov    (%rbx),%rdx
  15b0bc:	mov    %rbx,%rsi
  15b0bf:	mov    %rdx,(%rax)
  15b0c2:	mov    0x3f8(%rbx),%rdx
  15b0c9:	mov    %rdx,0x3f8(%rax)
  15b0d0:	sub    %rdi,%rax
  15b0d3:	sub    %rax,%rsi
  15b0d6:	add    $0x400,%eax
  15b0db:	shr    $0x3,%eax
  15b0de:	mov    %eax,%ecx
  15b0e0:	rep movsq %ds:(%rsi),%es:(%rdi)
  15b0e3:	mov    %r12d,0x40(%rsp)
  15b0e8:	mov    %rbp,0x48(%rsp)
  15b0ed:	movslq 0xbc(%rsp),%r13
  15b0f5:	mov    0xc0(%rsp),%rax
  15b0fd:	mov    0x60(%rsp),%r12
  15b102:	mov    %r13,%rbx
  15b105:	jmp    15b180 <pum_get_height@@Base+0x2070>
  15b107:	nopw   0x0(%rax,%rax,1)
  15b110:	mov    0xc0(%rsp),%rbp
  15b118:	lea    0x0(%rbp,%r13,1),%rdi
  15b11d:	callq  4ed80 <_init@@Base+0x190>
  15b122:	add    %eax,%ebx
  15b124:	mov    %eax,0xbc(%rsp)
  15b12b:	movslq %ebx,%r13
  15b12e:	cmpb   $0xa,-0x1(%rbp,%r13,1)
  15b134:	je     15ba7b <pum_get_height@@Base+0x296b>
  15b13a:	mov    0xb8(%rsp),%eax
  15b141:	cmp    $0x1000,%eax
  15b146:	je     15b9f1 <pum_get_height@@Base+0x28e1>
  15b14c:	add    %eax,%eax
  15b14e:	mov    $0x1000,%edi
  15b153:	cmp    $0x1000,%eax
  15b158:	cmovg  %edi,%eax
  15b15b:	mov    %rbp,%rdi
  15b15e:	mov    %eax,0xb8(%rsp)
  15b165:	add    %eax,%eax
  15b167:	movslq %eax,%rsi
  15b16a:	callq  4f078 <_init@@Base+0x488>
  15b16f:	test   %rax,%rax
  15b172:	mov    %rax,0xc0(%rsp)
  15b17a:	je     15b9e7 <pum_get_height@@Base+0x28d7>
  15b180:	mov    0xb8(%rsp),%esi
  15b187:	lea    (%rax,%r13,1),%rdi
  15b18b:	mov    %r12,%rdx
  15b18e:	sub    %ebx,%esi
  15b190:	callq  4eec0 <_init@@Base+0x2d0>
  15b195:	test   %rax,%rax
  15b198:	jne    15b110 <pum_get_height@@Base+0x2000>
  15b19e:	mov    0xc0(%rsp),%rax
  15b1a6:	mov    0x40(%rsp),%r12d
  15b1ab:	mov    0x48(%rsp),%rbp
  15b1b0:	mov    %rax,0x8(%rsp)
  15b1b5:	mov    %ebx,0xbc(%rsp)
  15b1bc:	jmpq   15a755 <pum_get_height@@Base+0x1645>
  15b1c1:	movb   $0x0,(%rax)
  15b1c4:	jmpq   15a76f <pum_get_height@@Base+0x165f>
  15b1c9:	mov    0x80(%rsp),%rax
  15b1d1:	test   %rax,%rax
  15b1d4:	je     15bd46 <pum_get_height@@Base+0x2c36>
  15b1da:	mov    (%rax),%eax
  15b1dc:	cmp    $0x2,%eax
  15b1df:	je     15bac0 <pum_get_height@@Base+0x29b0>
  15b1e5:	cmp    $0x5,%eax
  15b1e8:	je     15bbe1 <pum_get_height@@Base+0x2ad1>
  15b1ee:	mov    0xbc(%rsp),%ebx
  15b1f5:	jmpq   15a755 <pum_get_height@@Base+0x1645>
  15b1fa:	test   %rbp,%rbp
  15b1fd:	je     15ac1b <pum_get_height@@Base+0x1b0b>
  15b203:	test   %al,%al
  15b205:	je     15ac1b <pum_get_height@@Base+0x1b0b>
  15b20b:	cmpb   $0x0,(%r15)
  15b20f:	je     15bf87 <pum_get_height@@Base+0x2e77>
  15b215:	lea    0x1f8(%r14),%rsi
  15b21c:	xor    %edx,%edx
  15b21e:	mov    %r15,%rdi
  15b221:	callq  1597f0 <pum_get_height@@Base+0x6e0>
  15b226:	test   %rax,%rax
  15b229:	mov    %rax,0x200(%r14)
  15b230:	jne    15ac1b <pum_get_height@@Base+0x1b0b>
  15b236:	mov    0x8(%r14),%esi
  15b23a:	mov    %r14,%rdi
  15b23d:	mov    $0xffffffff,%ebx
  15b242:	callq  1592e0 <pum_get_height@@Base+0x1d0>
  15b247:	mov    0x8(%r14),%eax
  15b24b:	subl   $0x1,0x4(%r14)
  15b250:	test   %eax,%eax
  15b252:	jle    15b25a <pum_get_height@@Base+0x214a>
  15b254:	add    %ebx,%eax
  15b256:	mov    %eax,0x8(%r14)
  15b25a:	cmpq   $0x0,0x60(%rsp)
  15b260:	je     15b26c <pum_get_height@@Base+0x215c>
  15b262:	mov    0x60(%rsp),%rdi
  15b267:	callq  4ed38 <_init@@Base+0x148>
  15b26c:	mov    %r15,%rdi
  15b26f:	callq  11c7f0 <vim_free@@Base>
  15b274:	mov    0x38(%rsp),%rdi
  15b279:	callq  11c7f0 <vim_free@@Base>
  15b27e:	mov    0x18(%rsp),%rdi
  15b283:	callq  11c7f0 <vim_free@@Base>
  15b288:	mov    0xc0(%rsp),%rdi
  15b290:	callq  11c7f0 <vim_free@@Base>
  15b295:	mov    0x90(%rsp),%rsi
  15b29d:	mov    %r14,%rdi
  15b2a0:	callq  159e10 <pum_get_height@@Base+0xd00>
  15b2a5:	mov    %ebx,%eax
  15b2a7:	mov    0x188(%rsp),%rbx
  15b2af:	xor    %fs:0x28,%rbx
  15b2b8:	jne    15bf6c <pum_get_height@@Base+0x2e5c>
  15b2be:	add    $0x198,%rsp
  15b2c5:	pop    %rbx
  15b2c6:	pop    %rbp
  15b2c7:	pop    %r12
  15b2c9:	pop    %r13
  15b2cb:	pop    %r14
  15b2cd:	pop    %r15
  15b2cf:	retq   
  15b2d0:	movl   $0x1,0x218(%r14)
  15b2db:	movl   $0x0,0x21c(%r14)
  15b2e6:	cmpb   $0x2d,0x1b(%rbp)
  15b2ea:	je     15af84 <pum_get_height@@Base+0x1e74>
  15b2f0:	mov    0x40(%rsp),%rbp
  15b2f5:	jmpq   15ac89 <pum_get_height@@Base+0x1b79>
  15b2fa:	movslq 0x8(%r14),%rax
  15b2fe:	mov    %rax,%rsi
  15b301:	lea    (%rax,%rax,2),%rax
  15b305:	shl    $0x4,%rax
  15b309:	mov    0x18(%r14,%rax,1),%rbp
  15b30e:	test   %rbp,%rbp
  15b311:	je     15b23a <pum_get_height@@Base+0x212a>
  15b317:	mov    0x38(%rsp),%rax
  15b31c:	cmpb   $0x0,(%rax)
  15b31f:	jne    15b3b6 <pum_get_height@@Base+0x22a6>
  15b325:	cmpl   $0xffffffff,0x20(%rbp)
  15b329:	je     15b433 <pum_get_height@@Base+0x2323>
  15b32f:	mov    0x10(%rsp),%r13d
  15b334:	mov    %r13d,%edi
  15b337:	callq  5f290 <vim_isprintc@@Base>
  15b33c:	test   %eax,%eax
  15b33e:	je     15b34a <pum_get_height@@Base+0x223a>
  15b340:	cmpb   $0x0,0x3a(%rbp)
  15b344:	jne    15b34a <pum_get_height@@Base+0x223a>
  15b346:	mov    %r13b,0x3a(%rbp)
  15b34a:	cmpq   $0x0,0x10(%rbp)
  15b34f:	jne    15b35a <pum_get_height@@Base+0x224a>
  15b351:	mov    0x50(%rsp),%rax
  15b356:	mov    %rax,0x10(%rbp)
  15b35a:	mov    0x1c(%rbp),%r8d
  15b35e:	test   %r8d,%r8d
  15b361:	jne    15b367 <pum_get_height@@Base+0x2257>
  15b363:	mov    %r12d,0x1c(%rbp)
  15b367:	movzbl 0x20(%rsp),%eax
  15b36c:	mov    %al,0x38(%rbp)
  15b36f:	mov    0x18(%rbp),%eax
  15b372:	test   %eax,%eax
  15b374:	jne    15b393 <pum_get_height@@Base+0x2283>
  15b376:	cmpb   $0x0,(%r15)
  15b37a:	mov    0x200(%r14),%rsi
  15b381:	jne    15bb75 <pum_get_height@@Base+0x2a65>
  15b387:	test   %rsi,%rsi
  15b38a:	je     15bd09 <pum_get_height@@Base+0x2bf9>
  15b390:	mov    %eax,0x18(%rbp)
  15b393:	cmp    $0x5a,%ebx
  15b396:	je     15bb5a <pum_get_height@@Base+0x2a4a>
  15b39c:	callq  119f10 <line_breakcheck@@Base>
  15b3a1:	mov    0x40(%rsp),%rbp
  15b3a6:	jmpq   15a6f4 <pum_get_height@@Base+0x15e4>
  15b3ab:	mov    $0x1,%r12d
  15b3b1:	jmpq   15aa71 <pum_get_height@@Base+0x1961>
  15b3b6:	mov    0x21c(%r14),%r9d
  15b3bd:	test   %r9d,%r9d
  15b3c0:	jne    15b325 <pum_get_height@@Base+0x2215>
  15b3c6:	mov    0x30(%rbp),%rdi
  15b3ca:	callq  4ed80 <_init@@Base+0x190>
  15b3cf:	mov    0x38(%rsp),%rdi
  15b3d4:	mov    %rax,%r13
  15b3d7:	callq  4ed80 <_init@@Base+0x190>
  15b3dc:	lea    0x2(%rax,%r13,1),%edi
  15b3e1:	callq  121d10 <alloc@@Base>
  15b3e6:	test   %rax,%rax
  15b3e9:	je     15b236 <pum_get_height@@Base+0x2126>
  15b3ef:	mov    0x30(%rbp),%rsi
  15b3f3:	mov    %rax,%rdi
  15b3f6:	mov    %rax,0x68(%rsp)
  15b3fb:	movslq %r13d,%r13
  15b3fe:	callq  4eca0 <_init@@Base+0xb0>
  15b403:	mov    0x30(%rbp),%rdi
  15b407:	callq  11c7f0 <vim_free@@Base>
  15b40c:	mov    0x68(%rsp),%rdx
  15b411:	mov    0x38(%rsp),%rsi
  15b416:	mov    %rdx,0x30(%rbp)
  15b41a:	add    %r13,%rdx
  15b41d:	lea    0x1(%rdx),%rdi
  15b421:	movb   $0xa,(%rdx)
  15b424:	callq  4eca0 <_init@@Base+0xb0>
  15b429:	cmpl   $0xffffffff,0x20(%rbp)
  15b42d:	jne    15b32f <pum_get_height@@Base+0x221f>
  15b433:	mov    0x28(%rsp),%eax
  15b437:	mov    %eax,0x20(%rbp)
  15b43a:	jmpq   15b32f <pum_get_height@@Base+0x221f>
  15b43f:	nop
  15b440:	mov    0x8(%rsp),%rax
  15b445:	cmp    %r13,%r14
  15b448:	mov    0x28(%rsp),%r12
  15b44d:	movb   $0x5e,(%rax)
  15b450:	jbe    15b560 <pum_get_height@@Base+0x2450>
  15b456:	lea    0x1(%r13),%rax
  15b45a:	xor    %ebp,%ebp
  15b45c:	mov    %rax,0x20(%rsp)
  15b461:	jmp    15b48a <pum_get_height@@Base+0x237a>
  15b463:	nopl   0x0(%rax,%rax,1)
  15b468:	cmp    %r15,%r14
  15b46b:	jbe    15b49f <pum_get_height@@Base+0x238f>
  15b46d:	add    $0x2,%r13
  15b471:	movzbl (%r15),%eax
  15b475:	test   %al,%al
  15b477:	je     15b481 <pum_get_height@@Base+0x2371>
  15b479:	mov    %al,(%r12)
  15b47d:	add    $0x1,%r12
  15b481:	cmp    %r13,%r14
  15b484:	jbe    15b560 <pum_get_height@@Base+0x2450>
  15b48a:	movzbl 0x0(%r13),%esi
  15b48f:	lea    0x1(%r13),%r15
  15b493:	cmp    $0x25,%sil
  15b497:	je     15b4d0 <pum_get_height@@Base+0x23c0>
  15b499:	cmp    $0x5c,%sil
  15b49d:	je     15b468 <pum_get_height@@Base+0x2358>
  15b49f:	lea    0xd4639(%rip),%rdi        # 22fadf <_IO_stdin_used@@Base+0x1951f>
  15b4a6:	callq  11c810 <vim_strchr@@Base>
  15b4ab:	test   %rax,%rax
  15b4ae:	je     15b680 <pum_get_height@@Base+0x2570>
  15b4b4:	mov    %r15,%rax
  15b4b7:	movb   $0x5c,(%r12)
  15b4bc:	mov    %r13,%r15
  15b4bf:	add    $0x1,%r12
  15b4c3:	mov    %rax,%r13
  15b4c6:	jmp    15b471 <pum_get_height@@Base+0x2361>
  15b4c8:	nopl   0x0(%rax,%rax,1)
  15b4d0:	movzbl 0x1(%r13),%esi
  15b4d5:	lea    0x3247b4(%rip),%rdx        # 47fc90 <_IO_stdin_used@@Base+0x2696d0>
  15b4dc:	mov    $0x66,%ecx
  15b4e1:	xor    %eax,%eax
  15b4e3:	jmp    15b4ef <pum_get_height@@Base+0x23df>
  15b4e5:	nopl   (%rax)
  15b4e8:	movzbl (%rdx),%ecx
  15b4eb:	add    $0x10,%rdx
  15b4ef:	cmp    %cl,%sil
  15b4f2:	je     15b5e0 <pum_get_height@@Base+0x24d0>
  15b4f8:	add    $0x1,%eax
  15b4fb:	cmp    $0xa,%eax
  15b4fe:	jne    15b4e8 <pum_get_height@@Base+0x23d8>
  15b500:	cmp    $0x2a,%sil
  15b504:	jne    15b690 <pum_get_height@@Base+0x2580>
  15b50a:	movzbl 0x2(%r13),%edx
  15b50f:	lea    0x2(%r13),%rax
  15b513:	cmp    $0x5b,%dl
  15b516:	je     15b7b5 <pum_get_height@@Base+0x26a5>
  15b51c:	cmp    $0x5c,%dl
  15b51f:	jne    15bc60 <pum_get_height@@Base+0x2b50>
  15b525:	cmp    %rax,%r14
  15b528:	movb   $0x5c,(%r12)
  15b52d:	lea    0x1(%r12),%rdx
  15b532:	jbe    15b547 <pum_get_height@@Base+0x2437>
  15b534:	movzbl 0x3(%r13),%ecx
  15b539:	lea    0x2(%r12),%rdx
  15b53e:	lea    0x3(%r13),%rax
  15b542:	mov    %cl,0x1(%r12)
  15b547:	lea    0x1(%rax),%r13
  15b54b:	movb   $0x5c,(%rdx)
  15b54e:	lea    0x2(%rdx),%r12
  15b552:	movb   $0x2b,0x1(%rdx)
  15b556:	cmp    %r13,%r14
  15b559:	ja     15b48a <pum_get_height@@Base+0x237a>
  15b55f:	nop
  15b560:	mov    0x8(%rsp),%rdi
  15b565:	movb   $0x24,(%r12)
  15b56a:	mov    $0x3,%esi
  15b56f:	movb   $0x0,0x1(%r12)
  15b575:	callq  17fc50 <vim_regcomp@@Base>
  15b57a:	test   %rax,%rax
  15b57d:	mov    %rax,(%rbx)
  15b580:	je     15bb4b <pum_get_height@@Base+0x2a3b>
  15b586:	mov    %r14,%rdi
  15b589:	mov    %rbx,%rbp
  15b58c:	callq  10fff0 <skip_to_option_part@@Base>
  15b591:	cmpb   $0x0,(%rax)
  15b594:	mov    %rax,%r13
  15b597:	jne    15ae20 <pum_get_height@@Base+0x1d10>
  15b59d:	mov    0x30(%rsp),%r15
  15b5a2:	mov    0x40(%rsp),%r14
  15b5a7:	cmpq   $0x0,0xc8(%rsp)
  15b5b0:	jne    15b724 <pum_get_height@@Base+0x2614>
  15b5b6:	lea    0xcf9f3(%rip),%rsi        # 22afb0 <_IO_stdin_used@@Base+0x149f0>
  15b5bd:	xor    %edi,%edi
  15b5bf:	mov    $0x5,%edx
  15b5c4:	callq  4ed78 <_init@@Base+0x188>
  15b5c9:	mov    %rax,%rdi
  15b5cc:	callq  10d330 <emsg@@Base>
  15b5d1:	jmpq   15b724 <pum_get_height@@Base+0x2614>
  15b5d6:	nopw   %cs:0x0(%rax,%rax,1)
  15b5e0:	movslq %eax,%r15
  15b5e3:	cmpb   $0x0,0x10(%rbx,%r15,1)
  15b5e9:	jne    15b947 <pum_get_height@@Base+0x2837>
  15b5ef:	test   %eax,%eax
  15b5f1:	je     15b5fc <pum_get_height@@Base+0x24ec>
  15b5f3:	cmp    $0x5,%eax
  15b5f6:	jle    15b6c0 <pum_get_height@@Base+0x25b0>
  15b5fc:	cmp    $0x6,%eax
  15b5ff:	je     15b850 <pum_get_height@@Base+0x2740>
  15b605:	add    $0x1,%ebp
  15b608:	lea    0x2(%r12),%rax
  15b60d:	mov    %bpl,0x10(%rbx,%r15,1)
  15b612:	movb   $0x5c,(%r12)
  15b617:	movb   $0x28,0x1(%r12)
  15b61d:	cmpb   $0x66,0x1(%r13)
  15b622:	je     15b770 <pum_get_height@@Base+0x2660>
  15b628:	lea    0x324651(%rip),%rdi        # 47fc80 <_IO_stdin_used@@Base+0x2696c0>
  15b62f:	shl    $0x4,%r15
  15b633:	mov    0x8(%rdi,%r15,1),%rcx
  15b638:	lea    0x1(%rcx),%rdx
  15b63c:	movzbl (%rcx),%ecx
  15b63f:	test   %cl,%cl
  15b641:	mov    %cl,0x2(%r12)
  15b646:	je     15b662 <pum_get_height@@Base+0x2552>
  15b648:	nopl   0x0(%rax,%rax,1)
  15b650:	add    $0x1,%rdx
  15b654:	movzbl -0x1(%rdx),%ecx
  15b658:	add    $0x1,%rax
  15b65c:	test   %cl,%cl
  15b65e:	mov    %cl,(%rax)
  15b660:	jne    15b650 <pum_get_height@@Base+0x2540>
  15b662:	movb   $0x5c,(%rax)
  15b665:	lea    0x2(%rax),%r12
  15b669:	movb   $0x29,0x1(%rax)
  15b66d:	add    $0x2,%r13
  15b671:	jmpq   15b481 <pum_get_height@@Base+0x2371>
  15b676:	nopw   %cs:0x0(%rax,%rax,1)
  15b680:	mov    %r15,%rax
  15b683:	mov    %r13,%r15
  15b686:	mov    %rax,%r13
  15b689:	jmpq   15b471 <pum_get_height@@Base+0x2361>
  15b68e:	xchg   %ax,%ax
  15b690:	lea    0xcf729(%rip),%rdi        # 22adc0 <_IO_stdin_used@@Base+0x14800>
  15b697:	callq  11c810 <vim_strchr@@Base>
  15b69c:	test   %rax,%rax
  15b69f:	movzbl 0x1(%r13),%eax
  15b6a4:	je     15b870 <pum_get_height@@Base+0x2760>
  15b6aa:	mov    %al,(%r12)
  15b6ae:	add    $0x2,%r13
  15b6b2:	add    $0x1,%r12
  15b6b6:	jmpq   15b481 <pum_get_height@@Base+0x2371>
  15b6bb:	nopl   0x0(%rax,%rax,1)
  15b6c0:	movzbl 0x1a(%rbx),%esi
  15b6c4:	lea    0xcf6ef(%rip),%rdi        # 22adba <_IO_stdin_used@@Base+0x147fa>
  15b6cb:	callq  11c810 <vim_strchr@@Base>
  15b6d0:	test   %rax,%rax
  15b6d3:	je     15b605 <pum_get_height@@Base+0x24f5>
  15b6d9:	movzbl 0x1(%r13),%ebx
  15b6de:	mov    0x30(%rsp),%r15
  15b6e3:	lea    0xcf7f6(%rip),%rsi        # 22aee0 <_IO_stdin_used@@Base+0x14920>
  15b6ea:	mov    0x40(%rsp),%r14
  15b6ef:	mov    $0x5,%edx
  15b6f4:	xor    %edi,%edi
  15b6f6:	callq  4ed78 <_init@@Base+0x188>
  15b6fb:	mov    %ebx,%edx
  15b6fd:	mov    0x48(%rsp),%rbx
  15b702:	mov    %rax,%rsi
  15b705:	xor    %eax,%eax
  15b707:	mov    %rbx,%rdi
  15b70a:	callq  4f1a8 <_init@@Base+0x5b8>
  15b70f:	mov    %rbx,%rdi
  15b712:	callq  10d330 <emsg@@Base>
  15b717:	lea    0xc8(%rsp),%rdi
  15b71f:	callq  1597b0 <pum_get_height@@Base+0x6a0>
  15b724:	mov    0x8(%rsp),%rdi
  15b729:	callq  11c7f0 <vim_free@@Base>
  15b72e:	mov    0x48(%rsp),%rdi
  15b733:	callq  11c7f0 <vim_free@@Base>
  15b738:	mov    0xc8(%rsp),%rax
  15b740:	test   %rax,%rax
  15b743:	mov    %rax,0x349bfe(%rip)        # 4a5348 <current_funccal@@Base+0x3a40>
  15b74a:	je     15b236 <pum_get_height@@Base+0x2126>
  15b750:	mov    0x10(%rsp),%rdi
  15b755:	callq  11f220 <vim_strsave@@Base>
  15b75a:	mov    %rax,0x349bef(%rip)        # 4a5350 <current_funccal@@Base+0x3a48>
  15b761:	jmpq   15a643 <pum_get_height@@Base+0x1533>
  15b766:	nopw   %cs:0x0(%rax,%rax,1)
  15b770:	movzbl 0x2(%r13),%edx
  15b775:	test   %dl,%dl
  15b777:	je     15b628 <pum_get_height@@Base+0x2518>
  15b77d:	cmp    $0x5c,%dl
  15b780:	je     15b8d4 <pum_get_height@@Base+0x27c4>
  15b786:	cmp    $0x25,%dl
  15b789:	je     15b8d4 <pum_get_height@@Base+0x27c4>
  15b78f:	movabs $0x7d2c312d7b5c2e,%rdi
  15b799:	add    $0x2,%r13
  15b79d:	mov    %rdi,(%rax)
  15b7a0:	lea    0x9(%r12),%rax
  15b7a5:	movb   $0x5c,(%rax)
  15b7a8:	movb   $0x29,0x1(%rax)
  15b7ac:	lea    0x2(%rax),%r12
  15b7b0:	jmpq   15b481 <pum_get_height@@Base+0x2371>
  15b7b5:	movb   $0x5b,(%r12)
  15b7ba:	cmpb   $0x5e,0x3(%r13)
  15b7bf:	lea    0x1(%r12),%rdx
  15b7c4:	je     15b8f7 <pum_get_height@@Base+0x27e7>
  15b7ca:	cmp    %rax,%r14
  15b7cd:	jbe    15b547 <pum_get_height@@Base+0x2437>
  15b7d3:	movzbl 0x1(%rax),%esi
  15b7d7:	lea    0x1(%rax),%rcx
  15b7db:	cmp    %rcx,%r14
  15b7de:	mov    %sil,(%rdx)
  15b7e1:	jbe    15be30 <pum_get_height@@Base+0x2d20>
  15b7e7:	movzbl 0x2(%rax),%ecx
  15b7eb:	add    $0x2,%rdx
  15b7ef:	add    $0x2,%rax
  15b7f3:	mov    %cl,-0x1(%rdx)
  15b7f6:	cmp    $0x5d,%cl
  15b7f9:	jne    15b813 <pum_get_height@@Base+0x2703>
  15b7fb:	jmp    15b818 <pum_get_height@@Base+0x2708>
  15b7fd:	nopl   (%rax)
  15b800:	add    $0x1,%rax
  15b804:	movzbl (%rax),%ecx
  15b807:	add    $0x1,%rdx
  15b80b:	cmp    $0x5d,%cl
  15b80e:	mov    %cl,-0x1(%rdx)
  15b811:	je     15b818 <pum_get_height@@Base+0x2708>
  15b813:	cmp    %rax,%r14
  15b816:	ja     15b800 <pum_get_height@@Base+0x26f0>
  15b818:	cmp    %rax,%r14
  15b81b:	jne    15b547 <pum_get_height@@Base+0x2437>
  15b821:	lea    0xcf6e0(%rip),%rsi        # 22af08 <_IO_stdin_used@@Base+0x14948>
  15b828:	xor    %edi,%edi
  15b82a:	mov    $0x5,%edx
  15b82f:	mov    0x30(%rsp),%r15
  15b834:	mov    0x40(%rsp),%r14
  15b839:	callq  4ed78 <_init@@Base+0x188>
  15b83e:	mov    %rax,%rdi
  15b841:	callq  10d330 <emsg@@Base>
  15b846:	jmpq   15b717 <pum_get_height@@Base+0x2607>
  15b84b:	nopl   0x0(%rax,%rax,1)
  15b850:	movzbl 0x1a(%rbx),%esi
  15b854:	lea    0xcf576(%rip),%rdi        # 22add1 <_IO_stdin_used@@Base+0x14811>
  15b85b:	callq  11c810 <vim_strchr@@Base>
  15b860:	test   %rax,%rax
  15b863:	jne    15b605 <pum_get_height@@Base+0x24f5>
  15b869:	jmpq   15b6d9 <pum_get_height@@Base+0x25c9>
  15b86e:	xchg   %ax,%ax
  15b870:	cmp    $0x23,%al
  15b872:	je     15b935 <pum_get_height@@Base+0x2825>
  15b878:	cmp    $0x3e,%al
  15b87a:	je     15b9b8 <pum_get_height@@Base+0x28a8>
  15b880:	cmp    0x20(%rsp),%r15
  15b885:	jne    15bf34 <pum_get_height@@Base+0x2e24>
  15b88b:	lea    0xbb7fb(%rip),%rdi        # 21708d <_IO_stdin_used@@Base+0xacd>
  15b892:	movzbl %al,%esi
  15b895:	callq  11c810 <vim_strchr@@Base>
  15b89a:	test   %rax,%rax
  15b89d:	je     15b8ab <pum_get_height@@Base+0x279b>
  15b89f:	movzbl 0x1(%r13),%eax
  15b8a4:	lea    0x2(%r13),%r15
  15b8a8:	mov    %al,0x1b(%rbx)
  15b8ab:	movzbl (%r15),%esi
  15b8af:	lea    0xcf512(%rip),%rdi        # 22adc8 <_IO_stdin_used@@Base+0x14808>
  15b8b6:	callq  11c810 <vim_strchr@@Base>
  15b8bb:	test   %rax,%rax
  15b8be:	je     15bf11 <pum_get_height@@Base+0x2e01>
  15b8c4:	movzbl (%r15),%eax
  15b8c8:	lea    0x1(%r15),%r13
  15b8cc:	mov    %al,0x1a(%rbx)
  15b8cf:	jmpq   15b481 <pum_get_height@@Base+0x2371>
  15b8d4:	movl   $0x2b5c665c,(%rax)
  15b8da:	movb   $0x0,0x4(%rax)
  15b8de:	lea    0x6(%r12),%rax
  15b8e3:	add    $0x2,%r13
  15b8e7:	movb   $0x5c,(%rax)
  15b8ea:	movb   $0x29,0x1(%rax)
  15b8ee:	lea    0x2(%rax),%r12
  15b8f2:	jmpq   15b481 <pum_get_height@@Base+0x2371>
  15b8f7:	lea    0x2(%r12),%rdx
  15b8fc:	lea    0x3(%r13),%rax
  15b900:	movb   $0x5e,0x1(%r12)
  15b906:	jmpq   15b7ca <pum_get_height@@Base+0x26ba>
  15b90b:	mov    %rax,0xc8(%rsp)
  15b913:	movzbl 0x0(%r13),%eax
  15b918:	test   %al,%al
  15b91a:	jne    15ae56 <pum_get_height@@Base+0x1d46>
  15b920:	mov    0x8(%rsp),%rax
  15b925:	mov    0x28(%rsp),%r12
  15b92a:	mov    %r13,%r14
  15b92d:	movb   $0x5e,(%rax)
  15b930:	jmpq   15b560 <pum_get_height@@Base+0x2450>
  15b935:	movb   $0x2a,(%r12)
  15b93a:	add    $0x2,%r13
  15b93e:	add    $0x1,%r12
  15b942:	jmpq   15b481 <pum_get_height@@Base+0x2371>
  15b947:	mov    %sil,0x20(%rsp)
  15b94c:	lea    0xcf565(%rip),%rsi        # 22aeb8 <_IO_stdin_used@@Base+0x148f8>
  15b953:	mov    $0x5,%edx
  15b958:	xor    %edi,%edi
  15b95a:	mov    0x30(%rsp),%r15
  15b95f:	mov    0x40(%rsp),%r14
  15b964:	callq  4ed78 <_init@@Base+0x188>
  15b969:	movzbl 0x20(%rsp),%edx
  15b96e:	jmpq   15b6fd <pum_get_height@@Base+0x25ed>
  15b973:	mov    %r12,%rsi
  15b976:	mov    %r14,%rdi
  15b979:	callq  1596b0 <pum_get_height@@Base+0x5a0>
  15b97e:	mov    0x10(%rsp),%rax
  15b983:	cmp    %rax,0x352f36(%rip)        # 4ae8c0 <p_efm@@Base>
  15b98a:	mov    0x8(%r14),%eax
  15b98e:	jne    15b99f <pum_get_height@@Base+0x288f>
  15b990:	cmpq   $0x0,0x80(%rsp)
  15b999:	je     15be0e <pum_get_height@@Base+0x2cfe>
  15b99f:	test   %ebp,%ebp
  15b9a1:	movq   $0x0,0x90(%rsp)
  15b9ad:	jne    15a5c8 <pum_get_height@@Base+0x14b8>
  15b9b3:	jmpq   15a5bf <pum_get_height@@Base+0x14af>
  15b9b8:	movl   $0x1,0x1c(%rbx)
  15b9bf:	add    $0x2,%r13
  15b9c3:	jmpq   15b481 <pum_get_height@@Base+0x2371>
  15b9c8:	mov    0x210(%r14),%rdx
  15b9cf:	test   %rdx,%rdx
  15b9d2:	je     15b9e0 <pum_get_height@@Base+0x28d0>
  15b9d4:	mov    0x48(%rsp),%ecx
  15b9d8:	test   %ecx,%ecx
  15b9da:	jne    15aca7 <pum_get_height@@Base+0x1b97>
  15b9e0:	xor    %edx,%edx
  15b9e2:	jmpq   15aca7 <pum_get_height@@Base+0x1b97>
  15b9e7:	mov    $0xffffffff,%ebx
  15b9ec:	jmpq   15b262 <pum_get_height@@Base+0x2152>
  15b9f1:	mov    0x353638(%rip),%r13        # 4af030 <IObuff@@Base>
  15b9f8:	mov    0x48(%rsp),%rbp
  15b9fd:	mov    %ebx,0x8(%rsp)
  15ba01:	mov    0x40(%rsp),%r12d
  15ba06:	mov    0x60(%rsp),%rbx
  15ba0b:	mov    %r13,%rax
  15ba0e:	mov    %rbp,%r13
  15ba11:	mov    %rax,%rbp
  15ba14:	jmp    15ba3f <pum_get_height@@Base+0x292f>
  15ba16:	nopw   %cs:0x0(%rax,%rax,1)
  15ba20:	mov    0x353609(%rip),%rbp        # 4af030 <IObuff@@Base>
  15ba27:	mov    %rbp,%rdi
  15ba2a:	callq  4ed80 <_init@@Base+0x190>
  15ba2f:	cmp    $0x3ff,%eax
  15ba34:	jle    15ba54 <pum_get_height@@Base+0x2944>
  15ba36:	cmpb   $0xa,0x400(%rbp)
  15ba3d:	je     15ba54 <pum_get_height@@Base+0x2944>
  15ba3f:	mov    %rbx,%rdx
  15ba42:	mov    $0x401,%esi
  15ba47:	mov    %rbp,%rdi
  15ba4a:	callq  4eec0 <_init@@Base+0x2d0>
  15ba4f:	test   %rax,%rax
  15ba52:	jne    15ba20 <pum_get_height@@Base+0x2910>
  15ba54:	mov    0xc0(%rsp),%rax
  15ba5c:	mov    0x8(%rsp),%ebx
  15ba60:	mov    %r13,%rbp
  15ba63:	mov    %rax,0x8(%rsp)
  15ba68:	jmpq   15b1b5 <pum_get_height@@Base+0x20a5>
  15ba6d:	movq   $0x0,0x60(%rsp)
  15ba76:	jmpq   15a55f <pum_get_height@@Base+0x144f>
  15ba7b:	mov    %rbp,0x8(%rsp)
  15ba80:	mov    0x40(%rsp),%r12d
  15ba85:	mov    0x48(%rsp),%rbp
  15ba8a:	jmpq   15b1b5 <pum_get_height@@Base+0x20a5>
  15ba8f:	movl   $0x0,0x21c(%r14)
  15ba9a:	movl   $0x0,0x218(%r14)
  15baa5:	mov    0x40(%rsp),%rbp
  15baaa:	movq   $0x0,0x50(%rsp)
  15bab3:	movl   $0x0,0x48(%rsp)
  15babb:	jmpq   15ac89 <pum_get_height@@Base+0x1b79>
  15bac0:	mov    0x88(%rsp),%rax
  15bac8:	cmpb   $0x0,(%rax)
  15bacb:	je     15ad0d <pum_get_height@@Base+0x1bfd>
  15bad1:	mov    0x88(%rsp),%rbx
  15bad9:	mov    $0xa,%esi
  15bade:	mov    %rbx,%rdi
  15bae1:	callq  11c810 <vim_strchr@@Base>
  15bae6:	test   %rax,%rax
  15bae9:	je     15bec4 <pum_get_height@@Base+0x2db4>
  15baef:	sub    %rbx,%rax
  15baf2:	lea    0x1(%rax),%ebx
  15baf5:	cmp    $0x3ff,%ebx
  15bafb:	jg     15be48 <pum_get_height@@Base+0x2d38>
  15bb01:	mov    0x353528(%rip),%rax        # 4af030 <IObuff@@Base>
  15bb08:	mov    %ebx,0xbc(%rsp)
  15bb0f:	mov    %rax,0x8(%rsp)
  15bb14:	mov    %ebx,%eax
  15bb16:	mov    0x88(%rsp),%r13
  15bb1e:	mov    0x8(%rsp),%rdi
  15bb23:	movslq %eax,%rdx
  15bb26:	movslq %ebx,%rbx
  15bb29:	mov    %r13,%rsi
  15bb2c:	callq  11c750 <vim_strncpy@@Base>
  15bb31:	mov    %r13,%rax
  15bb34:	add    %rbx,%rax
  15bb37:	mov    0xbc(%rsp),%ebx
  15bb3e:	mov    %rax,0x88(%rsp)
  15bb46:	jmpq   15a755 <pum_get_height@@Base+0x1645>
  15bb4b:	mov    0x30(%rsp),%r15
  15bb50:	mov    0x40(%rsp),%r14
  15bb55:	jmpq   15b717 <pum_get_height@@Base+0x2607>
  15bb5a:	movl   $0x0,0x21c(%r14)
  15bb65:	movl   $0x0,0x218(%r14)
  15bb70:	jmpq   15b39c <pum_get_height@@Base+0x228c>
  15bb75:	mov    %r15,%rdx
  15bb78:	mov    %r14,%rdi
  15bb7b:	callq  15a0b0 <pum_get_height@@Base+0xfa0>
  15bb80:	mov    %eax,0x18(%rbp)
  15bb83:	jmpq   15b393 <pum_get_height@@Base+0x2283>
  15bb88:	mov    0x80(%rsp),%rax
  15bb90:	movq   $0x0,0x78(%rsp)
  15bb99:	mov    0x8(%rax),%rax
  15bb9d:	mov    %rax,0x88(%rsp)
  15bba5:	jmpq   15a6a0 <pum_get_height@@Base+0x1590>
  15bbaa:	mov    $0x800,%edi
  15bbaf:	movl   $0x800,0xb8(%rsp)
  15bbba:	callq  121d10 <alloc@@Base>
  15bbbf:	test   %rax,%rax
  15bbc2:	mov    %rax,0xc0(%rsp)
  15bbca:	je     15b9e7 <pum_get_height@@Base+0x28d7>
  15bbd0:	mov    0x353459(%rip),%rbx        # 4af030 <IObuff@@Base>
  15bbd7:	mov    %rbx,0x8(%rsp)
  15bbdc:	jmpq   15b0ac <pum_get_height@@Base+0x1f9c>
  15bbe1:	cmpq   $0x0,0x78(%rsp)
  15bbe7:	je     15ad0d <pum_get_height@@Base+0x1bfd>
  15bbed:	mov    0x78(%rsp),%rax
  15bbf2:	jmp    15bc04 <pum_get_height@@Base+0x2af4>
  15bbf4:	nopl   0x0(%rax)
  15bbf8:	mov    (%rax),%rax
  15bbfb:	test   %rax,%rax
  15bbfe:	je     15ad0d <pum_get_height@@Base+0x1bfd>
  15bc04:	cmpl   $0x2,0x10(%rax)
  15bc08:	jne    15bbf8 <pum_get_height@@Base+0x2ae8>
  15bc0a:	mov    0x18(%rax),%rbx
  15bc0e:	test   %rbx,%rbx
  15bc11:	je     15bbf8 <pum_get_height@@Base+0x2ae8>
  15bc13:	mov    %rbx,%rdi
  15bc16:	mov    %rax,0x78(%rsp)
  15bc1b:	callq  4ed80 <_init@@Base+0x190>
  15bc20:	cmp    $0x3ff,%eax
  15bc25:	movslq %eax,%rdx
  15bc28:	jg     15be81 <pum_get_height@@Base+0x2d71>
  15bc2e:	mov    0x3533fb(%rip),%rdi        # 4af030 <IObuff@@Base>
  15bc35:	mov    %eax,0xbc(%rsp)
  15bc3c:	mov    %rdi,0x8(%rsp)
  15bc41:	mov    0x8(%rsp),%rdi
  15bc46:	mov    %rbx,%rsi
  15bc49:	callq  11c750 <vim_strncpy@@Base>
  15bc4e:	mov    0x78(%rsp),%rax
  15bc53:	mov    (%rax),%rax
  15bc56:	mov    %rax,0x78(%rsp)
  15bc5b:	jmpq   15b1ee <pum_get_height@@Base+0x20de>
  15bc60:	lea    0xcf2c9(%rip),%rsi        # 22af30 <_IO_stdin_used@@Base+0x14970>
  15bc67:	mov    %edx,%r12d
  15bc6a:	xor    %edi,%edi
  15bc6c:	mov    $0x5,%edx
  15bc71:	mov    0x30(%rsp),%r15
  15bc76:	mov    0x40(%rsp),%r14
  15bc7b:	callq  4ed78 <_init@@Base+0x188>
  15bc80:	movzbl %r12b,%edx
  15bc84:	jmpq   15b6fd <pum_get_height@@Base+0x25ed>
  15bc89:	mov    0x80(%rsp),%rax
  15bc91:	mov    0x8(%rax),%rax
  15bc95:	mov    (%rax),%rax
  15bc98:	mov    %rax,0x78(%rsp)
  15bc9d:	jmpq   15a6a0 <pum_get_height@@Base+0x1590>
  15bca2:	mov    0x10(%rax),%rdx
  15bca6:	movl   $0x1,0x2c(%rax)
  15bcad:	mov    %rdx,0x20(%rax)
  15bcb1:	lea    0x3(%rcx,%rcx,2),%rax
  15bcb6:	shl    $0x4,%rax
  15bcba:	movl   $0x1,(%r14,%rax,1)
  15bcc2:	jmpq   15ad43 <pum_get_height@@Base+0x1c33>
  15bcc7:	mov    0x98(%rsp),%rdi
  15bccf:	mov    0x15a0(%rdi),%rdx
  15bcd6:	cmpb   $0x0,(%rdx)
  15bcd9:	cmove  0x10(%rsp),%rdx
  15bcdf:	mov    %rdx,0x10(%rsp)
  15bce4:	jmpq   15a5bf <pum_get_height@@Base+0x14af>
  15bce9:	lea    0x344550(%rip),%rsi        # 4a0240 <e_readerrf@@Base>
  15bcf0:	mov    $0x5,%edx
  15bcf5:	xor    %edi,%edi
  15bcf7:	callq  4ed78 <_init@@Base+0x188>
  15bcfc:	mov    %rax,%rdi
  15bcff:	callq  10d330 <emsg@@Base>
  15bd04:	jmpq   15b236 <pum_get_height@@Base+0x2126>
  15bd09:	mov    0x48(%rsp),%edi
  15bd0d:	mov    0x210(%r14),%rdx
  15bd14:	test   %edi,%edi
  15bd16:	je     15b390 <pum_get_height@@Base+0x2280>
  15bd1c:	test   %rdx,%rdx
  15bd1f:	je     15b390 <pum_get_height@@Base+0x2280>
  15bd25:	cmpb   $0x0,(%rdx)
  15bd28:	je     15b390 <pum_get_height@@Base+0x2280>
  15bd2e:	jmpq   15bb78 <pum_get_height@@Base+0x2a68>
  15bd33:	nopl   0x0(%rax,%rax,1)
  15bd38:	movq   $0x0,0x8(%rsp)
  15bd41:	jmpq   15b724 <pum_get_height@@Base+0x2614>
  15bd46:	mov    0x1d8(%rsp),%rax
  15bd4e:	cmp    %rax,0x1d0(%rsp)
  15bd56:	jg     15ad0d <pum_get_height@@Base+0x1bfd>
  15bd5c:	mov    0x1d0(%rsp),%rax
  15bd64:	mov    0x98(%rsp),%rdi
  15bd6c:	xor    %edx,%edx
  15bd6e:	mov    %rax,%rsi
  15bd71:	lea    0x1(%rax),%r13
  15bd75:	callq  100660 <ml_get_buf@@Base>
  15bd7a:	mov    %rax,%rdi
  15bd7d:	mov    %rax,%rbx
  15bd80:	callq  4ed80 <_init@@Base+0x190>
  15bd85:	cmp    $0x3ff,%eax
  15bd8a:	mov    %eax,%ecx
  15bd8c:	jg     15bed8 <pum_get_height@@Base+0x2dc8>
  15bd92:	mov    0x353297(%rip),%rdi        # 4af030 <IObuff@@Base>
  15bd99:	mov    %eax,0xbc(%rsp)
  15bda0:	mov    %rdi,0x8(%rsp)
  15bda5:	mov    0x8(%rsp),%rdi
  15bdaa:	mov    %rbx,%rsi
  15bdad:	movslq %ecx,%rdx
  15bdb0:	callq  11c750 <vim_strncpy@@Base>
  15bdb5:	mov    0xbc(%rsp),%ebx
  15bdbc:	mov    %r13,0x1d0(%rsp)
  15bdc4:	jmpq   15a755 <pum_get_height@@Base+0x1645>
  15bdc9:	lea    0x1f8(%r14),%rdi
  15bdd0:	callq  159480 <pum_get_height@@Base+0x370>
  15bdd5:	mov    %rax,0x200(%r14)
  15bddc:	jmpq   15ac1b <pum_get_height@@Base+0x1b0b>
  15bde1:	movq   $0x0,0x78(%rsp)
  15bdea:	movq   $0x0,0x88(%rsp)
  15bdf6:	jmpq   15a6a0 <pum_get_height@@Base+0x1590>
  15bdfb:	mov    $0xffffffff,%ebx
  15be00:	movq   $0x0,0x38(%rsp)
  15be09:	jmpq   15b25a <pum_get_height@@Base+0x214a>
  15be0e:	mov    0x98(%rsp),%rbx
  15be16:	mov    0x15a0(%rbx),%rdx
  15be1d:	cmpb   $0x0,(%rdx)
  15be20:	cmove  0x10(%rsp),%rdx
  15be26:	mov    %rdx,0x10(%rsp)
  15be2b:	jmpq   15b99f <pum_get_height@@Base+0x288f>
  15be30:	mov    %rcx,%rax
  15be33:	add    $0x1,%rdx
  15be37:	cmp    %rax,%r14
  15be3a:	jne    15b547 <pum_get_height@@Base+0x2437>
  15be40:	jmpq   15b821 <pum_get_height@@Base+0x2711>
  15be45:	nopl   (%rax)
  15be48:	mov    0xa0(%rsp),%rcx
  15be50:	mov    0xa8(%rsp),%rsi
  15be58:	lea    0xc0(%rsp),%rdi
  15be60:	mov    %ebx,%edx
  15be62:	callq  159520 <pum_get_height@@Base+0x410>
  15be67:	test   %rax,%rax
  15be6a:	mov    %rax,0x8(%rsp)
  15be6f:	je     15bfcc <pum_get_height@@Base+0x2ebc>
  15be75:	mov    0xbc(%rsp),%eax
  15be7c:	jmpq   15bb16 <pum_get_height@@Base+0x2a06>
  15be81:	mov    0xa0(%rsp),%rcx
  15be89:	mov    0xa8(%rsp),%rsi
  15be91:	lea    0xc0(%rsp),%rdi
  15be99:	mov    %eax,%edx
  15be9b:	callq  159520 <pum_get_height@@Base+0x410>
  15bea0:	test   %rax,%rax
  15bea3:	mov    %rax,0x8(%rsp)
  15bea8:	je     15bfcc <pum_get_height@@Base+0x2ebc>
  15beae:	mov    0x78(%rsp),%rax
  15beb3:	movslq 0xbc(%rsp),%rdx
  15bebb:	mov    0x18(%rax),%rbx
  15bebf:	jmpq   15bc41 <pum_get_height@@Base+0x2b31>
  15bec4:	mov    0x88(%rsp),%rdi
  15becc:	callq  4ed80 <_init@@Base+0x190>
  15bed1:	mov    %eax,%ebx
  15bed3:	jmpq   15baf5 <pum_get_height@@Base+0x29e5>
  15bed8:	mov    0xa0(%rsp),%rcx
  15bee0:	mov    0xa8(%rsp),%rsi
  15bee8:	lea    0xc0(%rsp),%rdi
  15bef0:	mov    %eax,%edx
  15bef2:	callq  159520 <pum_get_height@@Base+0x410>
  15bef7:	test   %rax,%rax
  15befa:	mov    %rax,0x8(%rsp)
  15beff:	je     15bfcc <pum_get_height@@Base+0x2ebc>
  15bf05:	mov    0xbc(%rsp),%ecx
  15bf0c:	jmpq   15bda5 <pum_get_height@@Base+0x2c95>
  15bf11:	mov    %r15,%r12
  15bf14:	mov    0x40(%rsp),%r14
  15bf19:	mov    0x30(%rsp),%r15
  15bf1e:	movzbl (%r12),%ebx
  15bf23:	mov    $0x5,%edx
  15bf28:	lea    0xcf029(%rip),%rsi        # 22af58 <_IO_stdin_used@@Base+0x14998>
  15bf2f:	jmpq   15b6f4 <pum_get_height@@Base+0x25e4>
  15bf34:	lea    0xcf04d(%rip),%rsi        # 22af88 <_IO_stdin_used@@Base+0x149c8>
  15bf3b:	mov    $0x5,%edx
  15bf40:	xor    %edi,%edi
  15bf42:	mov    0x30(%rsp),%r15
  15bf47:	mov    %al,0x20(%rsp)
  15bf4b:	mov    0x40(%rsp),%r14
  15bf50:	callq  4ed78 <_init@@Base+0x188>
  15bf55:	movzbl 0x20(%rsp),%edx
  15bf5a:	jmpq   15b6fd <pum_get_height@@Base+0x25ed>
  15bf5f:	mov    0x10(%rax),%rdx
  15bf63:	mov    %rdx,0x20(%rax)
  15bf67:	jmpq   15ad43 <pum_get_height@@Base+0x1c33>
  15bf6c:	callq  4ed90 <_init@@Base+0x1a0>
  15bf71:	mov    $0xffffffff,%ebx
  15bf76:	movq   $0x0,0x90(%rsp)
  15bf82:	jmpq   15b26c <pum_get_height@@Base+0x215c>
  15bf87:	mov    $0x5,%edx
  15bf8c:	lea    0xcf045(%rip),%rsi        # 22afd8 <_IO_stdin_used@@Base+0x14a18>
  15bf93:	jmpq   15bcf5 <pum_get_height@@Base+0x2be5>
  15bf98:	lea    0x344521(%rip),%rsi        # 4a04c0 <e_openerrf@@Base>
  15bf9f:	mov    $0x5,%edx
  15bfa4:	xor    %edi,%edi
  15bfa6:	callq  4ed78 <_init@@Base+0x188>
  15bfab:	mov    %rbx,%rsi
  15bfae:	mov    %rax,%rdi
  15bfb1:	mov    $0xffffffff,%ebx
  15bfb6:	callq  107390 <emsg2@@Base>
  15bfbb:	movq   $0x0,0x90(%rsp)
  15bfc7:	jmpq   15b26c <pum_get_height@@Base+0x215c>
  15bfcc:	mov    $0xffffffff,%ebx
  15bfd1:	jmpq   15b26c <pum_get_height@@Base+0x215c>
  15bfd6:	nopw   %cs:0x0(%rax,%rax,1)
  15bfe0:	mov    0x8(%rdi),%rax
  15bfe4:	test   %rax,%rax
  15bfe7:	je     15bff5 <pum_get_height@@Base+0x2ee5>
  15bfe9:	mov    0x13c8(%rax),%rax
  15bff0:	cmpb   $0x71,(%rax)
  15bff3:	je     15c018 <pum_get_height@@Base+0x2f08>
  15bff5:	push   %rbx
  15bff6:	mov    %rdi,%rbx
  15bff9:	lea    0x1858(%rdi),%rdi
  15c000:	callq  159420 <pum_get_height@@Base+0x310>
  15c005:	mov    0x1850(%rbx),%rax
  15c00c:	test   %rax,%rax
  15c00f:	je     15c030 <pum_get_height@@Base+0x2f20>
  15c011:	pop    %rbx
  15c012:	retq   
  15c013:	nopl   0x0(%rax,%rax,1)
  15c018:	mov    0x1858(%rdi),%rax
  15c01f:	test   %rax,%rax
  15c022:	je     15bff5 <pum_get_height@@Base+0x2ee5>
  15c024:	repz retq 
  15c026:	nopw   %cs:0x0(%rax,%rax,1)
  15c030:	callq  1594d0 <pum_get_height@@Base+0x3c0>
  15c035:	mov    %rax,0x1850(%rbx)
  15c03c:	pop    %rbx
  15c03d:	retq   
  15c03e:	xchg   %ax,%ax
