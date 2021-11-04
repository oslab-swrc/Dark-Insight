// TC_OUT
00000000000141e0 <tparm@@Base>:
   141e0:	push   %r15
   141e2:	push   %r14
   141e4:	push   %r13
   141e6:	push   %r12
   141e8:	push   %rbp
   141e9:	push   %rbx
   141ea:	sub    $0x128,%rsp
   141f1:	mov    %fs:0x28,%rax
   141fa:	mov    %rax,0xe8(%rsp)
   14202:	xor    %eax,%eax
   14204:	mov    0x216bd5(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   1420b:	mov    %rsi,0xf8(%rsp)
   14213:	test   %rdi,%rdi
   14216:	mov    %rdx,0x100(%rsp)
   1421e:	mov    %rcx,0x108(%rsp)
   14226:	mov    %r8,0x110(%rsp)
   1422e:	mov    %r9,0x118(%rsp)
   14236:	movl   $0x0,(%rax)
   1423c:	lea    0x160(%rsp),%rax
   14244:	movl   $0x8,0x38(%rsp)
   1424c:	movl   $0x0,0x34(%rsp)
   14254:	mov    %rax,0x40(%rsp)
   14259:	lea    0xf0(%rsp),%rax
   14261:	mov    %rax,0x48(%rsp)
   14266:	je     153e5 <tparm@@Base+0x1205>
   1426c:	mov    0x216c55(%rip),%r13        # 22aec8 <boolnames@@Base+0x7e8>
   14273:	lea    0x50(%rsp),%r12
   14278:	mov    %rdi,%rbx
   1427b:	movq   $0x0,0x1e8(%r13)
   14286:	callq  d610 <_init@@Base+0x178>
   1428b:	lea    0x34(%rsp),%rdx
   14290:	mov    %r12,%rsi
   14293:	mov    %rbx,%rdi
   14296:	mov    %rax,%rbp
   14299:	callq  d6f8 <_init@@Base+0x260>
   1429e:	cmpq   $0x0,0x1f0(%r13)
   142a6:	je     153e5 <tparm@@Base+0x1205>
   142ac:	mov    0x34(%rsp),%r8d
   142b1:	cmp    $0x9,%eax
   142b4:	mov    $0x9,%edx
   142b9:	cmovg  %edx,%eax
   142bc:	cmp    $0x9,%r8d
   142c0:	mov    %r8d,%esi
   142c3:	jg     14320 <tparm@@Base+0x140>
   142c5:	cmp    %eax,%r8d
   142c8:	mov    %eax,%ecx
   142ca:	cmovge %r8d,%ecx
   142ce:	test   %ecx,%ecx
   142d0:	jle    14377 <tparm@@Base+0x197>
   142d6:	mov    0x48(%rsp),%r15
   142db:	mov    0x38(%rsp),%r10d
   142e0:	lea    0xa0(%rsp),%rsi
   142e8:	mov    0x40(%rsp),%r11
   142ed:	xor    %edx,%edx
   142ef:	xor    %r14d,%r14d
   142f2:	xor    %r9d,%r9d
   142f5:	nopl   (%rax)
   142f8:	cmpq   $0x0,(%r12,%rdx,8)
   142fd:	je     14338 <tparm@@Base+0x158>
   142ff:	cmp    $0x2f,%r10d
   14303:	ja     15987 <tparm@@Base+0x17a7>
   14309:	mov    %r10d,%edi
   1430c:	mov    $0x1,%r9d
   14312:	add    $0x8,%r10d
   14316:	add    %r15,%rdi
   14319:	jmpq   15994 <tparm@@Base+0x17b4>
   1431e:	xchg   %ax,%ax
   14320:	movl   $0x9,0x34(%rsp)
   14328:	mov    $0x9,%ecx
   1432d:	mov    $0x9,%r8d
   14333:	jmp    142d6 <tparm@@Base+0xf6>
   14335:	nopl   (%rax)
   14338:	cmp    $0x2f,%r10d
   1433c:	ja     15975 <tparm@@Base+0x1795>
   14342:	mov    %r10d,%edi
   14345:	mov    $0x1,%r9d
   1434b:	add    $0x8,%r10d
   1434f:	add    %r15,%rdi
   14352:	mov    (%rdi),%rdi
   14355:	mov    %rdi,(%rsi,%rdx,8)
   14359:	add    $0x1,%rdx
   1435d:	cmp    %edx,%ecx
   1435f:	jg     142f8 <tparm@@Base+0x118>
   14361:	test   %r9b,%r9b
   14364:	jne    1596b <tparm@@Base+0x178b>
   1436a:	test   %r14b,%r14b
   1436d:	je     14374 <tparm@@Base+0x194>
   1436f:	mov    %r11,0x40(%rsp)
   14374:	mov    %r8d,%esi
   14377:	test   %r8d,%r8d
   1437a:	movl   $0x0,0x1d0(%r13)
   14385:	movb   $0x0,0x2e(%rsp)
   1438a:	jne    14407 <tparm@@Base+0x227>
   1438c:	sub    $0x1,%eax
   1438f:	js     14402 <tparm@@Base+0x222>
   14391:	mov    0x216a48(%rip),%rdi        # 22ade0 <boolnames@@Base+0x700>
   14398:	movslq %eax,%rdx
   1439b:	xor    %eax,%eax
   1439d:	mov    (%rdi),%edi
   1439f:	jmp    143ce <tparm@@Base+0x1ee>
   143a1:	nopl   0x0(%rax)
   143a8:	movslq %esi,%rax
   143ab:	add    $0x1,%esi
   143ae:	add    $0x8,%rax
   143b2:	shl    $0x4,%rax
   143b6:	add    %r13,%rax
   143b9:	movb   $0x0,0x18(%rax)
   143bd:	mov    %rcx,0x10(%rax)
   143c1:	mov    $0x1,%eax
   143c6:	sub    $0x1,%rdx
   143ca:	test   %edx,%edx
   143cc:	js     143f1 <tparm@@Base+0x211>
   143ce:	mov    (%r12,%rdx,8),%rcx
   143d2:	test   %rcx,%rcx
   143d5:	je     14780 <tparm@@Base+0x5a0>
   143db:	cmp    $0x13,%esi
   143de:	jle    143a8 <tparm@@Base+0x1c8>
   143e0:	sub    $0x1,%rdx
   143e4:	add    $0x1,%edi
   143e7:	mov    $0x1,%r8d
   143ed:	test   %edx,%edx
   143ef:	jns    143ce <tparm@@Base+0x1ee>
   143f1:	test   %al,%al
   143f3:	jne    1595f <tparm@@Base+0x177f>
   143f9:	test   %r8b,%r8b
   143fc:	jne    1593b <tparm@@Base+0x175b>
   14402:	movb   $0x1,0x2e(%rsp)
   14407:	movslq %ebp,%r14
   1440a:	mov    %rbx,0x8(%rsp)
   1440f:	test   %r14,%r14
   14412:	jle    14731 <tparm@@Base+0x551>
   14418:	movb   $0x0,0x2f(%rsp)
   1441d:	lea    0xcb28(%rip),%r15        # 20f4c <_nc_tinfo_fkeys@@Base+0x152c>
   14424:	jmp    14462 <tparm@@Base+0x282>
   14426:	nopw   %cs:0x0(%rax,%rax,1)
   14430:	mov    0x1d8(%r13),%rax
   14437:	mov    %rsi,0x1e8(%r13)
   1443e:	mov    %bpl,(%rax,%rdx,1)
   14442:	movzbl (%rbx),%eax
   14445:	test   %al,%al
   14447:	je     14731 <tparm@@Base+0x551>
   1444d:	add    $0x1,%rbx
   14451:	mov    %rbx,%rax
   14454:	sub    0x8(%rsp),%rax
   14459:	cmp    %rax,%r14
   1445c:	jle    14731 <tparm@@Base+0x551>
   14462:	movzbl (%rbx),%ebp
   14465:	cmp    $0x25,%bpl
   14469:	je     144c0 <tparm@@Base+0x2e0>
   1446b:	mov    0x1e8(%r13),%rdx
   14472:	test   %ebp,%ebp
   14474:	mov    $0x80,%eax
   14479:	cmove  %eax,%ebp
   1447c:	lea    0x1(%rdx),%rsi
   14480:	cmp    0x1e0(%r13),%rsi
   14487:	jbe    14430 <tparm@@Base+0x250>
   14489:	mov    0x1d8(%r13),%rdi
   14490:	add    %rsi,%rsi
   14493:	mov    %rsi,0x1e0(%r13)
   1449a:	callq  d5f8 <_init@@Base+0x160>
   1449f:	test   %rax,%rax
   144a2:	mov    %rax,0x1d8(%r13)
   144a9:	je     159a8 <tparm@@Base+0x17c8>
   144af:	mov    0x1e8(%r13),%rdx
   144b6:	lea    0x1(%rdx),%rsi
   144ba:	jmpq   14437 <tparm@@Base+0x257>
   144bf:	nop
   144c0:	mov    0x1f0(%r13),%rsi
   144c7:	lea    0x1(%rbx),%r12
   144cb:	mov    %rbx,0x88(%r13)
   144d2:	test   %rsi,%rsi
   144d5:	je     147f0 <tparm@@Base+0x610>
   144db:	lea    0x1(%rsi),%rdx
   144df:	movb   $0x25,(%rsi)
   144e2:	xor    %ecx,%ecx
   144e4:	movzbl 0x1(%rbx),%ebp
   144e8:	movl   $0x0,0x28(%rsp)
   144f0:	xor    %r8d,%r8d
   144f3:	xor    %edi,%edi
   144f5:	xor    %r10d,%r10d
   144f8:	xor    %ebx,%ebx
   144fa:	nopw   0x0(%rax,%rax,1)
   14500:	test   %bpl,%bpl
   14503:	sete   %al
   14506:	or     %al,%bl
   14508:	jne    14548 <tparm@@Base+0x368>
   1450a:	lea    -0x20(%rbp),%eax
   1450d:	cmp    $0x58,%al
   1450f:	ja     14650 <tparm@@Base+0x470>
   14515:	movzbl %al,%eax
   14518:	movslq (%r15,%rax,4),%rax
   1451c:	add    %r15,%rax
   1451f:	jmpq   *%rax
   14521:	nopl   0x0(%rax)
   14528:	mov    %bpl,(%rdx)
   1452b:	movzbl (%r12),%ebp
   14530:	add    $0x1,%rdx
   14534:	mov    $0x1,%ebx
   14539:	test   %bpl,%bpl
   1453c:	sete   %al
   1453f:	or     %al,%bl
   14541:	je     1450a <tparm@@Base+0x32a>
   14543:	nopl   0x0(%rax,%rax,1)
   14548:	test   %r8b,%r8b
   1454b:	je     14566 <tparm@@Base+0x386>
   1454d:	movb   $0x25,(%rsi)
   14550:	movzbl (%r12),%eax
   14555:	lea    0x2(%rsi),%rdx
   14559:	xor    %ecx,%ecx
   1455b:	movl   $0x0,0x28(%rsp)
   14563:	mov    %al,0x1(%rsi)
   14566:	xor    %eax,%eax
   14568:	test   %dil,%dil
   1456b:	je     14573 <tparm@@Base+0x393>
   1456d:	mov    %ecx,%eax
   1456f:	mov    0x28(%rsp),%ecx
   14573:	cmp    %eax,%ecx
   14575:	movb   $0x0,(%rdx)
   14578:	cmovge %ecx,%eax
   1457b:	movslq %eax,%rbp
   1457e:	movzbl (%r12),%eax
   14583:	lea    -0x21(%rax),%edx
   14586:	cmp    $0x5d,%dl
   14589:	ja     1535b <tparm@@Base+0x117b>
   1458f:	lea    0xcb1a(%rip),%rcx        # 210b0 <_nc_tinfo_fkeys@@Base+0x1690>
   14596:	movzbl %dl,%edx
   14599:	movslq (%rcx,%rdx,4),%rdx
   1459d:	add    %rcx,%rdx
   145a0:	jmpq   *%rdx
   145a2:	nopw   0x0(%rax,%rax,1)
   145a8:	movzbl 0x1(%r12),%ebp
   145ae:	mov    $0x1,%r10d
   145b4:	add    $0x1,%r12
   145b8:	jmpq   14500 <tparm@@Base+0x320>
   145bd:	nopl   (%rax)
   145c0:	test   %dil,%dil
   145c3:	movb   $0x2e,(%rdx)
   145c6:	lea    0x1(%rdx),%r9
   145ca:	lea    0x1(%r12),%rax
   145cf:	movzbl 0x1(%r12),%ebp
   145d5:	jne    146d0 <tparm@@Base+0x4f0>
   145db:	mov    %ecx,0x28(%rsp)
   145df:	xor    %ebx,%ebx
   145e1:	mov    %r9,%rdx
   145e4:	mov    %rax,%r12
   145e7:	xor    %ecx,%ecx
   145e9:	mov    $0x1,%edi
   145ee:	jmpq   14500 <tparm@@Base+0x320>
   145f3:	nopl   0x0(%rax,%rax,1)
   145f8:	movb   $0x23,(%rdx)
   145fb:	add    $0x1,%r12
   145ff:	movzbl (%r12),%ebp
   14604:	add    $0x1,%rdx
   14608:	jmpq   14500 <tparm@@Base+0x320>
   1460d:	nopl   (%rax)
   14610:	movb   $0x20,(%rdx)
   14613:	add    $0x1,%r12
   14617:	movzbl (%r12),%ebp
   1461c:	add    $0x1,%rdx
   14620:	jmpq   14500 <tparm@@Base+0x320>
   14625:	nopl   (%rax)
   14628:	test   %r10b,%r10b
   1462b:	je     14548 <tparm@@Base+0x368>
   14631:	movb   $0x2d,(%rdx)
   14634:	add    $0x1,%r12
   14638:	movzbl (%r12),%ebp
   1463d:	add    $0x1,%rdx
   14641:	jmpq   14500 <tparm@@Base+0x320>
   14646:	nopw   %cs:0x0(%rax,%rax,1)
   14650:	mov    %r8b,0x2d(%rsp)
   14655:	mov    %r10b,0x2c(%rsp)
   1465a:	mov    %dil,0x27(%rsp)
   1465f:	mov    %rdx,0x18(%rsp)
   14664:	mov    %ecx,0x20(%rsp)
   14668:	mov    %rsi,0x10(%rsp)
   1466d:	callq  d9a0 <_init@@Base+0x508>
   14672:	mov    (%rax),%r11
   14675:	movzbl %bpl,%r9d
   14679:	mov    0x10(%rsp),%rsi
   1467e:	mov    0x20(%rsp),%ecx
   14682:	mov    0x18(%rsp),%rdx
   14687:	movzbl 0x27(%rsp),%edi
   1468c:	movzbl 0x2c(%rsp),%r10d
   14692:	testb  $0x8,0x1(%r11,%r9,2)
   14698:	movzbl 0x2d(%rsp),%r8d
   1469e:	je     146e0 <tparm@@Base+0x500>
   146a0:	lea    (%rcx,%rcx,4),%ecx
   146a3:	movsbl %bpl,%eax
   146a7:	mov    %bpl,(%rdx)
   146aa:	movzbl 0x1(%r12),%ebp
   146b0:	lea    -0x30(%rax,%rcx,2),%ecx
   146b4:	mov    $0x1,%eax
   146b9:	cmp    $0x2711,%ecx
   146bf:	cmovge %eax,%r8d
   146c3:	add    $0x1,%rdx
   146c7:	add    $0x1,%r12
   146cb:	jmpq   14500 <tparm@@Base+0x320>
   146d0:	mov    %edi,%r8d
   146d3:	mov    %r9,%rdx
   146d6:	mov    %rax,%r12
   146d9:	xor    %ecx,%ecx
   146db:	jmpq   14500 <tparm@@Base+0x320>
   146e0:	mov    $0x1,%ebx
   146e5:	jmpq   14500 <tparm@@Base+0x320>
   146ea:	lea    0x1(%r12),%rax
   146ef:	movzbl 0x1(%r12),%edx
   146f5:	xor    %ecx,%ecx
   146f7:	jmp    14708 <tparm@@Base+0x528>
   146f9:	nopl   0x0(%rax)
   14700:	movzbl 0x1(%rax),%edx
   14704:	add    $0x1,%rax
   14708:	test   %dl,%dl
   1470a:	je     14731 <tparm@@Base+0x551>
   1470c:	cmp    $0x25,%dl
   1470f:	jne    14700 <tparm@@Base+0x520>
   14711:	lea    0x1(%rax),%rbx
   14715:	movzbl 0x1(%rax),%eax
   14719:	cmp    $0x3f,%al
   1471b:	je     1539d <tparm@@Base+0x11bd>
   14721:	cmp    $0x3b,%al
   14723:	je     15363 <tparm@@Base+0x1183>
   14729:	test   %al,%al
   1472b:	jne    1536e <tparm@@Base+0x118e>
   14731:	mov    0x1e8(%r13),%rdx
   14738:	lea    0x1(%rdx),%rax
   1473c:	cmp    0x1e0(%r13),%rax
   14743:	ja     147b8 <tparm@@Base+0x5d8>
   14745:	mov    0x1d8(%r13),%rax
   1474c:	movb   $0x0,(%rax,%rdx,1)
   14750:	mov    0x1d8(%r13),%rax
   14757:	mov    0xe8(%rsp),%rcx
   1475f:	xor    %fs:0x28,%rcx
   14768:	jne    1595a <tparm@@Base+0x177a>
   1476e:	add    $0x128,%rsp
   14775:	pop    %rbx
   14776:	pop    %rbp
   14777:	pop    %r12
   14779:	pop    %r13
   1477b:	pop    %r14
   1477d:	pop    %r15
   1477f:	retq   
   14780:	cmp    $0x13,%esi
   14783:	jg     143e0 <tparm@@Base+0x200>
   14789:	movslq %esi,%rax
   1478c:	mov    0xa0(%rsp,%rdx,8),%rcx
   14794:	add    $0x1,%esi
   14797:	add    $0x8,%rax
   1479b:	shl    $0x4,%rax
   1479f:	add    %r13,%rax
   147a2:	movb   $0x1,0x18(%rax)
   147a6:	mov    %ecx,0x10(%rax)
   147a9:	mov    $0x1,%eax
   147ae:	jmpq   143c6 <tparm@@Base+0x1e6>
   147b3:	nopl   0x0(%rax,%rax,1)
   147b8:	mov    0x1d8(%r13),%rdi
   147bf:	lea    (%rax,%rax,1),%rsi
   147c3:	mov    %rsi,0x1e0(%r13)
   147ca:	callq  d5f8 <_init@@Base+0x160>
   147cf:	test   %rax,%rax
   147d2:	mov    %rax,0x1d8(%r13)
   147d9:	je     159a8 <tparm@@Base+0x17c8>
   147df:	mov    0x1e8(%r13),%rdx
   147e6:	jmpq   1474c <tparm@@Base+0x56c>
   147eb:	nopl   0x0(%rax,%rax,1)
   147f0:	xor    %ebp,%ebp
   147f2:	jmpq   1457e <tparm@@Base+0x39e>
   147f7:	callq  d9a0 <_init@@Base+0x508>
   147fc:	lea    0x1(%r12),%rbx
   14801:	mov    (%rax),%rsi
   14804:	xor    %edx,%edx
   14806:	jmp    1481b <tparm@@Base+0x63b>
   14808:	nopl   0x0(%rax,%rax,1)
   14810:	lea    (%rdx,%rdx,4),%edx
   14813:	add    $0x1,%rbx
   14817:	lea    -0x30(%rax,%rdx,2),%edx
   1481b:	movzbl (%rbx),%eax
   1481e:	movzbl %al,%ecx
   14821:	testb  $0x8,0x1(%rsi,%rcx,2)
   14826:	jne    14810 <tparm@@Base+0x630>
   14828:	mov    0x1d0(%r13),%ecx
   1482f:	cmp    $0x13,%ecx
   14832:	jg     15748 <tparm@@Base+0x1568>
   14838:	movslq %ecx,%rax
   1483b:	add    $0x1,%ecx
   1483e:	add    $0x8,%rax
   14842:	mov    %ecx,0x1d0(%r13)
   14849:	shl    $0x4,%rax
   1484d:	add    %r13,%rax
   14850:	movb   $0x1,0x18(%rax)
   14854:	mov    %edx,0x10(%rax)
   14857:	movzbl (%rbx),%eax
   1485a:	jmpq   14445 <tparm@@Base+0x265>
   1485f:	mov    0x1d0(%r13),%eax
   14866:	test   %eax,%eax
   14868:	jle    157de <tparm@@Base+0x15fe>
   1486e:	sub    $0x1,%eax
   14871:	mov    %eax,0x1d0(%r13)
   14878:	cltq   
   1487a:	add    $0x8,%rax
   1487e:	shl    $0x4,%rax
   14882:	add    %r13,%rax
   14885:	cmpb   $0x0,0x18(%rax)
   14889:	jne    154e7 <tparm@@Base+0x1307>
   1488f:	lea    0x1(%r12),%rax
   14894:	movzbl 0x1(%r12),%edx
   1489a:	xor    %ecx,%ecx
   1489c:	jmp    148a8 <tparm@@Base+0x6c8>
   1489e:	xchg   %ax,%ax
   148a0:	movzbl 0x1(%rax),%edx
   148a4:	add    $0x1,%rax
   148a8:	test   %dl,%dl
   148aa:	je     14731 <tparm@@Base+0x551>
   148b0:	cmp    $0x25,%dl
   148b3:	jne    148a0 <tparm@@Base+0x6c0>
   148b5:	lea    0x1(%rax),%rbx
   148b9:	movzbl 0x1(%rax),%eax
   148bd:	cmp    $0x3f,%al
   148bf:	je     153a8 <tparm@@Base+0x11c8>
   148c5:	cmp    $0x3b,%al
   148c7:	je     153b3 <tparm@@Base+0x11d3>
   148cd:	cmp    $0x65,%al
   148cf:	jne    148d9 <tparm@@Base+0x6f9>
   148d1:	test   %ecx,%ecx
   148d3:	je     1444d <tparm@@Base+0x26d>
   148d9:	test   %al,%al
   148db:	je     14731 <tparm@@Base+0x551>
   148e1:	mov    %rbx,%rax
   148e4:	jmp    148a0 <tparm@@Base+0x6c0>
   148e6:	mov    0x1d0(%r13),%eax
   148ed:	test   %eax,%eax
   148ef:	jle    157ed <tparm@@Base+0x160d>
   148f5:	sub    $0x1,%eax
   148f8:	lea    0x216fb5(%rip),%r8        # 22b8b4 <_nc_tparm_err@@Base+0x4>
   148ff:	mov    %eax,0x1d0(%r13)
   14906:	cltq   
   14908:	add    $0x8,%rax
   1490c:	shl    $0x4,%rax
   14910:	add    %r13,%rax
   14913:	cmpb   $0x0,0x18(%rax)
   14917:	jne    1492b <tparm@@Base+0x74b>
   14919:	mov    0x10(%rax),%r8
   1491d:	lea    0x216f90(%rip),%rax        # 22b8b4 <_nc_tparm_err@@Base+0x4>
   14924:	test   %r8,%r8
   14927:	cmove  %rax,%r8
   1492b:	mov    %r8,%rdi
   1492e:	mov    %r8,0x10(%rsp)
   14933:	mov    0x1f0(%r13),%rbx
   1493a:	callq  d610 <_init@@Base+0x178>
   1493f:	movslq %ebp,%rdx
   14942:	cmp    %eax,%ebp
   14944:	mov    0x10(%rsp),%r8
   14949:	cmovg  %rdx,%rax
   1494d:	mov    0x1e8(%r13),%rdx
   14954:	lea    0x1(%rax,%rdx,1),%rax
   14959:	cmp    0x1e0(%r13),%rax
   14960:	ja     1569f <tparm@@Base+0x14bf>
   14966:	mov    0x1d8(%r13),%rdi
   1496d:	add    %rdx,%rdi
   14970:	mov    %rbx,%rcx
   14973:	mov    $0xffffffffffffffff,%rdx
   1497a:	mov    $0x1,%esi
   1497f:	xor    %eax,%eax
   14981:	callq  d9b0 <_init@@Base+0x518>
   14986:	jmpq   151e6 <tparm@@Base+0x1006>
   1498b:	movzbl 0x1(%r12),%edx
   14991:	lea    0x1(%r12),%rbx
   14996:	mov    %edx,%eax
   14998:	sub    $0x31,%edx
   1499b:	cmp    $0x8,%edx
   1499e:	ja     14445 <tparm@@Base+0x265>
   149a4:	movslq %edx,%rdx
   149a7:	mov    0x50(%rsp,%rdx,8),%rcx
   149ac:	test   %rcx,%rcx
   149af:	je     15587 <tparm@@Base+0x13a7>
   149b5:	mov    0x1d0(%r13),%edx
   149bc:	cmp    $0x13,%edx
   149bf:	jg     15572 <tparm@@Base+0x1392>
   149c5:	movslq %edx,%rax
   149c8:	add    $0x1,%edx
   149cb:	add    $0x8,%rax
   149cf:	mov    %edx,0x1d0(%r13)
   149d6:	shl    $0x4,%rax
   149da:	add    %r13,%rax
   149dd:	movb   $0x0,0x18(%rax)
   149e1:	mov    %rcx,0x10(%rax)
   149e5:	movzbl 0x1(%r12),%eax
   149eb:	jmpq   14445 <tparm@@Base+0x265>
   149f0:	mov    0x1d0(%r13),%ecx
   149f7:	test   %ecx,%ecx
   149f9:	jle    15628 <tparm@@Base+0x1448>
   149ff:	lea    -0x1(%rcx),%eax
   14a02:	movslq %eax,%rdx
   14a05:	mov    %eax,0x1d0(%r13)
   14a0c:	add    $0x8,%rdx
   14a10:	shl    $0x4,%rdx
   14a14:	add    %r13,%rdx
   14a17:	cmpb   $0x0,0x18(%rdx)
   14a1b:	je     15422 <tparm@@Base+0x1242>
   14a21:	test   %eax,%eax
   14a23:	mov    0x10(%rdx),%edx
   14a26:	je     158e2 <tparm@@Base+0x1702>
   14a2c:	sub    $0x2,%ecx
   14a2f:	xor    %eax,%eax
   14a31:	movslq %ecx,%rsi
   14a34:	mov    %ecx,0x1d0(%r13)
   14a3b:	add    $0x8,%rsi
   14a3f:	shl    $0x4,%rsi
   14a43:	add    %r13,%rsi
   14a46:	cmpb   $0x0,0x18(%rsi)
   14a4a:	je     14a4f <tparm@@Base+0x86f>
   14a4c:	mov    0x10(%rsi),%eax
   14a4f:	test   %edx,%edx
   14a51:	je     15436 <tparm@@Base+0x1256>
   14a57:	mov    %edx,%edi
   14a59:	cltd   
   14a5a:	idiv   %edi
   14a5c:	jmpq   15436 <tparm@@Base+0x1256>
   14a61:	mov    0x1d0(%r13),%ebp
   14a68:	test   %ebp,%ebp
   14a6a:	jle    1582b <tparm@@Base+0x164b>
   14a70:	sub    $0x1,%ebp
   14a73:	lea    0x216e3a(%rip),%rdi        # 22b8b4 <_nc_tparm_err@@Base+0x4>
   14a7a:	movslq %ebp,%rbx
   14a7d:	mov    %ebp,0x1d0(%r13)
   14a84:	lea    0x8(%rbx),%rax
   14a88:	shl    $0x4,%rax
   14a8c:	add    %r13,%rax
   14a8f:	cmpb   $0x0,0x18(%rax)
   14a93:	jne    14aa7 <tparm@@Base+0x8c7>
   14a95:	mov    0x10(%rax),%rdi
   14a99:	lea    0x216e14(%rip),%rax        # 22b8b4 <_nc_tparm_err@@Base+0x4>
   14aa0:	test   %rdi,%rdi
   14aa3:	cmove  %rax,%rdi
   14aa7:	callq  d610 <_init@@Base+0x178>
   14aac:	cmp    $0x13,%ebp
   14aaf:	jg     14f70 <tparm@@Base+0xd90>
   14ab5:	lea    0x8(%rbx),%rdx
   14ab9:	mov    %r12,%rbx
   14abc:	shl    $0x4,%rdx
   14ac0:	add    %r13,%rdx
   14ac3:	mov    %eax,0x10(%rdx)
   14ac6:	lea    0x1(%rbp),%eax
   14ac9:	movb   $0x1,0x18(%rdx)
   14acd:	mov    %eax,0x1d0(%r13)
   14ad4:	movzbl (%r12),%eax
   14ad9:	jmpq   14445 <tparm@@Base+0x265>
   14ade:	cmpb   $0x0,0x2f(%rsp)
   14ae3:	jne    153ec <tparm@@Base+0x120c>
   14ae9:	cmpq   $0x0,0x50(%rsp)
   14aef:	je     155c5 <tparm@@Base+0x13e5>
   14af5:	cmpq   $0x0,0x58(%rsp)
   14afb:	je     158f3 <tparm@@Base+0x1713>
   14b01:	mov    %r12,%rbx
   14b04:	movb   $0x1,0x2f(%rsp)
   14b09:	jmpq   1444d <tparm@@Base+0x26d>
   14b0e:	movzbl 0x1(%r12),%eax
   14b14:	lea    0x1(%r12),%rbx
   14b19:	lea    -0x41(%rax),%edx
   14b1c:	cmp    $0x19,%dl
   14b1f:	ja     153f4 <tparm@@Base+0x1214>
   14b25:	mov    0x1d0(%r13),%edx
   14b2c:	cmp    $0x13,%edx
   14b2f:	jg     15572 <tparm@@Base+0x1392>
   14b35:	sub    $0x41,%eax
   14b38:	cltq   
   14b3a:	mov    0x268(%r13,%rax,4),%ecx
   14b42:	movslq %edx,%rax
   14b45:	add    $0x1,%edx
   14b48:	add    $0x8,%rax
   14b4c:	shl    $0x4,%rax
   14b50:	add    %r13,%rax
   14b53:	movb   $0x1,0x18(%rax)
   14b57:	mov    %ecx,0x10(%rax)
   14b5a:	mov    %edx,0x1d0(%r13)
   14b61:	movzbl 0x1(%r12),%eax
   14b67:	jmpq   14445 <tparm@@Base+0x265>
   14b6c:	mov    0x1d0(%r13),%eax
   14b73:	test   %eax,%eax
   14b75:	jle    1538f <tparm@@Base+0x11af>
   14b7b:	lea    -0x1(%rax),%esi
   14b7e:	xor    %ecx,%ecx
   14b80:	movslq %esi,%rdx
   14b83:	mov    %esi,0x1d0(%r13)
   14b8a:	add    $0x8,%rdx
   14b8e:	shl    $0x4,%rdx
   14b92:	add    %r13,%rdx
   14b95:	cmpb   $0x0,0x18(%rdx)
   14b99:	jne    15517 <tparm@@Base+0x1337>
   14b9f:	test   %esi,%esi
   14ba1:	je     1589f <tparm@@Base+0x16bf>
   14ba7:	sub    $0x2,%eax
   14baa:	movslq %eax,%rdx
   14bad:	mov    %eax,0x1d0(%r13)
   14bb4:	add    $0x8,%rdx
   14bb8:	shl    $0x4,%rdx
   14bbc:	add    %r13,%rdx
   14bbf:	cmpb   $0x0,0x18(%rdx)
   14bc3:	je     154b4 <tparm@@Base+0x12d4>
   14bc9:	mov    0x10(%rdx),%edx
   14bcc:	sub    %ecx,%edx
   14bce:	mov    %edx,%ecx
   14bd0:	cmp    $0x13,%eax
   14bd3:	jg     14f70 <tparm@@Base+0xd90>
   14bd9:	movslq %eax,%rdx
   14bdc:	add    $0x8,%rdx
   14be0:	add    $0x1,%eax
   14be3:	mov    %r12,%rbx
   14be6:	shl    $0x4,%rdx
   14bea:	add    %r13,%rdx
   14bed:	movb   $0x1,0x18(%rdx)
   14bf1:	mov    %ecx,0x10(%rdx)
   14bf4:	mov    %eax,0x1d0(%r13)
   14bfb:	movzbl (%r12),%eax
   14c00:	jmpq   14445 <tparm@@Base+0x265>
   14c05:	mov    0x1d0(%r13),%edx
   14c0c:	test   %edx,%edx
   14c0e:	jle    1538f <tparm@@Base+0x11af>
   14c14:	lea    -0x1(%rdx),%ecx
   14c17:	xor    %esi,%esi
   14c19:	movslq %ecx,%rax
   14c1c:	mov    %ecx,0x1d0(%r13)
   14c23:	add    $0x8,%rax
   14c27:	shl    $0x4,%rax
   14c2b:	add    %r13,%rax
   14c2e:	cmpb   $0x0,0x18(%rax)
   14c32:	jne    1550f <tparm@@Base+0x132f>
   14c38:	test   %ecx,%ecx
   14c3a:	je     15917 <tparm@@Base+0x1737>
   14c40:	lea    -0x2(%rdx),%eax
   14c43:	movslq %eax,%rdx
   14c46:	mov    %eax,0x1d0(%r13)
   14c4d:	add    $0x8,%rdx
   14c51:	shl    $0x4,%rdx
   14c55:	add    %r13,%rdx
   14c58:	cmpb   $0x0,0x18(%rdx)
   14c5c:	je     154bb <tparm@@Base+0x12db>
   14c62:	xor    %ecx,%ecx
   14c64:	or     0x10(%rdx),%esi
   14c67:	setne  %cl
   14c6a:	jmpq   14bd0 <tparm@@Base+0x9f0>
   14c6f:	mov    0x1d0(%r13),%edx
   14c76:	test   %edx,%edx
   14c78:	jle    153c3 <tparm@@Base+0x11e3>
   14c7e:	lea    -0x1(%rdx),%ecx
   14c81:	movslq %ecx,%rax
   14c84:	mov    %ecx,0x1d0(%r13)
   14c8b:	add    $0x8,%rax
   14c8f:	shl    $0x4,%rax
   14c93:	add    %r13,%rax
   14c96:	movzbl 0x18(%rax),%esi
   14c9a:	test   %sil,%sil
   14c9d:	jne    154ff <tparm@@Base+0x131f>
   14ca3:	test   %ecx,%ecx
   14ca5:	je     153cd <tparm@@Base+0x11ed>
   14cab:	lea    -0x2(%rdx),%eax
   14cae:	xor    %ecx,%ecx
   14cb0:	movslq %eax,%rdx
   14cb3:	mov    %eax,0x1d0(%r13)
   14cba:	add    $0x8,%rdx
   14cbe:	shl    $0x4,%rdx
   14cc2:	add    %r13,%rdx
   14cc5:	cmpb   $0x0,0x18(%rdx)
   14cc9:	je     14bd0 <tparm@@Base+0x9f0>
   14ccf:	mov    0x10(%rdx),%edi
   14cd2:	xor    %ecx,%ecx
   14cd4:	test   %edi,%edi
   14cd6:	setne  %cl
   14cd9:	and    %esi,%ecx
   14cdb:	jmpq   14bd0 <tparm@@Base+0x9f0>
   14ce0:	mov    0x1d0(%r13),%eax
   14ce7:	test   %eax,%eax
   14ce9:	jle    153c3 <tparm@@Base+0x11e3>
   14cef:	lea    -0x1(%rax),%ecx
   14cf2:	xor    %esi,%esi
   14cf4:	movslq %ecx,%rdx
   14cf7:	mov    %ecx,0x1d0(%r13)
   14cfe:	add    $0x8,%rdx
   14d02:	shl    $0x4,%rdx
   14d06:	add    %r13,%rdx
   14d09:	cmpb   $0x0,0x18(%rdx)
   14d0d:	jne    154f7 <tparm@@Base+0x1317>
   14d13:	test   %ecx,%ecx
   14d15:	je     153cd <tparm@@Base+0x11ed>
   14d1b:	sub    $0x2,%eax
   14d1e:	xor    %ecx,%ecx
   14d20:	movslq %eax,%rdx
   14d23:	mov    %eax,0x1d0(%r13)
   14d2a:	add    $0x8,%rdx
   14d2e:	shl    $0x4,%rdx
   14d32:	add    %r13,%rdx
   14d35:	cmpb   $0x0,0x18(%rdx)
   14d39:	je     14bd0 <tparm@@Base+0x9f0>
   14d3f:	mov    0x10(%rdx),%ecx
   14d42:	and    %esi,%ecx
   14d44:	jmpq   14bd0 <tparm@@Base+0x9f0>
   14d49:	mov    0x1e8(%r13),%rcx
   14d50:	lea    0x1(%rcx),%rdx
   14d54:	cmp    0x1e0(%r13),%rdx
   14d5b:	ja     15711 <tparm@@Base+0x1531>
   14d61:	mov    0x1d8(%r13),%rax
   14d68:	mov    %rdx,0x1e8(%r13)
   14d6f:	mov    %r12,%rbx
   14d72:	movb   $0x25,(%rax,%rcx,1)
   14d76:	movzbl (%r12),%eax
   14d7b:	jmpq   14445 <tparm@@Base+0x265>
   14d80:	mov    0x1d0(%r13),%eax
   14d87:	test   %eax,%eax
   14d89:	jle    157ca <tparm@@Base+0x15ea>
   14d8f:	sub    $0x1,%eax
   14d92:	mov    $0x80,%ebx
   14d97:	mov    %eax,0x1d0(%r13)
   14d9e:	cltq   
   14da0:	add    $0x8,%rax
   14da4:	shl    $0x4,%rax
   14da8:	add    %r13,%rax
   14dab:	cmpb   $0x0,0x18(%rax)
   14daf:	jne    15537 <tparm@@Base+0x1357>
   14db5:	mov    0x1e8(%r13),%rcx
   14dbc:	lea    0x1(%rcx),%rdx
   14dc0:	cmp    0x1e0(%r13),%rdx
   14dc7:	ja     156da <tparm@@Base+0x14fa>
   14dcd:	mov    0x1d8(%r13),%rax
   14dd4:	mov    %rdx,0x1e8(%r13)
   14ddb:	mov    %bl,(%rax,%rcx,1)
   14dde:	mov    %r12,%rbx
   14de1:	movzbl (%r12),%eax
   14de6:	jmpq   14445 <tparm@@Base+0x265>
   14deb:	mov    0x1d0(%r13),%eax
   14df2:	test   %eax,%eax
   14df4:	jle    1538f <tparm@@Base+0x11af>
   14dfa:	lea    -0x1(%rax),%esi
   14dfd:	xor    %ecx,%ecx
   14dff:	movslq %esi,%rdx
   14e02:	mov    %esi,0x1d0(%r13)
   14e09:	add    $0x8,%rdx
   14e0d:	shl    $0x4,%rdx
   14e11:	add    %r13,%rdx
   14e14:	cmpb   $0x0,0x18(%rdx)
   14e18:	jne    1552f <tparm@@Base+0x134f>
   14e1e:	test   %esi,%esi
   14e20:	je     15379 <tparm@@Base+0x1199>
   14e26:	sub    $0x2,%eax
   14e29:	movslq %eax,%rdx
   14e2c:	mov    %eax,0x1d0(%r13)
   14e33:	add    $0x8,%rdx
   14e37:	shl    $0x4,%rdx
   14e3b:	add    %r13,%rdx
   14e3e:	cmpb   $0x0,0x18(%rdx)
   14e42:	je     14bd0 <tparm@@Base+0x9f0>
   14e48:	xor    0x10(%rdx),%ecx
   14e4b:	jmpq   14bd0 <tparm@@Base+0x9f0>
   14e50:	mov    0x1d0(%r13),%eax
   14e57:	test   %eax,%eax
   14e59:	jle    153c3 <tparm@@Base+0x11e3>
   14e5f:	lea    -0x1(%rax),%ecx
   14e62:	xor    %esi,%esi
   14e64:	movslq %ecx,%rdx
   14e67:	mov    %ecx,0x1d0(%r13)
   14e6e:	add    $0x8,%rdx
   14e72:	shl    $0x4,%rdx
   14e76:	add    %r13,%rdx
   14e79:	cmpb   $0x0,0x18(%rdx)
   14e7d:	jne    15527 <tparm@@Base+0x1347>
   14e83:	test   %ecx,%ecx
   14e85:	je     153cd <tparm@@Base+0x11ed>
   14e8b:	sub    $0x2,%eax
   14e8e:	xor    %ecx,%ecx
   14e90:	movslq %eax,%rdx
   14e93:	mov    %eax,0x1d0(%r13)
   14e9a:	add    $0x8,%rdx
   14e9e:	shl    $0x4,%rdx
   14ea2:	add    %r13,%rdx
   14ea5:	cmpb   $0x0,0x18(%rdx)
   14ea9:	je     14bd0 <tparm@@Base+0x9f0>
   14eaf:	mov    0x10(%rdx),%ecx
   14eb2:	imul   %esi,%ecx
   14eb5:	jmpq   14bd0 <tparm@@Base+0x9f0>
   14eba:	mov    0x1d0(%r13),%eax
   14ec1:	test   %eax,%eax
   14ec3:	jle    15817 <tparm@@Base+0x1637>
   14ec9:	lea    -0x1(%rax),%ecx
   14ecc:	xor    %esi,%esi
   14ece:	movslq %ecx,%rdx
   14ed1:	mov    %ecx,0x1d0(%r13)
   14ed8:	add    $0x8,%rdx
   14edc:	shl    $0x4,%rdx
   14ee0:	add    %r13,%rdx
   14ee3:	cmpb   $0x0,0x18(%rdx)
   14ee7:	jne    1551f <tparm@@Base+0x133f>
   14eed:	test   %ecx,%ecx
   14eef:	je     15923 <tparm@@Base+0x1743>
   14ef5:	sub    $0x2,%eax
   14ef8:	movslq %eax,%rdx
   14efb:	mov    %eax,0x1d0(%r13)
   14f02:	add    $0x8,%rdx
   14f06:	shl    $0x4,%rdx
   14f0a:	add    %r13,%rdx
   14f0d:	cmpb   $0x0,0x18(%rdx)
   14f11:	je     154cf <tparm@@Base+0x12ef>
   14f17:	xor    %ecx,%ecx
   14f19:	cmp    %esi,0x10(%rdx)
   14f1c:	sete   %cl
   14f1f:	jmpq   14bd0 <tparm@@Base+0x9f0>
   14f24:	mov    0x1d0(%r13),%eax
   14f2b:	test   %eax,%eax
   14f2d:	jle    15803 <tparm@@Base+0x1623>
   14f33:	sub    $0x1,%eax
   14f36:	mov    $0x1,%esi
   14f3b:	movslq %eax,%rdx
   14f3e:	mov    %eax,0x1d0(%r13)
   14f45:	lea    0x8(%rdx),%rcx
   14f49:	shl    $0x4,%rcx
   14f4d:	add    %r13,%rcx
   14f50:	cmpb   $0x0,0x18(%rcx)
   14f54:	je     14f5f <tparm@@Base+0xd7f>
   14f56:	mov    0x10(%rcx),%ecx
   14f59:	test   %ecx,%ecx
   14f5b:	sete   %sil
   14f5f:	cmp    $0x13,%eax
   14f62:	movzbl %sil,%ecx
   14f66:	jle    14bdc <tparm@@Base+0x9fc>
   14f6c:	nopl   0x0(%rax)
   14f70:	mov    0x215e69(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   14f77:	mov    %r12,%rbx
   14f7a:	addl   $0x1,(%rax)
   14f7d:	movzbl (%r12),%eax
   14f82:	jmpq   14445 <tparm@@Base+0x265>
   14f87:	mov    0x1d0(%r13),%eax
   14f8e:	test   %eax,%eax
   14f90:	jle    1538f <tparm@@Base+0x11af>
   14f96:	lea    -0x1(%rax),%esi
   14f99:	xor    %ecx,%ecx
   14f9b:	movslq %esi,%rdx
   14f9e:	mov    %esi,0x1d0(%r13)
   14fa5:	add    $0x8,%rdx
   14fa9:	shl    $0x4,%rdx
   14fad:	add    %r13,%rdx
   14fb0:	cmpb   $0x0,0x18(%rdx)
   14fb4:	jne    15559 <tparm@@Base+0x1379>
   14fba:	test   %esi,%esi
   14fbc:	je     15379 <tparm@@Base+0x1199>
   14fc2:	sub    $0x2,%eax
   14fc5:	movslq %eax,%rdx
   14fc8:	mov    %eax,0x1d0(%r13)
   14fcf:	add    $0x8,%rdx
   14fd3:	shl    $0x4,%rdx
   14fd7:	add    %r13,%rdx
   14fda:	cmpb   $0x0,0x18(%rdx)
   14fde:	je     14bd0 <tparm@@Base+0x9f0>
   14fe4:	add    0x10(%rdx),%ecx
   14fe7:	jmpq   14bd0 <tparm@@Base+0x9f0>
   14fec:	mov    0x1d0(%r13),%edx
   14ff3:	cmp    $0x13,%edx
   14ff6:	jg     157a4 <tparm@@Base+0x15c4>
   14ffc:	movzbl 0x1(%r12),%ecx
   15002:	movslq %edx,%rax
   15005:	add    $0x1,%edx
   15008:	add    $0x8,%rax
   1500c:	mov    %edx,0x1d0(%r13)
   15013:	shl    $0x4,%rax
   15017:	add    %r13,%rax
   1501a:	movb   $0x1,0x18(%rax)
   1501e:	mov    %ecx,0x10(%rax)
   15021:	lea    0x2(%r12),%rbx
   15026:	movzbl 0x2(%r12),%eax
   1502c:	jmpq   14445 <tparm@@Base+0x265>
   15031:	mov    0x1d0(%r13),%eax
   15038:	test   %eax,%eax
   1503a:	jle    157b3 <tparm@@Base+0x15d3>
   15040:	sub    $0x1,%eax
   15043:	mov    $0xffffffff,%esi
   15048:	movslq %eax,%rdx
   1504b:	mov    %eax,0x1d0(%r13)
   15052:	lea    0x8(%rdx),%rcx
   15056:	shl    $0x4,%rcx
   1505a:	add    %r13,%rcx
   1505d:	cmpb   $0x0,0x18(%rcx)
   15061:	je     15068 <tparm@@Base+0xe88>
   15063:	mov    0x10(%rcx),%esi
   15066:	not    %esi
   15068:	cmp    $0x13,%eax
   1506b:	jg     14f70 <tparm@@Base+0xd90>
   15071:	add    $0x8,%rdx
   15075:	add    $0x1,%eax
   15078:	mov    %r12,%rbx
   1507b:	shl    $0x4,%rdx
   1507f:	mov    %eax,0x1d0(%r13)
   15086:	add    %r13,%rdx
   15089:	movb   $0x1,0x18(%rdx)
   1508d:	mov    %esi,0x10(%rdx)
   15090:	movzbl (%r12),%eax
   15095:	jmpq   14445 <tparm@@Base+0x265>
   1509a:	mov    0x1d0(%r13),%eax
   150a1:	test   %eax,%eax
   150a3:	jle    1538f <tparm@@Base+0x11af>
   150a9:	lea    -0x1(%rax),%esi
   150ac:	xor    %ecx,%ecx
   150ae:	movslq %esi,%rdx
   150b1:	mov    %esi,0x1d0(%r13)
   150b8:	add    $0x8,%rdx
   150bc:	shl    $0x4,%rdx
   150c0:	add    %r13,%rdx
   150c3:	cmpb   $0x0,0x18(%rdx)
   150c7:	jne    15551 <tparm@@Base+0x1371>
   150cd:	test   %esi,%esi
   150cf:	je     15376 <tparm@@Base+0x1196>
   150d5:	sub    $0x2,%eax
   150d8:	movslq %eax,%rdx
   150db:	mov    %eax,0x1d0(%r13)
   150e2:	add    $0x8,%rdx
   150e6:	shl    $0x4,%rdx
   150ea:	add    %r13,%rdx
   150ed:	cmpb   $0x0,0x18(%rdx)
   150f1:	je     154c7 <tparm@@Base+0x12e7>
   150f7:	cmp    %ecx,0x10(%rdx)
   150fa:	setg   %cl
   150fd:	movzbl %cl,%ecx
   15100:	jmpq   14bd0 <tparm@@Base+0x9f0>
   15105:	mov    0x1d0(%r13),%eax
   1510c:	test   %eax,%eax
   1510e:	jle    1538f <tparm@@Base+0x11af>
   15114:	lea    -0x1(%rax),%esi
   15117:	xor    %ecx,%ecx
   15119:	movslq %esi,%rdx
   1511c:	mov    %esi,0x1d0(%r13)
   15123:	add    $0x8,%rdx
   15127:	shl    $0x4,%rdx
   1512b:	add    %r13,%rdx
   1512e:	cmpb   $0x0,0x18(%rdx)
   15132:	jne    15549 <tparm@@Base+0x1369>
   15138:	test   %esi,%esi
   1513a:	je     15379 <tparm@@Base+0x1199>
   15140:	sub    $0x2,%eax
   15143:	movslq %eax,%rdx
   15146:	mov    %eax,0x1d0(%r13)
   1514d:	add    $0x8,%rdx
   15151:	shl    $0x4,%rdx
   15155:	add    %r13,%rdx
   15158:	cmpb   $0x0,0x18(%rdx)
   1515c:	je     14bd0 <tparm@@Base+0x9f0>
   15162:	or     0x10(%rdx),%ecx
   15165:	jmpq   14bd0 <tparm@@Base+0x9f0>
   1516a:	mov    0x1d0(%r13),%eax
   15171:	test   %eax,%eax
   15173:	jle    15849 <tparm@@Base+0x1669>
   15179:	sub    $0x1,%eax
   1517c:	xor    %r8d,%r8d
   1517f:	mov    %eax,0x1d0(%r13)
   15186:	cltq   
   15188:	add    $0x8,%rax
   1518c:	shl    $0x4,%rax
   15190:	add    %r13,%rax
   15193:	cmpb   $0x0,0x18(%rax)
   15197:	jne    15569 <tparm@@Base+0x1389>
   1519d:	mov    0x1e8(%r13),%rdx
   151a4:	cmp    $0x1e,%ebp
   151a7:	mov    $0x1e,%eax
   151ac:	cmovge %rbp,%rax
   151b0:	mov    0x1f0(%r13),%rcx
   151b7:	lea    0x1(%rdx,%rax,1),%rax
   151bc:	cmp    0x1e0(%r13),%rax
   151c3:	ja     15655 <tparm@@Base+0x1475>
   151c9:	mov    0x1d8(%r13),%rdi
   151d0:	add    %rdx,%rdi
   151d3:	mov    $0x1,%esi
   151d8:	mov    $0xffffffffffffffff,%rdx
   151df:	xor    %eax,%eax
   151e1:	callq  d9b0 <_init@@Base+0x518>
   151e6:	mov    0x1e8(%r13),%rbx
   151ed:	mov    %rbx,%rdi
   151f0:	add    0x1d8(%r13),%rdi
   151f7:	callq  d610 <_init@@Base+0x178>
   151fc:	add    %rax,%rbx
   151ff:	mov    %rbx,0x1e8(%r13)
   15206:	movzbl (%r12),%eax
   1520b:	mov    %r12,%rbx
   1520e:	jmpq   14445 <tparm@@Base+0x265>
   15213:	mov    0x1d0(%r13),%eax
   1521a:	test   %eax,%eax
   1521c:	jle    1538f <tparm@@Base+0x11af>
   15222:	lea    -0x1(%rax),%ecx
   15225:	xor    %esi,%esi
   15227:	movslq %ecx,%rdx
   1522a:	mov    %ecx,0x1d0(%r13)
   15231:	add    $0x8,%rdx
   15235:	shl    $0x4,%rdx
   15239:	add    %r13,%rdx
   1523c:	cmpb   $0x0,0x18(%rdx)
   15240:	jne    15561 <tparm@@Base+0x1381>
   15246:	test   %ecx,%ecx
   15248:	je     1592f <tparm@@Base+0x174f>
   1524e:	sub    $0x2,%eax
   15251:	movslq %eax,%rdx
   15254:	mov    %eax,0x1d0(%r13)
   1525b:	add    $0x8,%rdx
   1525f:	shl    $0x4,%rdx
   15263:	add    %r13,%rdx
   15266:	cmpb   $0x0,0x18(%rdx)
   1526a:	je     154db <tparm@@Base+0x12fb>
   15270:	xor    %ecx,%ecx
   15272:	cmp    %esi,0x10(%rdx)
   15275:	setl   %cl
   15278:	jmpq   14bd0 <tparm@@Base+0x9f0>
   1527d:	movzbl 0x1(%r12),%eax
   15283:	lea    0x1(%r12),%rbx
   15288:	lea    -0x41(%rax),%edx
   1528b:	cmp    $0x19,%dl
   1528e:	jbe    1575a <tparm@@Base+0x157a>
   15294:	lea    -0x61(%rax),%edx
   15297:	cmp    $0x19,%dl
   1529a:	ja     14445 <tparm@@Base+0x265>
   152a0:	lea    -0x61(%rax),%edx
   152a3:	mov    0x1d0(%r13),%eax
   152aa:	test   %eax,%eax
   152ac:	jle    1586c <tparm@@Base+0x168c>
   152b2:	sub    $0x1,%eax
   152b5:	xor    %ecx,%ecx
   152b7:	mov    %eax,0x1d0(%r13)
   152be:	cltq   
   152c0:	add    $0x8,%rax
   152c4:	shl    $0x4,%rax
   152c8:	add    %r13,%rax
   152cb:	cmpb   $0x0,0x18(%rax)
   152cf:	je     152d4 <tparm@@Base+0x10f4>
   152d1:	mov    0x10(%rax),%ecx
   152d4:	movslq %edx,%rax
   152d7:	mov    %ecx,0x200(%r13,%rax,4)
   152df:	movzbl 0x1(%r12),%eax
   152e5:	jmpq   14445 <tparm@@Base+0x265>
   152ea:	mov    0x1d0(%r13),%ecx
   152f1:	test   %ecx,%ecx
   152f3:	jle    15639 <tparm@@Base+0x1459>
   152f9:	lea    -0x1(%rcx),%eax
   152fc:	movslq %eax,%rsi
   152ff:	mov    %eax,0x1d0(%r13)
   15306:	add    $0x8,%rsi
   1530a:	shl    $0x4,%rsi
   1530e:	add    %r13,%rsi
   15311:	cmpb   $0x0,0x18(%rsi)
   15315:	je     1546b <tparm@@Base+0x128b>
   1531b:	test   %eax,%eax
   1531d:	mov    0x10(%rsi),%esi
   15320:	je     15949 <tparm@@Base+0x1769>
   15326:	sub    $0x2,%ecx
   15329:	xor    %eax,%eax
   1532b:	movslq %ecx,%rdx
   1532e:	mov    %ecx,0x1d0(%r13)
   15335:	add    $0x8,%rdx
   15339:	shl    $0x4,%rdx
   1533d:	add    %r13,%rdx
   15340:	cmpb   $0x0,0x18(%rdx)
   15344:	je     15349 <tparm@@Base+0x1169>
   15346:	mov    0x10(%rdx),%eax
   15349:	test   %esi,%esi
   1534b:	je     1547f <tparm@@Base+0x129f>
   15351:	cltd   
   15352:	idiv   %esi
   15354:	mov    %eax,%esi
   15356:	jmpq   1547f <tparm@@Base+0x129f>
   1535b:	mov    %r12,%rbx
   1535e:	jmpq   14445 <tparm@@Base+0x265>
   15363:	test   %ecx,%ecx
   15365:	je     1444d <tparm@@Base+0x26d>
   1536b:	sub    $0x1,%ecx
   1536e:	mov    %rbx,%rax
   15371:	jmpq   14700 <tparm@@Base+0x520>
   15376:	shr    $0x1f,%ecx
   15379:	mov    0x215a60(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   15380:	addl   $0x1,(%rax)
   15383:	mov    0x1d0(%r13),%eax
   1538a:	jmpq   14bd0 <tparm@@Base+0x9f0>
   1538f:	mov    0x215a4a(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   15396:	xor    %ecx,%ecx
   15398:	addl   $0x1,(%rax)
   1539b:	jmp    15379 <tparm@@Base+0x1199>
   1539d:	add    $0x1,%ecx
   153a0:	mov    %rbx,%rax
   153a3:	jmpq   14700 <tparm@@Base+0x520>
   153a8:	add    $0x1,%ecx
   153ab:	mov    %rbx,%rax
   153ae:	jmpq   148a0 <tparm@@Base+0x6c0>
   153b3:	test   %ecx,%ecx
   153b5:	je     1444d <tparm@@Base+0x26d>
   153bb:	sub    $0x1,%ecx
   153be:	jmpq   148e1 <tparm@@Base+0x701>
   153c3:	mov    0x215a16(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   153ca:	addl   $0x1,(%rax)
   153cd:	mov    0x215a0c(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   153d4:	xor    %ecx,%ecx
   153d6:	addl   $0x1,(%rax)
   153d9:	mov    0x1d0(%r13),%eax
   153e0:	jmpq   14bd0 <tparm@@Base+0x9f0>
   153e5:	xor    %eax,%eax
   153e7:	jmpq   14757 <tparm@@Base+0x577>
   153ec:	mov    %r12,%rbx
   153ef:	jmpq   1444d <tparm@@Base+0x26d>
   153f4:	lea    -0x61(%rax),%edx
   153f7:	cmp    $0x19,%dl
   153fa:	ja     14445 <tparm@@Base+0x265>
   15400:	mov    0x1d0(%r13),%edx
   15407:	sub    $0x61,%eax
   1540a:	cmp    $0x13,%edx
   1540d:	jg     15572 <tparm@@Base+0x1392>
   15413:	cltq   
   15415:	mov    0x200(%r13,%rax,4),%ecx
   1541d:	jmpq   14b42 <tparm@@Base+0x962>
   15422:	test   %eax,%eax
   15424:	je     158b9 <tparm@@Base+0x16d9>
   1542a:	sub    $0x2,%ecx
   1542d:	xor    %edx,%edx
   1542f:	mov    %ecx,0x1d0(%r13)
   15436:	cmp    $0x13,%ecx
   15439:	jg     14f70 <tparm@@Base+0xd90>
   1543f:	movslq %ecx,%rax
   15442:	mov    %r12,%rbx
   15445:	add    $0x8,%rax
   15449:	shl    $0x4,%rax
   1544d:	add    %r13,%rax
   15450:	movb   $0x1,0x18(%rax)
   15454:	mov    %edx,0x10(%rax)
   15457:	lea    0x1(%rcx),%eax
   1545a:	mov    %eax,0x1d0(%r13)
   15461:	movzbl (%r12),%eax
   15466:	jmpq   14445 <tparm@@Base+0x265>
   1546b:	test   %eax,%eax
   1546d:	je     158a6 <tparm@@Base+0x16c6>
   15473:	sub    $0x2,%ecx
   15476:	xor    %esi,%esi
   15478:	mov    %ecx,0x1d0(%r13)
   1547f:	cmp    $0x13,%ecx
   15482:	jg     14f70 <tparm@@Base+0xd90>
   15488:	movslq %ecx,%rax
   1548b:	add    $0x1,%ecx
   1548e:	mov    %r12,%rbx
   15491:	add    $0x8,%rax
   15495:	mov    %ecx,0x1d0(%r13)
   1549c:	shl    $0x4,%rax
   154a0:	add    %r13,%rax
   154a3:	movb   $0x1,0x18(%rax)
   154a7:	mov    %esi,0x10(%rax)
   154aa:	movzbl (%r12),%eax
   154af:	jmpq   14445 <tparm@@Base+0x265>
   154b4:	neg    %ecx
   154b6:	jmpq   14bd0 <tparm@@Base+0x9f0>
   154bb:	xor    %ecx,%ecx
   154bd:	test   %esi,%esi
   154bf:	setne  %cl
   154c2:	jmpq   14bd0 <tparm@@Base+0x9f0>
   154c7:	shr    $0x1f,%ecx
   154ca:	jmpq   14bd0 <tparm@@Base+0x9f0>
   154cf:	xor    %ecx,%ecx
   154d1:	test   %esi,%esi
   154d3:	sete   %cl
   154d6:	jmpq   14bd0 <tparm@@Base+0x9f0>
   154db:	xor    %ecx,%ecx
   154dd:	test   %esi,%esi
   154df:	setg   %cl
   154e2:	jmpq   14bd0 <tparm@@Base+0x9f0>
   154e7:	mov    0x10(%rax),%eax
   154ea:	test   %eax,%eax
   154ec:	je     1488f <tparm@@Base+0x6af>
   154f2:	jmpq   15206 <tparm@@Base+0x1026>
   154f7:	mov    0x10(%rdx),%esi
   154fa:	jmpq   14d13 <tparm@@Base+0xb33>
   154ff:	mov    0x10(%rax),%r8d
   15503:	test   %r8d,%r8d
   15506:	setne  %sil
   1550a:	jmpq   14ca3 <tparm@@Base+0xac3>
   1550f:	mov    0x10(%rax),%esi
   15512:	jmpq   14c38 <tparm@@Base+0xa58>
   15517:	mov    0x10(%rdx),%ecx
   1551a:	jmpq   14b9f <tparm@@Base+0x9bf>
   1551f:	mov    0x10(%rdx),%esi
   15522:	jmpq   14eed <tparm@@Base+0xd0d>
   15527:	mov    0x10(%rdx),%esi
   1552a:	jmpq   14e83 <tparm@@Base+0xca3>
   1552f:	mov    0x10(%rdx),%ecx
   15532:	jmpq   14e1e <tparm@@Base+0xc3e>
   15537:	mov    0x10(%rax),%ebx
   1553a:	mov    $0x80,%eax
   1553f:	test   %ebx,%ebx
   15541:	cmove  %eax,%ebx
   15544:	jmpq   14db5 <tparm@@Base+0xbd5>
   15549:	mov    0x10(%rdx),%ecx
   1554c:	jmpq   15138 <tparm@@Base+0xf58>
   15551:	mov    0x10(%rdx),%ecx
   15554:	jmpq   150cd <tparm@@Base+0xeed>
   15559:	mov    0x10(%rdx),%ecx
   1555c:	jmpq   14fba <tparm@@Base+0xdda>
   15561:	mov    0x10(%rdx),%esi
   15564:	jmpq   15246 <tparm@@Base+0x1066>
   15569:	mov    0x10(%rax),%r8d
   1556d:	jmpq   1519d <tparm@@Base+0xfbd>
   15572:	mov    0x215867(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   15579:	addl   $0x1,(%rax)
   1557c:	movzbl 0x1(%r12),%eax
   15582:	jmpq   14445 <tparm@@Base+0x265>
   15587:	mov    0x1d0(%r13),%ecx
   1558e:	cmp    $0x13,%ecx
   15591:	jg     15572 <tparm@@Base+0x1392>
   15593:	movslq %ecx,%rax
   15596:	mov    0xa0(%rsp,%rdx,8),%rdx
   1559e:	add    $0x1,%ecx
   155a1:	add    $0x8,%rax
   155a5:	mov    %ecx,0x1d0(%r13)
   155ac:	shl    $0x4,%rax
   155b0:	add    %r13,%rax
   155b3:	movb   $0x1,0x18(%rax)
   155b7:	mov    %edx,0x10(%rax)
   155ba:	movzbl 0x1(%r12),%eax
   155c0:	jmpq   14445 <tparm@@Base+0x265>
   155c5:	mov    0xa0(%rsp),%rax
   155cd:	add    $0x1,%rax
   155d1:	cmpb   $0x0,0x2e(%rsp)
   155d6:	mov    %rax,0xa0(%rsp)
   155de:	je     1587d <tparm@@Base+0x169d>
   155e4:	cmpq   $0x0,0x58(%rsp)
   155ea:	mov    %eax,0x90(%r13)
   155f1:	jne    158cc <tparm@@Base+0x16ec>
   155f7:	mov    0xa8(%rsp),%rax
   155ff:	add    $0x1,%rax
   15603:	mov    %rax,0xa8(%rsp)
   1560b:	mov    %eax,0xa0(%r13)
   15612:	mov    %r12,%rbx
   15615:	movzbl (%r12),%eax
   1561a:	movb   $0x1,0x2f(%rsp)
   1561f:	jmpq   14445 <tparm@@Base+0x265>
   15624:	nopl   0x0(%rax)
   15628:	mov    0x2157b1(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   1562f:	xor    %edx,%edx
   15631:	addl   $0x2,(%rax)
   15634:	jmpq   1543f <tparm@@Base+0x125f>
   15639:	mov    0x2157a0(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   15640:	mov    0x215799(%rip),%rdi        # 22ade0 <boolnames@@Base+0x700>
   15647:	xor    %esi,%esi
   15649:	mov    (%rax),%eax
   1564b:	add    $0x2,%eax
   1564e:	mov    %eax,(%rdi)
   15650:	jmpq   1547f <tparm@@Base+0x129f>
   15655:	mov    0x1d8(%r13),%rdi
   1565c:	lea    (%rax,%rax,1),%rsi
   15660:	mov    %r8d,0x20(%rsp)
   15665:	mov    %rcx,0x10(%rsp)
   1566a:	mov    %rsi,0x1e0(%r13)
   15671:	callq  d5f8 <_init@@Base+0x160>
   15676:	test   %rax,%rax
   15679:	mov    %rax,0x1d8(%r13)
   15680:	je     159a8 <tparm@@Base+0x17c8>
   15686:	mov    0x1e8(%r13),%rdx
   1568d:	mov    %rax,%rdi
   15690:	mov    0x10(%rsp),%rcx
   15695:	mov    0x20(%rsp),%r8d
   1569a:	jmpq   151d0 <tparm@@Base+0xff0>
   1569f:	mov    0x1d8(%r13),%rdi
   156a6:	lea    (%rax,%rax,1),%rsi
   156aa:	mov    %rsi,0x1e0(%r13)
   156b1:	callq  d5f8 <_init@@Base+0x160>
   156b6:	test   %rax,%rax
   156b9:	mov    %rax,0x1d8(%r13)
   156c0:	je     159a8 <tparm@@Base+0x17c8>
   156c6:	mov    0x1e8(%r13),%rdx
   156cd:	mov    %rax,%rdi
   156d0:	mov    0x10(%rsp),%r8
   156d5:	jmpq   1496d <tparm@@Base+0x78d>
   156da:	mov    0x1d8(%r13),%rdi
   156e1:	lea    (%rdx,%rdx,1),%rsi
   156e5:	mov    %rsi,0x1e0(%r13)
   156ec:	callq  d5f8 <_init@@Base+0x160>
   156f1:	test   %rax,%rax
   156f4:	mov    %rax,0x1d8(%r13)
   156fb:	je     159a8 <tparm@@Base+0x17c8>
   15701:	mov    0x1e8(%r13),%rcx
   15708:	lea    0x1(%rcx),%rdx
   1570c:	jmpq   14dd4 <tparm@@Base+0xbf4>
   15711:	mov    0x1d8(%r13),%rdi
   15718:	lea    (%rdx,%rdx,1),%rsi
   1571c:	mov    %rsi,0x1e0(%r13)
   15723:	callq  d5f8 <_init@@Base+0x160>
   15728:	test   %rax,%rax
   1572b:	mov    %rax,0x1d8(%r13)
   15732:	je     159a8 <tparm@@Base+0x17c8>
   15738:	mov    0x1e8(%r13),%rcx
   1573f:	lea    0x1(%rcx),%rdx
   15743:	jmpq   14d68 <tparm@@Base+0xb88>
   15748:	mov    0x215691(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   1574f:	addl   $0x1,(%rax)
   15752:	movzbl (%rbx),%eax
   15755:	jmpq   14445 <tparm@@Base+0x265>
   1575a:	lea    -0x41(%rax),%edx
   1575d:	mov    0x1d0(%r13),%eax
   15764:	test   %eax,%eax
   15766:	jle    1585b <tparm@@Base+0x167b>
   1576c:	sub    $0x1,%eax
   1576f:	xor    %ecx,%ecx
   15771:	mov    %eax,0x1d0(%r13)
   15778:	cltq   
   1577a:	add    $0x8,%rax
   1577e:	shl    $0x4,%rax
   15782:	add    %r13,%rax
   15785:	cmpb   $0x0,0x18(%rax)
   15789:	je     1578e <tparm@@Base+0x15ae>
   1578b:	mov    0x10(%rax),%ecx
   1578e:	movslq %edx,%rax
   15791:	mov    %ecx,0x268(%r13,%rax,4)
   15799:	movzbl 0x1(%r12),%eax
   1579f:	jmpq   14445 <tparm@@Base+0x265>
   157a4:	mov    0x215635(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   157ab:	addl   $0x1,(%rax)
   157ae:	jmpq   15021 <tparm@@Base+0xe41>
   157b3:	mov    0x215626(%rip),%rcx        # 22ade0 <boolnames@@Base+0x700>
   157ba:	mov    $0xffffffff,%esi
   157bf:	movslq %eax,%rdx
   157c2:	addl   $0x1,(%rcx)
   157c5:	jmpq   15071 <tparm@@Base+0xe91>
   157ca:	mov    0x21560f(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   157d1:	mov    $0x80,%ebx
   157d6:	addl   $0x1,(%rax)
   157d9:	jmpq   14db5 <tparm@@Base+0xbd5>
   157de:	mov    0x2155fb(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   157e5:	addl   $0x1,(%rax)
   157e8:	jmpq   1488f <tparm@@Base+0x6af>
   157ed:	mov    0x2155ec(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   157f4:	lea    0x2160b9(%rip),%r8        # 22b8b4 <_nc_tparm_err@@Base+0x4>
   157fb:	addl   $0x1,(%rax)
   157fe:	jmpq   1492b <tparm@@Base+0x74b>
   15803:	mov    0x2155d6(%rip),%rcx        # 22ade0 <boolnames@@Base+0x700>
   1580a:	addl   $0x1,(%rcx)
   1580d:	mov    $0x1,%ecx
   15812:	jmpq   14bd9 <tparm@@Base+0x9f9>
   15817:	mov    0x2155c2(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   1581e:	mov    $0x1,%ecx
   15823:	addl   $0x1,(%rax)
   15826:	jmpq   15379 <tparm@@Base+0x1199>
   1582b:	mov    0x2155ae(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   15832:	lea    0x21607b(%rip),%rdi        # 22b8b4 <_nc_tparm_err@@Base+0x4>
   15839:	movslq %ebp,%rbx
   1583c:	addl   $0x1,(%rax)
   1583f:	callq  d610 <_init@@Base+0x178>
   15844:	jmpq   14ab5 <tparm@@Base+0x8d5>
   15849:	mov    0x215590(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   15850:	xor    %r8d,%r8d
   15853:	addl   $0x1,(%rax)
   15856:	jmpq   1519d <tparm@@Base+0xfbd>
   1585b:	mov    0x21557e(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   15862:	xor    %ecx,%ecx
   15864:	addl   $0x1,(%rax)
   15867:	jmpq   1578e <tparm@@Base+0x15ae>
   1586c:	mov    0x21556d(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   15873:	xor    %ecx,%ecx
   15875:	addl   $0x1,(%rax)
   15878:	jmpq   152d4 <tparm@@Base+0x10f4>
   1587d:	cmpq   $0x0,0x58(%rsp)
   15883:	jne    14b01 <tparm@@Base+0x921>
   15889:	addq   $0x1,0xa8(%rsp)
   15892:	mov    %r12,%rbx
   15895:	movb   $0x1,0x2f(%rsp)
   1589a:	jmpq   1444d <tparm@@Base+0x26d>
   1589f:	neg    %ecx
   158a1:	jmpq   15379 <tparm@@Base+0x1199>
   158a6:	mov    0x215533(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   158ad:	xor    %ecx,%ecx
   158af:	xor    %esi,%esi
   158b1:	addl   $0x1,(%rax)
   158b4:	jmpq   15488 <tparm@@Base+0x12a8>
   158b9:	mov    0x215520(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   158c0:	xor    %ecx,%ecx
   158c2:	xor    %edx,%edx
   158c4:	addl   $0x1,(%rax)
   158c7:	jmpq   1543f <tparm@@Base+0x125f>
   158cc:	movzbl 0x2e(%rsp),%ecx
   158d1:	movzbl (%r12),%eax
   158d6:	mov    %r12,%rbx
   158d9:	mov    %cl,0x2f(%rsp)
   158dd:	jmpq   14445 <tparm@@Base+0x265>
   158e2:	mov    0x2154f7(%rip),%rcx        # 22ade0 <boolnames@@Base+0x700>
   158e9:	addl   $0x1,(%rcx)
   158ec:	xor    %ecx,%ecx
   158ee:	jmpq   14a4f <tparm@@Base+0x86f>
   158f3:	mov    0xa8(%rsp),%rax
   158fb:	add    $0x1,%rax
   158ff:	cmpb   $0x0,0x2e(%rsp)
   15904:	mov    %rax,0xa8(%rsp)
   1590c:	je     14b01 <tparm@@Base+0x921>
   15912:	jmpq   1560b <tparm@@Base+0x142b>
   15917:	xor    %ecx,%ecx
   15919:	test   %esi,%esi
   1591b:	setne  %cl
   1591e:	jmpq   15379 <tparm@@Base+0x1199>
   15923:	xor    %ecx,%ecx
   15925:	test   %esi,%esi
   15927:	sete   %cl
   1592a:	jmpq   15379 <tparm@@Base+0x1199>
   1592f:	xor    %ecx,%ecx
   15931:	test   %esi,%esi
   15933:	setg   %cl
   15936:	jmpq   15379 <tparm@@Base+0x1199>
   1593b:	mov    0x21549e(%rip),%rax        # 22ade0 <boolnames@@Base+0x700>
   15942:	mov    %edi,(%rax)
   15944:	jmpq   14402 <tparm@@Base+0x222>
   15949:	mov    0x215490(%rip),%rcx        # 22ade0 <boolnames@@Base+0x700>
   15950:	addl   $0x1,(%rcx)
   15953:	xor    %ecx,%ecx
   15955:	jmpq   15349 <tparm@@Base+0x1169>
   1595a:	callq  d640 <_init@@Base+0x1a8>
   1595f:	mov    %esi,0x1d0(%r13)
   15966:	jmpq   143f9 <tparm@@Base+0x219>
   1596b:	mov    %r10d,0x38(%rsp)
   15970:	jmpq   1436a <tparm@@Base+0x18a>
   15975:	mov    %r11,%rdi
   15978:	mov    $0x1,%r14d
   1597e:	add    $0x8,%r11
   15982:	jmpq   14352 <tparm@@Base+0x172>
   15987:	mov    %r11,%rdi
   1598a:	mov    $0x1,%r14d
   15990:	add    $0x8,%r11
   15994:	mov    (%rdi),%rdi
   15997:	movq   $0x0,(%rsi,%rdx,8)
   1599f:	mov    %rdi,(%r12,%rdx,8)
   159a3:	jmpq   14359 <tparm@@Base+0x179>
   159a8:	lea    0x49d1(%rip),%rdi        # 1a380 <_fini@@Base+0x18>
   159af:	xor    %eax,%eax
   159b1:	callq  d858 <_init@@Base+0x3c0>
   159b6:	nopw   %cs:0x0(%rax,%rax,1)
