// TC_OUT backspace_until_column@@Base,0x6b2e6,0x6b308,0x0(0x4a0d6c),0x40(0x0(0x4ae710))

000000000006b2d0 <backspace_until_column@@Base>:
   6b2d0:	push   %rbx
   6b2d1:	mov    %edi,%ebx
   6b2d3:	nopl   0x0(%rax,%rax,1)
   6b2d8:	mov    0x443431(%rip),%rdx        # 4ae710 <curwin@@Base>
   6b2df:	mov    0x40(%rdx),%eax
   6b2e2:	cmp    %ebx,%eax
   6b2e4:	jle    6b30a <backspace_until_column@@Base+0x3a>
   6b2e6:	sub    $0x1,%eax
   6b2e9:	testb  $0x40,0x435a7c(%rip)        # 4a0d6c <State@@Base>
   6b2f0:	mov    %ebx,%edi
   6b2f2:	mov    %eax,0x40(%rdx)
   6b2f5:	je     6b310 <backspace_until_column@@Base+0x40>
   6b2f7:	callq  6b050 <replace_push@@Base+0x390>
   6b2fc:	mov    0x44340d(%rip),%rdx        # 4ae710 <curwin@@Base>
   6b303:	mov    0x40(%rdx),%eax
   6b306:	cmp    %ebx,%eax
   6b308:	jg     6b2e6 <backspace_until_column@@Base+0x16>
   6b30a:	pop    %rbx
   6b30b:	retq   
   6b30c:	nopl   0x0(%rax)
   6b310:	callq  67d50 <ex_loadkeymap@@Base+0xe70>
   6b315:	test   %eax,%eax
   6b317:	jne    6b2d8 <backspace_until_column@@Base+0x8>
   6b319:	pop    %rbx
   6b31a:	retq   
   6b31b:	nopl   0x0(%rax,%rax,1)
   6b320:	sub    $0x8,%rsp
   6b324:	mov    0x442bd6(%rip),%edi        # 4adf00 <compl_cont_status@@Base>
   6b32a:	and    $0x1,%edi
   6b32d:	cmovne 0x442bd4(%rip),%edi        # 4adf08 <compl_length@@Base>
   6b334:	add    0x43653e(%rip),%edi        # 4a1878 <stderr@@GLIBC_2.2.5+0x778>
   6b33a:	callq  6b2d0 <backspace_until_column@@Base>
   6b33f:	callq  1229c0 <changed_cline_bef_curs@@Base>
   6b344:	callq  7b8a0 <dict_alloc@@Base>
   6b349:	mov    $0x3c,%edi
   6b34e:	mov    %rax,%rsi
   6b351:	add    $0x8,%rsp
   6b355:	jmpq   8b1e0 <set_vim_var_dict@@Base>
   6b35a:	nopw   0x0(%rax,%rax,1)
   6b360:	push   %r15
   6b362:	push   %r14
   6b364:	push   %r13
   6b366:	push   %r12
   6b368:	mov    %r8,%r13
   6b36b:	push   %rbp
   6b36c:	push   %rbx
   6b36d:	mov    %rdi,%rbp
   6b370:	mov    %r9d,%ebx
   6b373:	sub    $0x28,%rsp
   6b377:	test   %r9d,%r9d
   6b37a:	cmove  0x421847(%rip),%ebx        # 48cbc8 <__data_start@@Base+0x3bc8>
   6b381:	mov    %esi,0x18(%rsp)
   6b385:	mov    %edx,0x1c(%rsp)
   6b389:	mov    %rcx,0x10(%rsp)
   6b38e:	callq  1d1d90 <ui_breakcheck@@Base>
   6b393:	mov    0x442867(%rip),%eax        # 4adc00 <got_int@@Base>
   6b399:	test   %eax,%eax
   6b39b:	jne    6b550 <backspace_until_column@@Base+0x280>
   6b3a1:	mov    0x18(%rsp),%r9d
   6b3a6:	test   %r9d,%r9d
   6b3a9:	js     6b580 <backspace_until_column@@Base+0x2b0>
   6b3af:	mov    0x68(%rsp),%r8d
   6b3b4:	mov    0x43652d(%rip),%r14        # 4a18e8 <stderr@@GLIBC_2.2.5+0x7e8>
   6b3bb:	test   %r8d,%r8d
   6b3be:	jne    6b418 <backspace_until_column@@Base+0x148>
   6b3c0:	test   %r14,%r14
   6b3c3:	je     6b418 <backspace_until_column@@Base+0x148>
   6b3c5:	movslq 0x18(%rsp),%rax
   6b3ca:	mov    %r14,%r15
   6b3cd:	mov    %rax,0x8(%rsp)
   6b3d2:	jmp    6b3dd <backspace_until_column@@Base+0x10d>
   6b3d4:	nopl   0x0(%rax)
   6b3d8:	cmp    %r15,%r14
   6b3db:	je     6b418 <backspace_until_column@@Base+0x148>
   6b3dd:	testb  $0x1,0x48(%r15)
   6b3e2:	jne    6b40c <backspace_until_column@@Base+0x13c>
   6b3e4:	mov    0x10(%r15),%r12
   6b3e8:	mov    0x8(%rsp),%rdx
   6b3ed:	mov    %rbp,%rsi
   6b3f0:	mov    %r12,%rdi
   6b3f3:	callq  4ec90 <_init@@Base+0xa0>
   6b3f8:	test   %eax,%eax
   6b3fa:	jne    6b40c <backspace_until_column@@Base+0x13c>
   6b3fc:	mov    0x8(%rsp),%rax
   6b401:	cmpb   $0x0,(%r12,%rax,1)
   6b406:	je     6b757 <backspace_until_column@@Base+0x487>
   6b40c:	mov    (%r15),%r15
   6b40f:	test   %r15,%r15
   6b412:	jne    6b3d8 <backspace_until_column@@Base+0x108>
   6b414:	nopl   0x0(%rax)
   6b418:	callq  67560 <ex_loadkeymap@@Base+0x680>
   6b41d:	mov    $0x50,%edi
   6b422:	callq  121cc0 <alloc_clear@@Base>
   6b427:	test   %rax,%rax
   6b42a:	mov    %rax,%r12
   6b42d:	je     6b550 <backspace_until_column@@Base+0x280>
   6b433:	mov    0x60(%rsp),%eax
   6b437:	mov    0x18(%rsp),%esi
   6b43b:	mov    %rbp,%rdi
   6b43e:	and    $0x1,%eax
   6b441:	sub    $0x1,%eax
   6b444:	mov    %eax,0x4c(%r12)
   6b449:	callq  11f330 <vim_strnsave@@Base>
   6b44e:	test   %rax,%rax
   6b451:	mov    %rax,0x10(%r12)
   6b456:	je     6b548 <backspace_until_column@@Base+0x278>
   6b45c:	movzbl 0x1c(%rsp),%eax
   6b461:	mov    0x10(%rsp),%rdi
   6b466:	test   %rdi,%rdi
   6b469:	mov    %al,0x18(%r12)
   6b46e:	je     6b6b0 <backspace_until_column@@Base+0x3e0>
   6b474:	mov    0x436465(%rip),%rax        # 4a18e0 <stderr@@GLIBC_2.2.5+0x7e0>
   6b47b:	test   %rax,%rax
   6b47e:	je     6b499 <backspace_until_column@@Base+0x1c9>
   6b480:	mov    0x40(%rax),%rbp
   6b484:	test   %rbp,%rbp
   6b487:	je     6b499 <backspace_until_column@@Base+0x1c9>
   6b489:	mov    %rbp,%rsi
   6b48c:	callq  4eef0 <_init@@Base+0x300>
   6b491:	test   %eax,%eax
   6b493:	je     6b598 <backspace_until_column@@Base+0x2c8>
   6b499:	mov    0x10(%rsp),%rdi
   6b49e:	callq  11f220 <vim_strsave@@Base>
   6b4a3:	orl    $0x2,0x60(%rsp)
   6b4a8:	mov    %rax,0x40(%r12)
   6b4ad:	mov    0x60(%rsp),%eax
   6b4b1:	xor    %ebp,%ebp
   6b4b3:	test   %r13,%r13
   6b4b6:	mov    %eax,0x48(%r12)
   6b4bb:	je     6b4da <backspace_until_column@@Base+0x20a>
   6b4bd:	mov    0x0(%r13,%rbp,1),%rdi
   6b4c2:	test   %rdi,%rdi
   6b4c5:	je     6b4d0 <backspace_until_column@@Base+0x200>
   6b4c7:	cmpb   $0x0,(%rdi)
   6b4ca:	jne    6b568 <backspace_until_column@@Base+0x298>
   6b4d0:	add    $0x8,%rbp
   6b4d4:	cmp    $0x20,%rbp
   6b4d8:	jne    6b4bd <backspace_until_column@@Base+0x1ed>
   6b4da:	cmpq   $0x0,0x436406(%rip)        # 4a18e8 <stderr@@GLIBC_2.2.5+0x7e8>
   6b4e2:	je     6b6d0 <backspace_until_column@@Base+0x400>
   6b4e8:	cmp    $0x1,%ebx
   6b4eb:	je     6b688 <backspace_until_column@@Base+0x3b8>
   6b4f1:	mov    0x4363e8(%rip),%rax        # 4a18e0 <stderr@@GLIBC_2.2.5+0x7e0>
   6b4f8:	mov    0x8(%rax),%rdx
   6b4fc:	mov    %rax,(%r12)
   6b500:	mov    %rdx,0x8(%r12)
   6b505:	mov    %r12,0x8(%rax)
   6b509:	mov    0x8(%r12),%rax
   6b50e:	test   %rax,%rax
   6b511:	je     6b6e1 <backspace_until_column@@Base+0x411>
   6b517:	mov    %r12,(%rax)
   6b51a:	mov    0x4363a0(%rip),%edi        # 4a18c0 <stderr@@GLIBC_2.2.5+0x7c0>
   6b520:	mov    %r12,0x4363b9(%rip)        # 4a18e0 <stderr@@GLIBC_2.2.5+0x7e0>
   6b527:	test   %edi,%edi
   6b529:	je     6b534 <backspace_until_column@@Base+0x264>
   6b52b:	mov    0x60(%rsp),%ebx
   6b52f:	and    $0x1,%ebx
   6b532:	je     6b5a8 <backspace_until_column@@Base+0x2d8>
   6b534:	mov    $0x1,%eax
   6b539:	add    $0x28,%rsp
   6b53d:	pop    %rbx
   6b53e:	pop    %rbp
   6b53f:	pop    %r12
   6b541:	pop    %r13
   6b543:	pop    %r14
   6b545:	pop    %r15
   6b547:	retq   
   6b548:	mov    %r12,%rdi
   6b54b:	callq  11c7f0 <vim_free@@Base>
   6b550:	add    $0x28,%rsp
   6b554:	xor    %eax,%eax
   6b556:	pop    %rbx
   6b557:	pop    %rbp
   6b558:	pop    %r12
   6b55a:	pop    %r13
   6b55c:	pop    %r14
   6b55e:	pop    %r15
   6b560:	retq   
   6b561:	nopl   0x0(%rax)
   6b568:	callq  11f220 <vim_strsave@@Base>
   6b56d:	mov    %rax,0x20(%r12,%rbp,1)
   6b572:	jmpq   6b4d0 <backspace_until_column@@Base+0x200>
   6b577:	nopw   0x0(%rax,%rax,1)
   6b580:	mov    %rbp,%rdi
   6b583:	callq  4ed80 <_init@@Base+0x190>
   6b588:	mov    %eax,0x18(%rsp)
   6b58c:	jmpq   6b3af <backspace_until_column@@Base+0xdf>
   6b591:	nopl   0x0(%rax)
   6b598:	mov    %rbp,0x40(%r12)
   6b59d:	jmpq   6b4ad <backspace_until_column@@Base+0x1dd>
   6b5a2:	nopw   0x0(%rax,%rax,1)
   6b5a8:	mov    0x436319(%rip),%rbp        # 4a18c8 <stderr@@GLIBC_2.2.5+0x7c8>
   6b5af:	mov    0x10(%r12),%r13
   6b5b4:	test   %rbp,%rbp
   6b5b7:	je     6b76a <backspace_until_column@@Base+0x49a>
   6b5bd:	movzbl 0x0(%rbp),%eax
   6b5c1:	test   %al,%al
   6b5c3:	je     6b607 <backspace_until_column@@Base+0x337>
   6b5c5:	mov    0x442719(%rip),%esi        # 4adce4 <has_mbyte@@Base>
   6b5cb:	test   %esi,%esi
   6b5cd:	jne    6b640 <backspace_until_column@@Base+0x370>
   6b5cf:	movzbl 0x0(%r13),%r14d
   6b5d4:	movzbl %al,%ebx
   6b5d7:	cmp    %r14d,%ebx
   6b5da:	setne  %al
   6b5dd:	cmpb   $0x0,0x18(%r12)
   6b5e3:	jne    6b620 <backspace_until_column@@Base+0x350>
   6b5e5:	test   %al,%al
   6b5e7:	jne    6b6f0 <backspace_until_column@@Base+0x420>
   6b5ed:	mov    0x4426f1(%rip),%ecx        # 4adce4 <has_mbyte@@Base>
   6b5f3:	test   %ecx,%ecx
   6b5f5:	jne    6b660 <backspace_until_column@@Base+0x390>
   6b5f7:	add    $0x1,%rbp
   6b5fb:	movzbl 0x0(%rbp),%eax
   6b5ff:	add    $0x1,%r13
   6b603:	test   %al,%al
   6b605:	jne    6b5c5 <backspace_until_column@@Base+0x2f5>
   6b607:	movl   $0x0,0x4362a3(%rip)        # 4a18b4 <stderr@@GLIBC_2.2.5+0x7b4>
   6b611:	jmpq   6b534 <backspace_until_column@@Base+0x264>
   6b616:	nopw   %cs:0x0(%rax,%rax,1)
   6b620:	mov    %ebx,%edi
   6b622:	callq  60b60 <vim_tolower@@Base>
   6b627:	mov    %r14d,%edi
   6b62a:	mov    %eax,%ebx
   6b62c:	callq  60b60 <vim_tolower@@Base>
   6b631:	cmp    %eax,%ebx
   6b633:	setne  %al
   6b636:	jmp    6b5e5 <backspace_until_column@@Base+0x315>
   6b638:	nopl   0x0(%rax,%rax,1)
   6b640:	mov    %rbp,%rdi
   6b643:	callq  *0x4359bf(%rip)        # 4a1008 <mb_ptr2char@@Base>
   6b649:	mov    %r13,%rdi
   6b64c:	mov    %eax,%ebx
   6b64e:	callq  *0x4359b4(%rip)        # 4a1008 <mb_ptr2char@@Base>
   6b654:	mov    %eax,%r14d
   6b657:	jmpq   6b5d7 <backspace_until_column@@Base+0x307>
   6b65c:	nopl   0x0(%rax)
   6b660:	mov    %rbp,%rdi
   6b663:	callq  *0x4359df(%rip)        # 4a1048 <mb_ptr2len@@Base>
   6b669:	mov    0x442675(%rip),%edx        # 4adce4 <has_mbyte@@Base>
   6b66f:	cltq   
   6b671:	add    %rax,%rbp
   6b674:	mov    $0x1,%eax
   6b679:	test   %edx,%edx
   6b67b:	jne    6b6c0 <backspace_until_column@@Base+0x3f0>
   6b67d:	add    %rax,%r13
   6b680:	jmpq   6b5bd <backspace_until_column@@Base+0x2ed>
   6b685:	nopl   (%rax)
   6b688:	mov    0x436251(%rip),%rdx        # 4a18e0 <stderr@@GLIBC_2.2.5+0x7e0>
   6b68f:	mov    (%rdx),%rax
   6b692:	mov    %rdx,0x8(%r12)
   6b697:	test   %rax,%rax
   6b69a:	mov    %rax,(%r12)
   6b69e:	jne    6b505 <backspace_until_column@@Base+0x235>
   6b6a4:	mov    %rdx,%rax
   6b6a7:	jmpq   6b50e <backspace_until_column@@Base+0x23e>
   6b6ac:	nopl   0x0(%rax)
   6b6b0:	movq   $0x0,0x40(%r12)
   6b6b9:	jmpq   6b4ad <backspace_until_column@@Base+0x1dd>
   6b6be:	xchg   %ax,%ax
   6b6c0:	mov    %r13,%rdi
   6b6c3:	callq  *0x43597f(%rip)        # 4a1048 <mb_ptr2len@@Base>
   6b6c9:	cltq   
   6b6cb:	jmp    6b67d <backspace_until_column@@Base+0x3ad>
   6b6cd:	nopl   (%rax)
   6b6d0:	movq   $0x0,0x8(%r12)
   6b6d9:	movq   $0x0,(%r12)
   6b6e1:	mov    %r12,0x436200(%rip)        # 4a18e8 <stderr@@GLIBC_2.2.5+0x7e8>
   6b6e8:	jmpq   6b51a <backspace_until_column@@Base+0x24a>
   6b6ed:	nopl   (%rax)
   6b6f0:	cmpb   $0x0,0x0(%rbp)
   6b6f4:	je     6b607 <backspace_until_column@@Base+0x337>
   6b6fa:	movb   $0x0,0x0(%rbp)
   6b6fe:	mov    0x44300b(%rip),%rax        # 4ae710 <curwin@@Base>
   6b705:	mov    0x43616d(%rip),%ebx        # 4a1878 <stderr@@GLIBC_2.2.5+0x778>
   6b70b:	mov    0x40(%rax),%ebp
   6b70e:	callq  6b320 <backspace_until_column@@Base+0x50>
   6b713:	mov    0x442ff6(%rip),%rax        # 4ae710 <curwin@@Base>
   6b71a:	mov    $0x0,%edx
   6b71f:	mov    0x40(%rax),%eax
   6b722:	sub    0x436150(%rip),%eax        # 4a1878 <stderr@@GLIBC_2.2.5+0x778>
   6b728:	cmovs  %edx,%eax
   6b72b:	cltq   
   6b72d:	add    0x436194(%rip),%rax        # 4a18c8 <stderr@@GLIBC_2.2.5+0x7c8>
   6b734:	mov    %rax,%rdi
   6b737:	callq  111520 <ins_bytes@@Base>
   6b73c:	callq  ec9a0 <char_avail@@Base>
   6b741:	test   %eax,%eax
   6b743:	je     6b761 <backspace_until_column@@Base+0x491>
   6b745:	cmp    %ebx,%ebp
   6b747:	jg     6b607 <backspace_until_column@@Base+0x337>
   6b74d:	callq  6b320 <backspace_until_column@@Base+0x50>
   6b752:	jmpq   6b607 <backspace_until_column@@Base+0x337>
   6b757:	mov    $0x2,%eax
   6b75c:	jmpq   6b539 <backspace_until_column@@Base+0x269>
   6b761:	xor    %edi,%edi
   6b763:	callq  67a40 <ex_loadkeymap@@Base+0xb60>
   6b768:	jmp    6b745 <backspace_until_column@@Base+0x475>
   6b76a:	mov    %r13,%rdi
   6b76d:	callq  11f220 <vim_strsave@@Base>
   6b772:	test   %rax,%rax
   6b775:	mov    %rax,0x43614c(%rip)        # 4a18c8 <stderr@@GLIBC_2.2.5+0x7c8>
   6b77c:	je     6b534 <backspace_until_column@@Base+0x264>
   6b782:	mov    0x442f87(%rip),%rax        # 4ae710 <curwin@@Base>
   6b789:	mov    0x4360e9(%rip),%ebp        # 4a1878 <stderr@@GLIBC_2.2.5+0x778>
   6b78f:	mov    0x40(%rax),%r12d
   6b793:	callq  6b320 <backspace_until_column@@Base+0x50>
   6b798:	mov    0x442f71(%rip),%rax        # 4ae710 <curwin@@Base>
   6b79f:	mov    0x40(%rax),%eax
   6b7a2:	sub    0x4360d0(%rip),%eax        # 4a1878 <stderr@@GLIBC_2.2.5+0x778>
   6b7a8:	cmovs  %ebx,%eax
   6b7ab:	cltq   
   6b7ad:	add    0x436114(%rip),%rax        # 4a18c8 <stderr@@GLIBC_2.2.5+0x7c8>
   6b7b4:	mov    %rax,%rdi
   6b7b7:	callq  111520 <ins_bytes@@Base>
   6b7bc:	callq  ec9a0 <char_avail@@Base>
   6b7c1:	test   %eax,%eax
   6b7c3:	je     6b7d3 <backspace_until_column@@Base+0x503>
   6b7c5:	cmp    %ebp,%r12d
   6b7c8:	jg     6b607 <backspace_until_column@@Base+0x337>
   6b7ce:	jmpq   6b74d <backspace_until_column@@Base+0x47d>
   6b7d3:	xor    %edi,%edi
   6b7d5:	callq  67a40 <ex_loadkeymap@@Base+0xb60>
   6b7da:	jmp    6b7c5 <backspace_until_column@@Base+0x4f5>
   6b7dc:	nopl   0x0(%rax)
   6b7e0:	push   %r15
   6b7e2:	push   %r14
   6b7e4:	mov    %edx,%r15d
   6b7e7:	push   %r13
   6b7e9:	push   %r12
   6b7eb:	mov    %rsi,%r13
   6b7ee:	push   %rbp
   6b7ef:	push   %rbx
   6b7f0:	mov    %edi,%r12d
   6b7f3:	mov    $0x1,%ebx
   6b7f8:	mov    $0x1,%r14d
   6b7fe:	sub    $0x8,%rsp
   6b802:	test   %edi,%edi
   6b804:	mov    0x4213be(%rip),%ebp        # 48cbc8 <__data_start@@Base+0x3bc8>
   6b80a:	jle    6b84a <backspace_until_column@@Base+0x57a>
   6b80c:	nopl   0x0(%rax)
   6b810:	mov    -0x8(%r13,%rbx,8),%rdi
   6b815:	pushq  $0x0
   6b817:	xor    %ecx,%ecx
   6b819:	pushq  $0x0
   6b81b:	mov    %ebp,%r9d
   6b81e:	xor    %r8d,%r8d
   6b821:	mov    %r15d,%edx
   6b824:	mov    $0xffffffff,%esi
   6b829:	callq  6b360 <backspace_until_column@@Base+0x90>
   6b82e:	cmp    $0x1,%eax
   6b831:	cmove  %r14d,%ebp
   6b835:	cmp    %ebx,%r12d
   6b838:	pop    %rdx
   6b839:	setg   %dl
   6b83c:	test   %eax,%eax
   6b83e:	setne  %al
   6b841:	add    $0x1,%rbx
   6b845:	test   %al,%dl
   6b847:	pop    %rcx
   6b848:	jne    6b810 <backspace_until_column@@Base+0x540>
   6b84a:	add    $0x8,%rsp
   6b84e:	mov    %r13,%rsi
   6b851:	mov    %r12d,%edi
   6b854:	pop    %rbx
   6b855:	pop    %rbp
   6b856:	pop    %r12
   6b858:	pop    %r13
   6b85a:	pop    %r14
   6b85c:	pop    %r15
   6b85e:	jmpq   11bca0 <FreeWild@@Base>
   6b863:	nopl   (%rax)
   6b866:	nopw   %cs:0x0(%rax,%rax,1)
