// TC_OUT
0000000000ebd4e0 <tree_search_key>:
  ebd4e0:	push   %rbp
  ebd4e1:	mov    %rsp,%rbp
  ebd4e4:	push   %r15
  ebd4e6:	mov    %rdi,%r15
  ebd4e9:	push   %r14
  ebd4eb:	push   %r13
  ebd4ed:	push   %r12
  ebd4ef:	mov    %rdx,%r12
  ebd4f2:	push   %rbx
  ebd4f3:	lea    0x8(%rdi),%rbx
  ebd4f7:	sub    $0x38,%rsp
  ebd4fb:	mov    (%rdi),%r14
  ebd4fe:	mov    %rsi,-0x38(%rbp)
  ebd502:	mov    %rcx,-0x60(%rbp)
  ebd506:	mov    %r8d,-0x54(%rbp)
  ebd50a:	mov    %rbx,(%rdx)
  ebd50d:	cmp    %rbx,%r14
  ebd510:	je     ebd7d2 <tree_search_key+0x2f2>
  ebd516:	mov    %r8d,%ecx
  ebd519:	mov    $0x1,%eax
  ebd51e:	mov    %r9,%r13
  ebd521:	shl    %cl,%rax
  ebd524:	mov    %rax,%rdx
  ebd527:	mov    %rax,%rcx
  ebd52a:	and    $0x8,%edx
  ebd52d:	and    $0xc0,%ecx
  ebd533:	test   $0x13,%al
  ebd535:	jne    ebd5f0 <tree_search_key+0x110>
  ebd53b:	test   %rdx,%rdx
  ebd53e:	jne    ebd690 <tree_search_key+0x1b0>
  ebd544:	cmp    $0x7,%r8d
  ebd548:	ja     ebd878 <tree_search_key+0x398>
  ebd54e:	test   %rcx,%rcx
  ebd551:	movq   $0x0,-0x48(%rbp)
  ebd559:	movq   $0x0,-0x50(%rbp)
  ebd561:	movq   $0x0,-0x40(%rbp)
  ebd569:	je     ebd973 <tree_search_key+0x493>
  ebd56f:	mov    %r12,%rax
  ebd572:	mov    %r14,%r15
  ebd575:	mov    %rbx,%r12
  ebd578:	mov    %rdi,%r14
  ebd57b:	mov    %rax,%rbx
  ebd57e:	jmp    ebd591 <tree_search_key+0xb1>
  ebd580:	mov    %rbx,-0x48(%rbp)
  ebd584:	mov    0x8(%r15),%r15
  ebd588:	mov    %rbx,-0x50(%rbp)
  ebd58c:	cmp    %r15,%r12
  ebd58f:	je     ebd5cf <tree_search_key+0xef>
  ebd591:	add    $0x8,%rbx
  ebd595:	mov    %r15,(%rbx)
  ebd598:	mov    0x220(%r14),%eax
  ebd59f:	mov    0x240(%r14),%r10
  ebd5a6:	mov    %eax,%esi
  ebd5a8:	add    %r15,%rsi
  ebd5ab:	test   %eax,%eax
  ebd5ad:	jne    ebd5b3 <tree_search_key+0xd3>
  ebd5af:	mov    0x18(%r15),%rsi
  ebd5b3:	mov    -0x38(%rbp),%rdx
  ebd5b7:	mov    %r13,%rdi
  ebd5ba:	callq  *%r10
  ebd5bd:	test   %eax,%eax
  ebd5bf:	je     ebd580 <tree_search_key+0xa0>
  ebd5c1:	js     ebd584 <tree_search_key+0xa4>
  ebd5c3:	mov    (%r15),%r15
  ebd5c6:	mov    %rbx,-0x40(%rbp)
  ebd5ca:	cmp    %r15,%r12
  ebd5cd:	jne    ebd591 <tree_search_key+0xb1>
  ebd5cf:	mov    %r14,%r15
  ebd5d2:	mov    -0x54(%rbp),%eax
  ebd5d5:	cmp    $0x7,%eax
  ebd5d8:	ja     ebd678 <tree_search_key+0x198>
  ebd5de:	mov    %eax,%edx
  ebd5e0:	lea    0x70900d(%rip),%rax        # 15c65f4 <__func__.11922+0xe>
  ebd5e7:	movslq (%rax,%rdx,4),%rdx
  ebd5eb:	add    %rdx,%rax
  ebd5ee:	jmpq   *%rax
  ebd5f0:	cmpl   $0x7,-0x54(%rbp)
  ebd5f4:	ja     ebd7ef <tree_search_key+0x30f>
  ebd5fa:	mov    %r12,%rax
  ebd5fd:	mov    %r14,%r15
  ebd600:	mov    %rbx,%r12
  ebd603:	movq   $0x0,-0x48(%rbp)
  ebd60b:	movq   $0x0,-0x50(%rbp)
  ebd613:	mov    %rax,%rbx
  ebd616:	movq   $0x0,-0x40(%rbp)
  ebd61e:	mov    %rdi,%r14
  ebd621:	jmp    ebd638 <tree_search_key+0x158>
  ebd623:	nopl   0x0(%rax,%rax,1)
  ebd628:	mov    %rbx,-0x48(%rbp)
  ebd62c:	mov    (%r15),%r15
  ebd62f:	mov    %rbx,-0x40(%rbp)
  ebd633:	cmp    %r15,%r12
  ebd636:	je     ebd5cf <tree_search_key+0xef>
  ebd638:	add    $0x8,%rbx
  ebd63c:	mov    %r15,(%rbx)
  ebd63f:	mov    0x220(%r14),%eax
  ebd646:	mov    0x240(%r14),%r10
  ebd64d:	mov    %eax,%esi
  ebd64f:	add    %r15,%rsi
  ebd652:	test   %eax,%eax
  ebd654:	jne    ebd65a <tree_search_key+0x17a>
  ebd656:	mov    0x18(%r15),%rsi
  ebd65a:	mov    -0x38(%rbp),%rdx
  ebd65e:	mov    %r13,%rdi
  ebd661:	callq  *%r10
  ebd664:	test   %eax,%eax
  ebd666:	je     ebd628 <tree_search_key+0x148>
  ebd668:	jns    ebd62c <tree_search_key+0x14c>
  ebd66a:	mov    0x8(%r15),%r15
  ebd66e:	mov    %rbx,-0x50(%rbp)
  ebd672:	jmp    ebd633 <tree_search_key+0x153>
  ebd674:	nopl   0x0(%rax)
  ebd678:	add    $0x38,%rsp
  ebd67c:	xor    %eax,%eax
  ebd67e:	pop    %rbx
  ebd67f:	pop    %r12
  ebd681:	pop    %r13
  ebd683:	pop    %r14
  ebd685:	pop    %r15
  ebd687:	pop    %rbp
  ebd688:	retq   
  ebd689:	nopl   0x0(%rax)
  ebd690:	cmpl   $0x7,-0x54(%rbp)
  ebd694:	movq   $0x0,-0x50(%rbp)
  ebd69c:	movq   $0x0,-0x40(%rbp)
  ebd6a4:	ja     ebd904 <tree_search_key+0x424>
  ebd6aa:	add    $0x8,%r12
  ebd6ae:	mov    %r14,(%r12)
  ebd6b2:	mov    0x220(%r15),%eax
  ebd6b9:	mov    0x240(%r15),%rcx
  ebd6c0:	test   %eax,%eax
  ebd6c2:	lea    (%r14,%rax,1),%rsi
  ebd6c6:	jne    ebd6cc <tree_search_key+0x1ec>
  ebd6c8:	mov    0x18(%r14),%rsi
  ebd6cc:	mov    -0x38(%rbp),%rdx
  ebd6d0:	mov    %r13,%rdi
  ebd6d3:	callq  *%rcx
  ebd6d5:	mov    (%r14),%rdx
  ebd6d8:	test   %eax,%eax
  ebd6da:	cmovle 0x8(%r14),%rdx
  ebd6df:	mov    -0x40(%rbp),%rcx
  ebd6e3:	mov    -0x50(%rbp),%rax
  ebd6e7:	cmovg  %r12,%rcx
  ebd6eb:	cmovle %r12,%rax
  ebd6ef:	cmp    %rdx,%rbx
  ebd6f2:	mov    %rcx,-0x40(%rbp)
  ebd6f6:	mov    %rdx,%r14
  ebd6f9:	mov    %rax,-0x50(%rbp)
  ebd6fd:	jne    ebd6aa <tree_search_key+0x1ca>
  ebd6ff:	movq   $0x0,-0x48(%rbp)
  ebd707:	jmpq   ebd5d2 <tree_search_key+0xf2>
  ebd70c:	nopl   0x0(%rax)
  ebd710:	mov    -0x48(%rbp),%rax
  ebd714:	mov    -0x60(%rbp),%rcx
  ebd718:	test   %rax,%rax
  ebd71b:	cmove  -0x50(%rbp),%rax
  ebd720:	mov    %rax,-0x50(%rbp)
  ebd724:	mov    %rax,(%rcx)
  ebd727:	cmpq   $0x0,-0x50(%rbp)
  ebd72c:	je     ebd678 <tree_search_key+0x198>
  ebd732:	mov    0x220(%r15),%eax
  ebd739:	test   %eax,%eax
  ebd73b:	je     ebd7b8 <tree_search_key+0x2d8>
  ebd73d:	mov    -0x50(%rbp),%rcx
  ebd741:	add    (%rcx),%rax
  ebd744:	add    $0x38,%rsp
  ebd748:	pop    %rbx
  ebd749:	pop    %r12
  ebd74b:	pop    %r13
  ebd74d:	pop    %r14
  ebd74f:	pop    %r15
  ebd751:	pop    %rbp
  ebd752:	retq   
  ebd753:	nopl   0x0(%rax,%rax,1)
  ebd758:	mov    -0x60(%rbp),%rax
  ebd75c:	mov    -0x50(%rbp),%rcx
  ebd760:	mov    %rcx,(%rax)
  ebd763:	jmp    ebd727 <tree_search_key+0x247>
  ebd765:	nopl   (%rax)
  ebd768:	mov    -0x40(%rbp),%rax
  ebd76c:	mov    -0x60(%rbp),%rcx
  ebd770:	mov    %rax,-0x50(%rbp)
  ebd774:	mov    %rax,(%rcx)
  ebd777:	jmp    ebd727 <tree_search_key+0x247>
  ebd779:	nopl   0x0(%rax)
  ebd780:	mov    -0x48(%rbp),%rax
  ebd784:	mov    -0x60(%rbp),%rcx
  ebd788:	test   %rax,%rax
  ebd78b:	cmove  -0x40(%rbp),%rax
  ebd790:	mov    %rax,-0x50(%rbp)
  ebd794:	mov    %rax,(%rcx)
  ebd797:	jmp    ebd727 <tree_search_key+0x247>
  ebd799:	nopl   0x0(%rax)
  ebd7a0:	mov    -0x48(%rbp),%rax
  ebd7a4:	mov    -0x60(%rbp),%rcx
  ebd7a8:	mov    %rax,-0x50(%rbp)
  ebd7ac:	mov    %rax,(%rcx)
  ebd7af:	jmpq   ebd727 <tree_search_key+0x247>
  ebd7b4:	nopl   0x0(%rax)
  ebd7b8:	mov    -0x50(%rbp),%rax
  ebd7bc:	mov    (%rax),%rax
  ebd7bf:	mov    0x18(%rax),%rax
  ebd7c3:	add    $0x38,%rsp
  ebd7c7:	pop    %rbx
  ebd7c8:	pop    %r12
  ebd7ca:	pop    %r13
  ebd7cc:	pop    %r14
  ebd7ce:	pop    %r15
  ebd7d0:	pop    %rbp
  ebd7d1:	retq   
  ebd7d2:	movq   $0x0,-0x48(%rbp)
  ebd7da:	movq   $0x0,-0x50(%rbp)
  ebd7e2:	movq   $0x0,-0x40(%rbp)
  ebd7ea:	jmpq   ebd5d2 <tree_search_key+0xf2>
  ebd7ef:	xor    %eax,%eax
  ebd7f1:	mov    %rbx,-0x48(%rbp)
  ebd7f5:	mov    %r14,%r15
  ebd7f8:	mov    %r12,%rbx
  ebd7fb:	movq   $0x0,-0x40(%rbp)
  ebd803:	mov    %rax,%r12
  ebd806:	mov    %rdi,%r13
  ebd809:	mov    %r9,%r14
  ebd80c:	nopl   0x0(%rax)
  ebd810:	add    $0x8,%rbx
  ebd814:	mov    %r15,(%rbx)
  ebd817:	mov    0x220(%r13),%eax
  ebd81e:	mov    0x240(%r13),%r10
  ebd825:	test   %eax,%eax
  ebd827:	lea    (%r15,%rax,1),%rsi
  ebd82b:	jne    ebd831 <tree_search_key+0x351>
  ebd82d:	mov    0x18(%r15),%rsi
  ebd831:	mov    -0x38(%rbp),%rdx
  ebd835:	mov    %r14,%rdi
  ebd838:	callq  *%r10
  ebd83b:	test   %eax,%eax
  ebd83d:	je     ebd678 <tree_search_key+0x198>
  ebd843:	mov    -0x40(%rbp),%rcx
  ebd847:	mov    (%r15),%rax
  ebd84a:	cmovs  %rbx,%r12
  ebd84e:	cmovs  0x8(%r15),%rax
  ebd853:	cmovns %rbx,%rcx
  ebd857:	cmp    %rax,-0x48(%rbp)
  ebd85b:	mov    %rcx,-0x40(%rbp)
  ebd85f:	mov    %rax,%r15
  ebd862:	jne    ebd810 <tree_search_key+0x330>
  ebd864:	mov    %r12,-0x50(%rbp)
  ebd868:	mov    %r13,%r15
  ebd86b:	movq   $0x0,-0x48(%rbp)
  ebd873:	jmpq   ebd5d2 <tree_search_key+0xf2>
  ebd878:	mov    %r12,%rax
  ebd87b:	mov    %rbx,%r15
  ebd87e:	movq   $0x0,-0x50(%rbp)
  ebd886:	mov    %r14,%rbx
  ebd889:	movq   $0x0,-0x40(%rbp)
  ebd891:	mov    %rdi,%r12
  ebd894:	mov    %rax,%r14
  ebd897:	add    $0x8,%r14
  ebd89b:	mov    %rbx,(%r14)
  ebd89e:	mov    0x220(%r12),%eax
  ebd8a6:	mov    0x240(%r12),%r10
  ebd8ae:	test   %eax,%eax
  ebd8b0:	lea    (%rbx,%rax,1),%rsi
  ebd8b4:	jne    ebd8ba <tree_search_key+0x3da>
  ebd8b6:	mov    0x18(%rbx),%rsi
  ebd8ba:	mov    -0x38(%rbp),%rdx
  ebd8be:	mov    %r13,%rdi
  ebd8c1:	callq  *%r10
  ebd8c4:	test   %eax,%eax
  ebd8c6:	je     ebd678 <tree_search_key+0x198>
  ebd8cc:	mov    (%rbx),%rax
  ebd8cf:	cmovs  0x8(%rbx),%rax
  ebd8d4:	mov    -0x40(%rbp),%rcx
  ebd8d8:	mov    %rax,%rbx
  ebd8db:	mov    -0x50(%rbp),%rax
  ebd8df:	cmovns %r14,%rcx
  ebd8e3:	mov    %rcx,-0x40(%rbp)
  ebd8e7:	cmovs  %r14,%rax
  ebd8eb:	cmp    %rbx,%r15
  ebd8ee:	mov    %rax,-0x50(%rbp)
  ebd8f2:	jne    ebd897 <tree_search_key+0x3b7>
  ebd8f4:	mov    %r12,%r15
  ebd8f7:	movq   $0x0,-0x48(%rbp)
  ebd8ff:	jmpq   ebd5d2 <tree_search_key+0xf2>
  ebd904:	mov    %r12,%rax
  ebd907:	mov    %rbx,%r15
  ebd90a:	mov    %rdi,%r12
  ebd90d:	mov    %r14,%rbx
  ebd910:	mov    %rax,%r14
  ebd913:	add    $0x8,%r14
  ebd917:	mov    %rbx,(%r14)
  ebd91a:	mov    0x220(%r12),%eax
  ebd922:	mov    0x240(%r12),%r10
  ebd92a:	mov    %eax,%esi
  ebd92c:	add    %rbx,%rsi
  ebd92f:	test   %eax,%eax
  ebd931:	jne    ebd937 <tree_search_key+0x457>
  ebd933:	mov    0x18(%rbx),%rsi
  ebd937:	mov    -0x38(%rbp),%rdx
  ebd93b:	mov    %r13,%rdi
  ebd93e:	callq  *%r10
  ebd941:	test   %eax,%eax
  ebd943:	je     ebd678 <tree_search_key+0x198>
  ebd949:	mov    (%rbx),%rax
  ebd94c:	cmovs  0x8(%rbx),%rax
  ebd951:	mov    -0x40(%rbp),%rcx
  ebd955:	mov    %rax,%rbx
  ebd958:	mov    -0x50(%rbp),%rax
  ebd95c:	cmovns %r14,%rcx
  ebd960:	mov    %rcx,-0x40(%rbp)
  ebd964:	cmovs  %r14,%rax
  ebd968:	cmp    %rbx,%r15
  ebd96b:	mov    %rax,-0x50(%rbp)
  ebd96f:	jne    ebd913 <tree_search_key+0x433>
  ebd971:	jmp    ebd8f4 <tree_search_key+0x414>
  ebd973:	mov    %r12,%rax
  ebd976:	mov    %rbx,%r15
  ebd979:	mov    %rdi,%r12
  ebd97c:	mov    %r14,%rbx
  ebd97f:	mov    %rax,%r14
  ebd982:	add    $0x8,%r14
  ebd986:	mov    %rbx,(%r14)
  ebd989:	mov    0x220(%r12),%eax
  ebd991:	mov    0x240(%r12),%r10
  ebd999:	test   %eax,%eax
  ebd99b:	lea    (%rbx,%rax,1),%rsi
  ebd99f:	jne    ebd9a5 <tree_search_key+0x4c5>
  ebd9a1:	mov    0x18(%rbx),%rsi
  ebd9a5:	mov    -0x38(%rbp),%rdx
  ebd9a9:	mov    %r13,%rdi
  ebd9ac:	callq  *%r10
  ebd9af:	test   %eax,%eax
  ebd9b1:	je     ebd678 <tree_search_key+0x198>
  ebd9b7:	mov    (%rbx),%rax
  ebd9ba:	cmovs  0x8(%rbx),%rax
  ebd9bf:	mov    -0x40(%rbp),%rcx
  ebd9c3:	mov    %rax,%rbx
  ebd9c6:	mov    -0x50(%rbp),%rax
  ebd9ca:	cmovns %r14,%rcx
  ebd9ce:	mov    %rcx,-0x40(%rbp)
  ebd9d2:	cmovs  %r14,%rax
  ebd9d6:	cmp    %rbx,%r15
  ebd9d9:	mov    %rax,-0x50(%rbp)
  ebd9dd:	jne    ebd982 <tree_search_key+0x4a2>
  ebd9df:	jmpq   ebd8f4 <tree_search_key+0x414>
  ebd9e4:	data32 data32 nopw %cs:0x0(%rax,%rax,1)
