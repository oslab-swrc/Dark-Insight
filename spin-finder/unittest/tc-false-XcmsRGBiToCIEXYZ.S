// TC_OUT
000000000007b320 <XcmsRGBiToCIEXYZ>:
   7b320:	test   %rdi,%rdi
   7b323:	je     7b3a0 <XcmsRGBiToCIEXYZ+0x80>
   7b325:	push   %r13
   7b327:	push   %r12
   7b329:	push   %rbp
   7b32a:	push   %rbx
   7b32b:	sub    $0x28,%rsp
   7b32f:	mov    0x68(%rdi),%rax
   7b333:	test   %edx,%edx
   7b335:	mov    0x38(%rax),%r13
   7b339:	lea    -0x1(%rdx),%eax
   7b33c:	je     7b38f <XcmsRGBiToCIEXYZ+0x6f>
   7b33e:	lea    0x3(%rax,%rax,2),%r12
   7b343:	mov    %rsi,%rbx
   7b346:	add    $0x48,%r13
   7b34a:	mov    %rsp,%rbp
   7b34d:	shl    $0x4,%r12
   7b351:	add    %rsi,%r12
   7b354:	nopl   0x0(%rax)
   7b358:	mov    %rbx,%rsi
   7b35b:	mov    %rbp,%rdx
   7b35e:	mov    %r13,%rdi
   7b361:	callq  7aa20 <XcmsFormatOfPrefix+0x2c0>
   7b366:	mov    0x0(%rbp),%rax
   7b36a:	add    $0x30,%rbx
   7b36e:	mov    %rax,-0x30(%rbx)
   7b372:	mov    0x8(%rbp),%rax
   7b376:	mov    %rax,-0x28(%rbx)
   7b37a:	mov    0x10(%rbp),%rax
   7b37e:	mov    %rax,-0x20(%rbx)
   7b382:	cmp    %r12,%rbx
   7b385:	movq   $0x1,-0x8(%rbx)
   7b38d:	jne    7b358 <XcmsRGBiToCIEXYZ+0x38>
   7b38f:	add    $0x28,%rsp
   7b393:	mov    $0x1,%eax
   7b398:	pop    %rbx
   7b399:	pop    %rbp
   7b39a:	pop    %r12
   7b39c:	pop    %r13
   7b39e:	retq   
   7b39f:	nop
   7b3a0:	xor    %eax,%eax
   7b3a2:	retq   
   7b3a3:	data16 data16 data16 nopw %cs:0x0(%rax,%rax,1)
   7b3b0:	push   %r15
   7b3b2:	push   %r14
   7b3b4:	push   %r13
   7b3b6:	push   %r12
   7b3b8:	movslq %esi,%r12
   7b3bb:	push   %rbp
   7b3bc:	push   %rbx
   7b3bd:	lea    0x98fb4(%rip),%rsi        # 114378 <_XkeyTable+0x72538>
   7b3c4:	mov    %rdx,%rbp
   7b3c7:	mov    $0x1,%edx
   7b3cc:	mov    %rdi,%rbx
   7b3cf:	sub    $0x78,%rsp
   7b3d3:	callq  27d00 <XInternAtom>
   7b3d8:	lea    0x98fb5(%rip),%rsi        # 114394 <_XkeyTable+0x72554>
   7b3df:	mov    $0x1,%edx
   7b3e4:	mov    %rbx,%rdi
   7b3e7:	mov    %rax,%r13
   7b3ea:	callq  27d00 <XInternAtom>
   7b3ef:	mov    $0xa8,%esi
   7b3f4:	mov    $0x1,%edi
   7b3f9:	mov    %rax,%r15
   7b3fc:	callq  183f0 <calloc@plt>
   7b401:	test   %rax,%rax
   7b404:	mov    %rax,%r14
   7b407:	je     7b628 <XcmsRGBiToCIEXYZ+0x308>
   7b40d:	test   %r15,%r15
   7b410:	jne    7b430 <XcmsRGBiToCIEXYZ+0x110>
   7b412:	mov    %r14,%rdi
   7b415:	callq  18060 <free@plt>
   7b41a:	movb   $0x0,0x40(%rbp)
   7b41e:	xor    %eax,%eax
   7b420:	add    $0x78,%rsp
   7b424:	pop    %rbx
   7b425:	pop    %rbp
   7b426:	pop    %r12
   7b428:	pop    %r13
   7b42a:	pop    %r14
   7b42c:	pop    %r15
   7b42e:	retq   
   7b42f:	nop
   7b430:	shl    $0x7,%r12
   7b434:	sub    $0x8,%rsp
   7b438:	mov    %rbx,%rdi
   7b43b:	mov    %r12,0x18(%rsp)
   7b440:	lea    0x60(%rsp),%rax
   7b445:	mov    %r12,%rdx
   7b448:	lea    0x58(%rsp),%r12
   7b44d:	mov    %rax,0x20(%rsp)
   7b452:	mov    %rax,%r9
   7b455:	lea    0x54(%rsp),%rax
   7b45a:	mov    %r12,%r8
   7b45d:	mov    %rax,0x30(%rsp)
   7b462:	mov    %rax,%rcx
   7b465:	mov    0xe8(%rbx),%rax
   7b46c:	mov    0x10(%rax,%rdx,1),%rsi
   7b471:	lea    0x68(%rsp),%rax
   7b476:	mov    %r15,%rdx
   7b479:	mov    %rax,0x28(%rsp)
   7b47e:	push   %rax
   7b47f:	callq  842d0 <_XcmsGetProperty>
   7b484:	test   %eax,%eax
   7b486:	pop    %rsi
   7b487:	pop    %rdi
   7b488:	je     7b412 <XcmsRGBiToCIEXYZ+0xf2>
   7b48a:	cmpq   $0x12,0x50(%rsp)
   7b490:	jne    7b412 <XcmsRGBiToCIEXYZ+0xf2>
   7b492:	mov    0x4c(%rsp),%edi
   7b496:	cmp    $0x20,%edi
   7b499:	jne    7b412 <XcmsRGBiToCIEXYZ+0xf2>
   7b49f:	mov    0x60(%rsp),%rax
   7b4a4:	mov    %r14,%rcx
   7b4a7:	mov    %rax,0x68(%rsp)
   7b4ac:	lea    0x90(%r14),%rax
   7b4b3:	mov    %rax,%r15
   7b4b6:	lea    0x68(%rsp),%rax
   7b4bb:	mov    %rax,0x30(%rsp)
   7b4c0:	jmp    7b4cc <XcmsRGBiToCIEXYZ+0x1ac>
   7b4c2:	nopw   0x0(%rax,%rax,1)
   7b4c8:	mov    0x4c(%rsp),%edi
   7b4cc:	mov    0x30(%rsp),%rsi
   7b4d1:	add    $0x8,%rcx
   7b4d5:	mov    %r12,%rdx
   7b4d8:	mov    %rcx,0x8(%rsp)
   7b4dd:	mov    %rcx,0x38(%rsp)
   7b4e2:	callq  84270 <_XcmsGetElement>
   7b4e7:	pxor   %xmm0,%xmm0
   7b4eb:	mov    0x8(%rsp),%rcx
   7b4f0:	cvtsi2sd %rax,%xmm0
   7b4f5:	cmp    %r15,%rcx
   7b4f8:	mulsd  0x998c8(%rip),%xmm0        # 114dc8 <_XkeyTable+0x72f88>
   7b500:	movsd  %xmm0,-0x8(%rcx)
   7b505:	jne    7b4c8 <XcmsRGBiToCIEXYZ+0x1a8>
   7b507:	mov    0x60(%rsp),%rdi
   7b50c:	callq  18060 <free@plt>
   7b511:	movsd  0x48(%r14),%xmm0
   7b517:	movsd  0x78(%r14),%xmm1
   7b51d:	addsd  0x50(%r14),%xmm0
   7b523:	addsd  0x80(%r14),%xmm1
   7b52c:	addsd  0x58(%r14),%xmm0
   7b532:	addsd  0x88(%r14),%xmm1
   7b53b:	movsd  %xmm0,0x0(%rbp)
   7b540:	movsd  0x60(%r14),%xmm0
   7b546:	movsd  %xmm1,0x10(%rbp)
   7b54b:	addsd  0x68(%r14),%xmm0
   7b551:	movsd  0x99877(%rip),%xmm1        # 114dd0 <_XkeyTable+0x72f90>
   7b559:	addsd  0x70(%r14),%xmm0
   7b55f:	ucomisd %xmm0,%xmm1
   7b563:	movsd  %xmm0,0x8(%rbp)
   7b568:	ja     7b412 <XcmsRGBiToCIEXYZ+0xf2>
   7b56e:	ucomisd 0x9984a(%rip),%xmm0        # 114dc0 <_XkeyTable+0x72f80>
   7b576:	ja     7b412 <XcmsRGBiToCIEXYZ+0xf2>
   7b57c:	movsd  0x98d44(%rip),%xmm2        # 1142c8 <_XkeyTable+0x72488>
   7b584:	test   %r13,%r13
   7b587:	movq   $0x1,0x28(%rbp)
   7b58f:	movq   $0x0,0x20(%rbp)
   7b597:	movsd  %xmm2,0x8(%rbp)
   7b59c:	je     7b412 <XcmsRGBiToCIEXYZ+0xf2>
   7b5a2:	sub    $0x8,%rsp
   7b5a6:	mov    0xe8(%rbx),%rax
   7b5ad:	mov    %r13,%rdx
   7b5b0:	mov    0x18(%rsp),%rcx
   7b5b5:	mov    %r12,%r8
   7b5b8:	mov    %rbx,%rdi
   7b5bb:	mov    0x10(%rax,%rcx,1),%rsi
   7b5c0:	pushq  0x28(%rsp)
   7b5c4:	mov    0x28(%rsp),%r9
   7b5c9:	mov    0x38(%rsp),%rcx
   7b5ce:	callq  842d0 <_XcmsGetProperty>
   7b5d3:	test   %eax,%eax
   7b5d5:	pop    %rdx
   7b5d6:	pop    %rcx
   7b5d7:	je     7b412 <XcmsRGBiToCIEXYZ+0xf2>
   7b5dd:	mov    0x60(%rsp),%rax
   7b5e2:	mov    %r14,%r13
   7b5e5:	mov    %rax,0x68(%rsp)
   7b5ea:	mov    0x50(%rsp),%rax
   7b5ef:	test   %rax,%rax
   7b5f2:	je     7b947 <XcmsRGBiToCIEXYZ+0x627>
   7b5f8:	mov    0x4c(%rsp),%edi
   7b5fc:	cmp    $0x10,%edi
   7b5ff:	je     7b639 <XcmsRGBiToCIEXYZ+0x319>
   7b601:	cmp    $0x20,%edi
   7b604:	je     7b862 <XcmsRGBiToCIEXYZ+0x542>
   7b60a:	cmp    $0x8,%edi
   7b60d:	je     7b84d <XcmsRGBiToCIEXYZ+0x52d>
   7b613:	mov    0x60(%rsp),%rdi
   7b618:	callq  18060 <free@plt>
   7b61d:	jmpq   7b412 <XcmsRGBiToCIEXYZ+0xf2>
   7b622:	nopw   0x0(%rax,%rax,1)
   7b628:	add    $0x78,%rsp
   7b62c:	xor    %eax,%eax
   7b62e:	pop    %rbx
   7b62f:	pop    %rbp
   7b630:	pop    %r12
   7b632:	pop    %r13
   7b634:	pop    %r14
   7b636:	pop    %r15
   7b638:	retq   
   7b639:	cmp    $0x6,%rax
   7b63d:	jbe    7b613 <XcmsRGBiToCIEXYZ+0x2f3>
   7b63f:	mov    $0x1,%r13d
   7b645:	mov    0x30(%rsp),%rsi
   7b64a:	mov    %r12,%rdx
   7b64d:	callq  84270 <_XcmsGetElement>
   7b652:	mov    %rax,%r15
   7b655:	nopl   (%rax)
   7b658:	mov    0x4c(%rsp),%edi
   7b65c:	mov    0x30(%rsp),%rsi
   7b661:	mov    %r12,%rdx
   7b664:	mov    %edi,%ecx
   7b666:	shl    %cl,%r15
   7b669:	callq  84270 <_XcmsGetElement>
   7b66e:	or     %rax,%r15
   7b671:	sub    $0x1,%r13d
   7b675:	jne    7b658 <XcmsRGBiToCIEXYZ+0x338>
   7b677:	test   %r15,%r15
   7b67a:	je     7b82b <XcmsRGBiToCIEXYZ+0x50b>
   7b680:	mov    $0xa8,%esi
   7b685:	mov    $0x1,%edi
   7b68a:	callq  183f0 <calloc@plt>
   7b68f:	test   %rax,%rax
   7b692:	mov    %rax,%r13
   7b695:	je     7b613 <XcmsRGBiToCIEXYZ+0x2f3>
   7b69b:	mov    %rax,%rdi
   7b69e:	mov    %r14,%rsi
   7b6a1:	mov    $0x24,%ecx
   7b6a6:	rep movsl %ds:(%rsi),%es:(%rdi)
   7b6a8:	mov    $0x20,%esi
   7b6ad:	mov    $0x1,%edi
   7b6b2:	callq  183f0 <calloc@plt>
   7b6b7:	test   %rax,%rax
   7b6ba:	je     7b977 <XcmsRGBiToCIEXYZ+0x657>
   7b6c0:	mov    0x9b8(%rbx),%rdx
   7b6c7:	lea    -0xb2e(%rip),%rcx        # 7aba0 <XcmsFormatOfPrefix+0x440>
   7b6ce:	mov    %rax,0x9b8(%rbx)
   7b6d5:	mov    %r15,(%rax)
   7b6d8:	mov    %r13,0x8(%rax)
   7b6dc:	mov    %rcx,0x10(%rax)
   7b6e0:	mov    %rdx,0x18(%rax)
   7b6e4:	mov    0x8(%rbx),%rax
   7b6e8:	lea    0x85d1(%rip),%rdx        # 83cc0 <_XcmsFreeIntensityMaps>
   7b6ef:	mov    %rdx,0x30(%rax)
   7b6f3:	mov    0x30(%rsp),%r15
   7b6f8:	mov    0x4c(%rsp),%edi
   7b6fc:	mov    %r12,%rdx
   7b6ff:	mov    %r15,%rsi
   7b702:	callq  84270 <_XcmsGetElement>
   7b707:	mov    0x4c(%rsp),%edi
   7b70b:	mov    %r15,%rsi
   7b70e:	mov    %r12,%rdx
   7b711:	mov    %rax,0x8(%rsp)
   7b716:	callq  84270 <_XcmsGetElement>
   7b71b:	mov    0x8(%rsp),%rcx
   7b720:	mov    %rax,%r15
   7b723:	test   %ecx,%ecx
   7b725:	je     7b886 <XcmsRGBiToCIEXYZ+0x566>
   7b72b:	sub    $0x1,%ecx
   7b72e:	jne    7b613 <XcmsRGBiToCIEXYZ+0x2f3>
   7b734:	mov    $0x10,%esi
   7b739:	mov    $0x1,%edi
   7b73e:	callq  183f0 <calloc@plt>
   7b743:	test   %rax,%rax
   7b746:	mov    %rax,0x90(%r13)
   7b74d:	je     7b613 <XcmsRGBiToCIEXYZ+0x2f3>
   7b753:	mov    0x30(%rsp),%rdx
   7b758:	mov    0x4c(%rsp),%esi
   7b75c:	mov    %r12,%rcx
   7b75f:	mov    %rax,%rdi
   7b762:	callq  18b1f <_XEatDataWords+0x2be>
   7b767:	test   %eax,%eax
   7b769:	je     7b81a <XcmsRGBiToCIEXYZ+0x4fa>
   7b76f:	sub    $0x1,%r15d
   7b773:	je     7b833 <XcmsRGBiToCIEXYZ+0x513>
   7b779:	mov    $0x10,%esi
   7b77e:	mov    $0x1,%edi
   7b783:	callq  183f0 <calloc@plt>
   7b788:	test   %rax,%rax
   7b78b:	mov    %rax,0x98(%r13)
   7b792:	je     7b80b <XcmsRGBiToCIEXYZ+0x4eb>
   7b794:	mov    0x30(%rsp),%r15
   7b799:	mov    0x4c(%rsp),%esi
   7b79d:	mov    %r12,%rcx
   7b7a0:	mov    %rax,%rdi
   7b7a3:	mov    %r15,%rdx
   7b7a6:	callq  18b1f <_XEatDataWords+0x2be>
   7b7ab:	test   %eax,%eax
   7b7ad:	je     7b7ff <XcmsRGBiToCIEXYZ+0x4df>
   7b7af:	mov    $0x10,%esi
   7b7b4:	mov    $0x1,%edi
   7b7b9:	callq  183f0 <calloc@plt>
   7b7be:	test   %rax,%rax
   7b7c1:	mov    %rax,0xa0(%r13)
   7b7c8:	je     7b7f0 <XcmsRGBiToCIEXYZ+0x4d0>
   7b7ca:	mov    0x4c(%rsp),%esi
   7b7ce:	mov    %r12,%rcx
   7b7d1:	mov    %r15,%rdx
   7b7d4:	mov    %rax,%rdi
   7b7d7:	callq  18b1f <_XEatDataWords+0x2be>
   7b7dc:	test   %eax,%eax
   7b7de:	jne    7b5ea <XcmsRGBiToCIEXYZ+0x2ca>
   7b7e4:	mov    0xa0(%r13),%rdi
   7b7eb:	callq  18060 <free@plt>
   7b7f0:	mov    0x98(%r13),%rax
   7b7f7:	mov    (%rax),%rdi
   7b7fa:	callq  18060 <free@plt>
   7b7ff:	mov    0x98(%r13),%rdi
   7b806:	callq  18060 <free@plt>
   7b80b:	mov    0x90(%r13),%rax
   7b812:	mov    (%rax),%rdi
   7b815:	callq  18060 <free@plt>
   7b81a:	mov    0x90(%r13),%rdi
   7b821:	callq  18060 <free@plt>
   7b826:	jmpq   7b613 <XcmsRGBiToCIEXYZ+0x2f3>
   7b82b:	mov    %r14,%r13
   7b82e:	jmpq   7b6f3 <XcmsRGBiToCIEXYZ+0x3d3>
   7b833:	mov    0x90(%r13),%rax
   7b83a:	mov    %rax,0x98(%r13)
   7b841:	mov    %rax,0xa0(%r13)
   7b848:	jmpq   7b5ea <XcmsRGBiToCIEXYZ+0x2ca>
   7b84d:	cmp    $0x8,%rax
   7b851:	jbe    7b613 <XcmsRGBiToCIEXYZ+0x2f3>
   7b857:	mov    $0x3,%r13d
   7b85d:	jmpq   7b645 <XcmsRGBiToCIEXYZ+0x325>
   7b862:	cmp    $0x5,%rax
   7b866:	jbe    7b613 <XcmsRGBiToCIEXYZ+0x2f3>
   7b86c:	mov    0x30(%rsp),%rsi
   7b871:	mov    %r12,%rdx
   7b874:	mov    $0x20,%edi
   7b879:	callq  84270 <_XcmsGetElement>
   7b87e:	mov    %rax,%r15
   7b881:	jmpq   7b677 <XcmsRGBiToCIEXYZ+0x357>
   7b886:	mov    $0x10,%esi
   7b88b:	mov    $0x1,%edi
   7b890:	callq  183f0 <calloc@plt>
   7b895:	test   %rax,%rax
   7b898:	mov    %rax,0x90(%r13)
   7b89f:	je     7b613 <XcmsRGBiToCIEXYZ+0x2f3>
   7b8a5:	mov    0x30(%rsp),%rdx
   7b8aa:	mov    0x4c(%rsp),%esi
   7b8ae:	mov    %r12,%rcx
   7b8b1:	mov    %rax,%rdi
   7b8b4:	callq  18976 <_XEatDataWords+0x115>
   7b8b9:	test   %eax,%eax
   7b8bb:	je     7b81a <XcmsRGBiToCIEXYZ+0x4fa>
   7b8c1:	sub    $0x1,%r15d
   7b8c5:	je     7b833 <XcmsRGBiToCIEXYZ+0x513>
   7b8cb:	mov    $0x10,%esi
   7b8d0:	mov    $0x1,%edi
   7b8d5:	callq  183f0 <calloc@plt>
   7b8da:	test   %rax,%rax
   7b8dd:	mov    %rax,0x98(%r13)
   7b8e4:	je     7b80b <XcmsRGBiToCIEXYZ+0x4eb>
   7b8ea:	mov    0x30(%rsp),%r15
   7b8ef:	mov    0x4c(%rsp),%esi
   7b8f3:	mov    %r12,%rcx
   7b8f6:	mov    %rax,%rdi
   7b8f9:	mov    %r15,%rdx
   7b8fc:	callq  18976 <_XEatDataWords+0x115>
   7b901:	test   %eax,%eax
   7b903:	je     7b7ff <XcmsRGBiToCIEXYZ+0x4df>
   7b909:	mov    $0x10,%esi
   7b90e:	mov    $0x1,%edi
   7b913:	callq  183f0 <calloc@plt>
   7b918:	test   %rax,%rax
   7b91b:	mov    %rax,0xa0(%r13)
   7b922:	je     7b7f0 <XcmsRGBiToCIEXYZ+0x4d0>
   7b928:	mov    0x4c(%rsp),%esi
   7b92c:	mov    %r12,%rcx
   7b92f:	mov    %r15,%rdx
   7b932:	mov    %rax,%rdi
   7b935:	callq  18976 <_XEatDataWords+0x115>
   7b93a:	test   %eax,%eax
   7b93c:	jne    7b5ea <XcmsRGBiToCIEXYZ+0x2ca>
   7b942:	jmpq   7b7e4 <XcmsRGBiToCIEXYZ+0x4c4>
   7b947:	mov    0x60(%rsp),%rdi
   7b94c:	callq  18060 <free@plt>
   7b951:	mov    0x38(%rbp),%rdi
   7b955:	callq  7aba0 <XcmsFormatOfPrefix+0x440>
   7b95a:	mov    0x2b8527(%rip),%rax        # 333e88 <_XcmsCIEXYZ_prefix+0x21ef73>
   7b961:	mov    %r13,0x38(%rbp)
   7b965:	movb   $0x1,0x40(%rbp)
   7b969:	mov    %rax,0x30(%rbp)
   7b96d:	mov    $0x1,%eax
   7b972:	jmpq   7b420 <XcmsRGBiToCIEXYZ+0x100>
   7b977:	mov    %r13,%rdi
   7b97a:	callq  18060 <free@plt>
   7b97f:	jmpq   7b613 <XcmsRGBiToCIEXYZ+0x2f3>
   7b984:	data16 data16 nopw %cs:0x0(%rax,%rax,1)
   7b990:	lea    -0x1(%rcx),%r10d
   7b994:	push   %r15
   7b996:	push   %r14
   7b998:	push   %r13
   7b99a:	push   %r12
   7b99c:	mov    %r8,%r12
   7b99f:	mov    %r10d,%ecx
   7b9a2:	push   %rbp
   7b9a3:	push   %rbx
   7b9a4:	shl    $0x4,%ecx
   7b9a7:	mov    %rdi,%rbp
   7b9aa:	mov    %rdx,%rbx
   7b9ad:	mov    %ecx,%r10d
   7b9b0:	sub    $0x28,%rsp
   7b9b4:	mov    $0x10,%ecx
   7b9b9:	lea    (%rdx,%r10,1),%r13
   7b9bd:	movzwl 0x0(%rbp),%edx
   7b9c1:	sub    %esi,%ecx
   7b9c3:	mov    %esi,%edi
   7b9c5:	mov    0x60(%rsp),%rax
   7b9ca:	mov    %esi,0xc(%rsp)
   7b9ce:	mov    $0x1,%esi
   7b9d3:	mov    %r9,0x18(%rsp)
   7b9d8:	sar    %cl,%edx
   7b9da:	mov    %edi,%ecx
   7b9dc:	mov    %rax,0x10(%rsp)
   7b9e1:	movslq %edx,%rdx
   7b9e4:	shl    %cl,%esi
   7b9e6:	mov    %rbp,%rdi
   7b9e9:	mov    %rdx,%rax
   7b9ec:	lea    -0x1(%rsi),%ecx
   7b9ef:	mov    %rbx,%rsi
   7b9f2:	shl    $0x10,%rax
   7b9f6:	sub    %rdx,%rax
   7b9f9:	movslq %ecx,%rcx
   7b9fc:	xor    %edx,%edx
   7b9fe:	div    %rcx
   7ba01:	mov    %ax,0x0(%rbp)
   7ba05:	callq  *%r8
   7ba08:	test   %eax,%eax
   7ba0a:	jle    7bab8 <XcmsRGBiToCIEXYZ+0x798>
   7ba10:	cmp    %r13,%rbx
   7ba13:	mov    %rbx,%r15
   7ba16:	jne    7ba30 <XcmsRGBiToCIEXYZ+0x710>
   7ba18:	jmp    7ba90 <XcmsRGBiToCIEXYZ+0x770>
   7ba1a:	nopw   0x0(%rax,%rax,1)
   7ba20:	cmovns %r14,%r15
   7ba24:	cmovs  %r14,%r13
   7ba28:	cmp    %rbx,%r14
   7ba2b:	je     7ba90 <XcmsRGBiToCIEXYZ+0x770>
   7ba2d:	mov    %r14,%rbx
   7ba30:	mov    %r13,%rcx
   7ba33:	mov    %rbp,%rdi
   7ba36:	sub    %r15,%rcx
   7ba39:	shr    $0x5,%ecx
   7ba3c:	shl    $0x4,%ecx
   7ba3f:	lea    (%r15,%rcx,1),%r14
   7ba43:	mov    %r14,%rsi
   7ba46:	callq  *%r12
   7ba49:	test   %eax,%eax
   7ba4b:	jne    7ba20 <XcmsRGBiToCIEXYZ+0x700>
   7ba4d:	mov    (%r14),%rax
   7ba50:	mov    0x10(%rsp),%rdx
   7ba55:	mov    %rax,(%rdx)
   7ba58:	mov    0x8(%r14),%rax
   7ba5c:	movslq 0xc(%rsp),%r13
   7ba61:	mov    %rax,0x8(%rdx)
   7ba65:	lea    0x99314(%rip),%rax        # 114d80 <_XkeyTable+0x72f40>
   7ba6c:	movzwl (%rax,%r13,2),%eax
   7ba71:	and    %ax,(%rdx)
   7ba74:	add    $0x28,%rsp
   7ba78:	mov    $0x1,%eax
   7ba7d:	pop    %rbx
   7ba7e:	pop    %rbp
   7ba7f:	pop    %r12
   7ba81:	pop    %r13
   7ba83:	pop    %r14
   7ba85:	pop    %r15
   7ba87:	retq   
   7ba88:	nopl   0x0(%rax,%rax,1)
   7ba90:	mov    0xc(%rsp),%r8d
   7ba95:	mov    0x10(%rsp),%rcx
   7ba9a:	mov    %r13,%rdx
   7ba9d:	mov    0x18(%rsp),%rax
   7baa2:	add    $0x28,%rsp
   7baa6:	mov    %r15,%rsi
   7baa9:	pop    %rbx
   7baaa:	mov    %rbp,%rdi
   7baad:	pop    %rbp
   7baae:	pop    %r12
   7bab0:	pop    %r13
   7bab2:	pop    %r14
   7bab4:	pop    %r15
   7bab6:	jmpq   *%rax
   7bab8:	mov    (%rbx),%rax
   7babb:	mov    0x10(%rsp),%rdx
   7bac0:	mov    %rax,(%rdx)
   7bac3:	mov    0x8(%rbx),%rax
   7bac7:	jmp    7ba5c <XcmsRGBiToCIEXYZ+0x73c>
   7bac9:	nopl   0x0(%rax)
