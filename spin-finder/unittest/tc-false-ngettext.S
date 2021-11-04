// TC_OUT
0000000000030480 <ngettext>:
   30480:	mov    %rdx,%rcx
   30483:	mov    $0x5,%r8d
   30489:	mov    %rsi,%rdx
   3048c:	mov    %rdi,%rsi
   3048f:	xor    %edi,%edi
   30491:	jmpq   30460 <dcngettext>
   30496:	nopw   %cs:0x0(%rax,%rax,1)
   304a0:	push   %r15
   304a2:	push   %r14
   304a4:	mov    %rdx,%r14
   304a7:	push   %r13
   304a9:	push   %r12
   304ab:	mov    %rsi,%r13
   304ae:	push   %rbp
   304af:	push   %rbx
   304b0:	mov    %rdi,%rbp
   304b3:	mov    %rcx,%r12
   304b6:	sub    $0x48,%rsp
   304ba:	mov    0x3997af(%rip),%r11d        # 3c9c70 <argp_program_version_hook+0x1e8>
   304c1:	test   %r11d,%r11d
   304c4:	jne    30540 <ngettext+0xc0>
   304c6:	mov    %rbp,%rdi
   304c9:	callq  8b6d0 <strlen>
   304ce:	sub    $0x8,%rsp
   304d2:	lea    0x1(%rax),%rdx
   304d6:	lea    0x39583b(%rip),%rdi        # 3c5d18 <__vdso_clock_gettime+0x318>
   304dd:	pushq  $0x0
   304df:	push   %r14
   304e1:	xor    %r9d,%r9d
   304e4:	pushq  $0x0
   304e6:	pushq  $0x0
   304e8:	xor    %ecx,%ecx
   304ea:	pushq  $0x0
   304ec:	mov    %r13,%r8
   304ef:	mov    %rbp,%rsi
   304f2:	callq  32530 <textdomain+0x140>
   304f7:	mov    0x399772(%rip),%r10d        # 3c9c70 <argp_program_version_hook+0x1e8>
   304fe:	add    $0x30,%rsp
   30502:	mov    %rax,%rbx
   30505:	test   %r10d,%r10d
   30508:	jne    30568 <ngettext+0xe8>
   3050a:	test   %rbx,%rbx
   3050d:	je     30600 <ngettext+0x180>
   30513:	mov    0x8(%rbx),%r9d
   30517:	test   %r9d,%r9d
   3051a:	jle    305f0 <ngettext+0x170>
   30520:	cmpq   $0x0,0x10(%rbx)
   30525:	mov    %rbx,%rax
   30528:	je     30590 <ngettext+0x110>
   3052a:	add    $0x48,%rsp
   3052e:	pop    %rbx
   3052f:	pop    %rbp
   30530:	pop    %r12
   30532:	pop    %r13
   30534:	pop    %r14
   30536:	pop    %r15
   30538:	retq   
   30539:	nopl   0x0(%rax)
   30540:	mov    0x3996b9(%rip),%rax        # 3c9c00 <argp_program_version_hook+0x178>
   30547:	lea    0x395792(%rip),%rdi        # 3c5ce0 <__vdso_clock_gettime+0x2e0>
   3054e:	ror    $0x11,%rax
   30552:	xor    %fs:0x30,%rax
   3055b:	callq  *%rax
   3055d:	jmpq   304c6 <ngettext+0x46>
   30562:	nopw   0x0(%rax,%rax,1)
   30568:	mov    0x3996a1(%rip),%rax        # 3c9c10 <argp_program_version_hook+0x188>
   3056f:	lea    0x39576a(%rip),%rdi        # 3c5ce0 <__vdso_clock_gettime+0x2e0>
   30576:	ror    $0x11,%rax
   3057a:	xor    %fs:0x30,%rax
   30583:	callq  *%rax
   30585:	jmp    3050a <ngettext+0x8a>
   30587:	nopw   0x0(%rax,%rax,1)
   30590:	mov    0x20(%rbx),%rdi
   30594:	test   %rdi,%rdi
   30597:	je     3052a <ngettext+0xaa>
   30599:	xor    %ebp,%ebp
   3059b:	jmp    305be <ngettext+0x13e>
   3059d:	nopl   (%rax)
   305a0:	movslq %ebp,%rax
   305a3:	lea    (%rbx,%rax,8),%rax
   305a7:	mov    0x20(%rax),%rdx
   305ab:	cmpq   $0x0,0x10(%rdx)
   305b0:	jne    305d8 <ngettext+0x158>
   305b2:	mov    0x28(%rax),%rdi
   305b6:	add    $0x1,%ebp
   305b9:	test   %rdi,%rdi
   305bc:	je     305d8 <ngettext+0x158>
   305be:	mov    0x8(%rdi),%r8d
   305c2:	test   %r8d,%r8d
   305c5:	jg     305a0 <ngettext+0x120>
   305c7:	mov    %r12,%rsi
   305ca:	callq  307a0 <ngettext+0x320>
   305cf:	jmp    305a0 <ngettext+0x120>
   305d1:	nopl   0x0(%rax)
   305d8:	add    $0x48,%rsp
   305dc:	mov    %rbx,%rax
   305df:	pop    %rbx
   305e0:	pop    %rbp
   305e1:	pop    %r12
   305e3:	pop    %r13
   305e5:	pop    %r14
   305e7:	pop    %r15
   305e9:	retq   
   305ea:	nopw   0x0(%rax,%rax,1)
   305f0:	mov    %r12,%rsi
   305f3:	mov    %rbx,%rdi
   305f6:	callq  307a0 <ngettext+0x320>
   305fb:	jmpq   30520 <ngettext+0xa0>
   30600:	mov    %r13,%rdi
   30603:	callq  32250 <ngettext+0x1dd0>
   30608:	test   %rax,%rax
   3060b:	mov    %rax,%r15
   3060e:	je     30624 <ngettext+0x1a4>
   30610:	mov    %rax,%rdi
   30613:	callq  8b410 <__strdup>
   30618:	test   %rax,%rax
   3061b:	mov    %rax,%r13
   3061e:	je     30791 <ngettext+0x311>
   30624:	lea    0x28(%rsp),%rcx
   30629:	lea    0x20(%rsp),%rdx
   3062e:	lea    0x18(%rsp),%rsi
   30633:	lea    0x38(%rsp),%r9
   30638:	lea    0x30(%rsp),%r8
   3063d:	mov    %r13,%rdi
   30640:	callq  32c30 <textdomain+0x840>
   30645:	cmp    $0xffffffff,%eax
   30648:	mov    %eax,%ebx
   3064a:	je     30791 <ngettext+0x311>
   30650:	mov    0x39961a(%rip),%esi        # 3c9c70 <argp_program_version_hook+0x1e8>
   30656:	test   %esi,%esi
   30658:	jne    30712 <ngettext+0x292>
   3065e:	mov    %rbp,%rdi
   30661:	callq  8b6d0 <strlen>
   30666:	sub    $0x8,%rsp
   3066a:	lea    0x1(%rax),%rdx
   3066e:	lea    0x3956a3(%rip),%rdi        # 3c5d18 <__vdso_clock_gettime+0x318>
   30675:	pushq  $0x1
   30677:	push   %r14
   30679:	mov    %ebx,%ecx
   3067b:	pushq  0x38(%rsp)
   3067f:	pushq  0x58(%rsp)
   30683:	mov    %rbp,%rsi
   30686:	pushq  0x58(%rsp)
   3068a:	mov    0x58(%rsp),%r9
   3068f:	mov    0x48(%rsp),%r8
   30694:	callq  32530 <textdomain+0x140>
   30699:	mov    0x3995d1(%rip),%ecx        # 3c9c70 <argp_program_version_hook+0x1e8>
   3069f:	add    $0x30,%rsp
   306a3:	mov    %rax,%rbp
   306a6:	test   %ecx,%ecx
   306a8:	jne    306f3 <ngettext+0x273>
   306aa:	test   %rbp,%rbp
   306ad:	je     306ce <ngettext+0x24e>
   306af:	mov    0x8(%rbp),%edx
   306b2:	test   %edx,%edx
   306b4:	jle    30781 <ngettext+0x301>
   306ba:	cmpq   $0x0,0x10(%rbp)
   306bf:	je     30734 <ngettext+0x2b4>
   306c1:	test   %r15,%r15
   306c4:	je     306ce <ngettext+0x24e>
   306c6:	mov    %r13,%rdi
   306c9:	callq  1f4c0 <free@plt>
   306ce:	and    $0x1,%ebx
   306d1:	mov    %rbp,%rax
   306d4:	je     3052a <ngettext+0xaa>
   306da:	mov    0x38(%rsp),%rdi
   306df:	mov    %rbp,0x8(%rsp)
   306e4:	callq  1f4c0 <free@plt>
   306e9:	mov    0x8(%rsp),%rax
   306ee:	jmpq   3052a <ngettext+0xaa>
   306f3:	mov    0x399516(%rip),%rax        # 3c9c10 <argp_program_version_hook+0x188>
   306fa:	lea    0x3955df(%rip),%rdi        # 3c5ce0 <__vdso_clock_gettime+0x2e0>
   30701:	ror    $0x11,%rax
   30705:	xor    %fs:0x30,%rax
   3070e:	callq  *%rax
   30710:	jmp    306aa <ngettext+0x22a>
   30712:	mov    0x3994ef(%rip),%rax        # 3c9c08 <argp_program_version_hook+0x180>
   30719:	lea    0x3955c0(%rip),%rdi        # 3c5ce0 <__vdso_clock_gettime+0x2e0>
   30720:	ror    $0x11,%rax
   30724:	xor    %fs:0x30,%rax
   3072d:	callq  *%rax
   3072f:	jmpq   3065e <ngettext+0x1de>
   30734:	mov    0x20(%rbp),%rdi
   30738:	test   %rdi,%rdi
   3073b:	je     306c1 <ngettext+0x241>
   3073d:	xor    %r14d,%r14d
   30740:	jmp    30770 <ngettext+0x2f0>
   30742:	nopw   0x0(%rax,%rax,1)
   30748:	movslq %r14d,%rax
   3074b:	lea    0x0(%rbp,%rax,8),%rax
   30750:	mov    0x20(%rax),%rdx
   30754:	cmpq   $0x0,0x10(%rdx)
   30759:	jne    306c1 <ngettext+0x241>
   3075f:	mov    0x28(%rax),%rdi
   30763:	add    $0x1,%r14d
   30767:	test   %rdi,%rdi
   3076a:	je     306c1 <ngettext+0x241>
   30770:	mov    0x8(%rdi),%eax
   30773:	test   %eax,%eax
   30775:	jg     30748 <ngettext+0x2c8>
   30777:	mov    %r12,%rsi
   3077a:	callq  307a0 <ngettext+0x320>
   3077f:	jmp    30748 <ngettext+0x2c8>
   30781:	mov    %r12,%rsi
   30784:	mov    %rbp,%rdi
   30787:	callq  307a0 <ngettext+0x320>
   3078c:	jmpq   306ba <ngettext+0x23a>
   30791:	xor    %eax,%eax
   30793:	jmpq   3052a <ngettext+0xaa>
   30798:	nopl   0x0(%rax,%rax,1)
   307a0:	push   %rbp
   307a1:	mov    %rsi,%r9
   307a4:	mov    %fs:0x10,%r8
   307ad:	mov    %rsp,%rbp
   307b0:	push   %r15
   307b2:	push   %r14
   307b4:	push   %r13
   307b6:	push   %r12
   307b8:	push   %rbx
   307b9:	mov    %rdi,%rbx
   307bc:	sub    $0x138,%rsp
   307c3:	cmp    0x39555e(%rip),%r8        # 3c5d28 <__vdso_clock_gettime+0x328>
   307ca:	je     30812 <ngettext+0x392>
   307cc:	mov    $0x1,%esi
   307d1:	xor    %eax,%eax
   307d3:	cmpl   $0x0,0x3994a6(%rip)        # 3c9c80 <argp_program_version_hook+0x1f8>
   307da:	je     307e8 <ngettext+0x368>
   307dc:	lock cmpxchg %esi,0x39553c(%rip)        # 3c5d20 <__vdso_clock_gettime+0x320>
   307e4:	jne    307f1 <ngettext+0x371>
   307e6:	jmp    3080b <ngettext+0x38b>
   307e8:	cmpxchg %esi,0x395531(%rip)        # 3c5d20 <__vdso_clock_gettime+0x320>
   307ef:	je     3080b <ngettext+0x38b>
   307f1:	lea    0x395528(%rip),%rdi        # 3c5d20 <__vdso_clock_gettime+0x320>
   307f8:	sub    $0x80,%rsp
   307ff:	callq  114bd0 <pthread_setcanceltype+0x30>
   30804:	add    $0x80,%rsp
   3080b:	mov    %r8,0x395516(%rip)        # 3c5d28 <__vdso_clock_gettime+0x328>
   30812:	mov    0x39550c(%rip),%eax        # 3c5d24 <__vdso_clock_gettime+0x324>
   30818:	mov    0x8(%rbx),%r8d
   3081c:	add    $0x1,%eax
   3081f:	test   %r8d,%r8d
   30822:	mov    %eax,0x3954fc(%rip)        # 3c5d24 <__vdso_clock_gettime+0x324>
   30828:	jne    30890 <ngettext+0x410>
   3082a:	mov    (%rbx),%rdi
   3082d:	mov    %r9,%r13
   30830:	movl   $0xffffffff,0x8(%rbx)
   30837:	movq   $0x0,0x10(%rbx)
   3083f:	test   %rdi,%rdi
   30842:	je     30889 <ngettext+0x409>
   30844:	xor    %esi,%esi
   30846:	xor    %eax,%eax
   30848:	callq  f7269 <__open+0x9>
   3084d:	cmp    $0xffffffff,%eax
   30850:	mov    %eax,%r14d
   30853:	je     30883 <ngettext+0x403>
   30855:	lea    -0xc0(%rbp),%rdx
   3085c:	mov    %eax,%esi
   3085e:	mov    $0x1,%edi
   30863:	callq  f6e50 <__fxstat>
   30868:	test   %eax,%eax
   3086a:	jne    30879 <ngettext+0x3f9>
   3086c:	mov    -0x90(%rbp),%r12
   30873:	cmp    $0x2f,%r12
   30877:	ja     308f0 <ngettext+0x470>
   30879:	movslq %r14d,%rdi
   3087c:	mov    $0x3,%eax
   30881:	syscall 
   30883:	mov    0x39549b(%rip),%eax        # 3c5d24 <__vdso_clock_gettime+0x324>
   30889:	movl   $0x1,0x8(%rbx)
   30890:	sub    $0x1,%eax
   30893:	test   %eax,%eax
   30895:	mov    %eax,0x395489(%rip)        # 3c5d24 <__vdso_clock_gettime+0x324>
   3089b:	jne    308de <ngettext+0x45e>
   3089d:	movq   $0x0,0x395480(%rip)        # 3c5d28 <__vdso_clock_gettime+0x328>
   308a8:	cmpl   $0x0,0x3993d1(%rip)        # 3c9c80 <argp_program_version_hook+0x1f8>
   308af:	je     308bc <ngettext+0x43c>
   308b1:	lock decl 0x395468(%rip)        # 3c5d20 <__vdso_clock_gettime+0x320>
   308b8:	jne    308c4 <ngettext+0x444>
   308ba:	jmp    308de <ngettext+0x45e>
   308bc:	decl   0x39545e(%rip)        # 3c5d20 <__vdso_clock_gettime+0x320>
   308c2:	je     308de <ngettext+0x45e>
   308c4:	lea    0x395455(%rip),%rdi        # 3c5d20 <__vdso_clock_gettime+0x320>
   308cb:	sub    $0x80,%rsp
   308d2:	callq  114c00 <pthread_setcanceltype+0x60>
   308d7:	add    $0x80,%rsp
   308de:	lea    -0x28(%rbp),%rsp
   308e2:	pop    %rbx
   308e3:	pop    %r12
   308e5:	pop    %r13
   308e7:	pop    %r14
   308e9:	pop    %r15
   308eb:	pop    %rbp
   308ec:	retq   
   308ed:	nopl   (%rax)
   308f0:	xor    %r9d,%r9d
   308f3:	xor    %edi,%edi
   308f5:	mov    %r14d,%r8d
   308f8:	mov    $0x2,%ecx
   308fd:	mov    $0x1,%edx
   30902:	mov    %r12,%rsi
   30905:	callq  101720 <mmap>
   3090a:	cmp    $0xffffffffffffffff,%rax
   3090e:	mov    %rax,%r15
   30911:	je     30b1e <ngettext+0x69e>
   30917:	movslq %r14d,%rdi
   3091a:	mov    $0x3,%eax
   3091f:	syscall 
   30921:	mov    (%r15),%eax
   30924:	cmp    $0x950412de,%eax
   30929:	setne  %dl
   3092c:	cmp    $0xde120495,%eax
   30931:	mov    %edx,%r9d
   30934:	je     3094a <ngettext+0x4ca>
   30936:	test   %dl,%dl
   30938:	je     3094a <ngettext+0x4ca>
   3093a:	mov    %r12,%rsi
   3093d:	mov    %r15,%rdi
   30940:	callq  101750 <munmap>
   30945:	jmpq   30883 <ngettext+0x403>
   3094a:	movl   $0x1,-0xe0(%rbp)
   30954:	mov    $0xc8,%edi
   30959:	mov    %r9b,-0xd8(%rbp)
   30960:	callq  1f460 <malloc@plt>
   30965:	test   %rax,%rax
   30968:	mov    %rax,%r14
   3096b:	je     30883 <ngettext+0x403>
   30971:	movzbl -0xd8(%rbp),%edx
   30978:	mov    %r15,(%rax)
   3097b:	mov    %rax,0x10(%rbx)
   3097f:	mov    -0xe0(%rbp),%eax
   30985:	mov    %r12,0x10(%r14)
   30989:	movq   $0x0,0x20(%r14)
   30991:	test   %dl,%dl
   30993:	mov    %eax,0x8(%r14)
   30997:	mov    %edx,%r9d
   3099a:	mov    %edx,0x18(%r14)
   3099e:	mov    0x4(%r15),%eax
   309a2:	je     30bf1 <ngettext+0x771>
   309a8:	bswap  %eax
   309aa:	cmp    $0x1ffff,%eax
   309af:	ja     30bbc <ngettext+0x73c>
   309b5:	mov    0x8(%r15),%ecx
   309b9:	bswap  %ecx
   309bb:	mov    %ecx,0x28(%r14)
   309bf:	mov    0xc(%r15),%ecx
   309c3:	bswap  %ecx
   309c5:	mov    %ecx,%ecx
   309c7:	add    %r15,%rcx
   309ca:	mov    %rcx,0x30(%r14)
   309ce:	mov    0x10(%r15),%ecx
   309d2:	bswap  %ecx
   309d4:	mov    %ecx,%ecx
   309d6:	add    %r15,%rcx
   309d9:	mov    %rcx,0x38(%r14)
   309dd:	mov    0x14(%r15),%ecx
   309e1:	bswap  %ecx
   309e3:	cmp    $0x2,%ecx
   309e6:	mov    %ecx,-0xf0(%rbp)
   309ec:	mov    %ecx,0x58(%r14)
   309f0:	jbe    30bab <ngettext+0x72b>
   309f6:	mov    0x18(%r15),%ecx
   309fa:	bswap  %ecx
   309fc:	mov    %ecx,%ecx
   309fe:	add    %r15,%rcx
   30a01:	test   %ax,%ax
   30a04:	mov    %edx,0x68(%r14)
   30a08:	mov    %rcx,0x60(%r14)
   30a0c:	je     30c32 <ngettext+0x7b2>
   30a12:	test   %rcx,%rcx
   30a15:	je     30bbc <ngettext+0x73c>
   30a1b:	test   %r9b,%r9b
   30a1e:	mov    0x24(%r15),%eax
   30a22:	je     30de2 <ngettext+0x962>
   30a28:	bswap  %eax
   30a2a:	test   %eax,%eax
   30a2c:	mov    %eax,-0x108(%rbp)
   30a32:	je     30c32 <ngettext+0x7b2>
   30a38:	mov    0x1c(%r15),%eax
   30a3c:	bswap  %eax
   30a3e:	mov    %eax,%ecx
   30a40:	mov    %eax,-0xd8(%rbp)
   30a46:	mov    0x20(%r15),%eax
   30a4a:	bswap  %eax
   30a4c:	mov    %eax,%eax
   30a4e:	lea    (%r15,%rax,1),%rdx
   30a52:	mov    %ecx,%eax
   30a54:	lea    0x1e(,%rax,8),%rax
   30a5c:	shr    $0x4,%rax
   30a60:	shl    $0x4,%rax
   30a64:	sub    %rax,%rsp
   30a67:	lea    0xf(%rsp),%rax
   30a6c:	and    $0xfffffffffffffff0,%rax
   30a70:	test   %ecx,%ecx
   30a72:	mov    %rax,-0xe8(%rbp)
   30a79:	je     311fe <ngettext+0xd7e>
   30a7f:	lea    0x4(%rdx),%rdi
   30a83:	xor    %esi,%esi
   30a85:	xor    %r10d,%r10d
   30a88:	mov    %r12,-0xf8(%rbp)
   30a8f:	mov    %r14,-0x100(%rbp)
   30a96:	mov    %rbx,-0x110(%rbp)
   30a9d:	mov    %r13,-0x120(%rbp)
   30aa4:	jmp    30b0f <ngettext+0x68f>
   30aa6:	mov    (%rdi),%edx
   30aa8:	mov    -0x4(%rdi),%eax
   30aab:	bswap  %edx
   30aad:	bswap  %eax
   30aaf:	mov    %edx,%edx
   30ab1:	add    %r15,%rdx
   30ab4:	test   %eax,%eax
   30ab6:	je     311bb <ngettext+0xd3b>
   30abc:	sub    $0x1,%eax
   30abf:	cmpb   $0x0,(%rdx,%rax,1)
   30ac3:	jne    311bb <ngettext+0xd3b>
   30ac9:	movzbl (%rdx),%ecx
   30acc:	xor    %eax,%eax
   30ace:	cmp    $0x50,%cl
   30ad1:	je     30cac <ngettext+0x82c>
   30ad7:	cmp    $0x49,%cl
   30ada:	jne    30aeb <ngettext+0x66b>
   30adc:	cmpb   $0x0,0x1(%rdx)
   30ae0:	lea    0x15e84d(%rip),%rcx        # 18f334 <_libc_intl_domainname+0x310b>
   30ae7:	cmove  %rcx,%rax
   30aeb:	mov    -0xe8(%rbp),%rcx
   30af2:	add    $0x1,%r10d
   30af6:	add    $0x8,%rdi
   30afa:	mov    %rax,(%rcx,%rsi,1)
   30afe:	add    $0x8,%rsi
   30b02:	cmp    -0xd8(%rbp),%r10d
   30b09:	jae    311d9 <ngettext+0xd59>
   30b0f:	test   %r9b,%r9b
   30b12:	jne    30aa6 <ngettext+0x626>
   30b14:	mov    (%rdi),%edx
   30b16:	mov    -0x4(%rdi),%eax
   30b19:	add    %r15,%rdx
   30b1c:	jmp    30ab4 <ngettext+0x634>
   30b1e:	mov    %r12,%rdi
   30b21:	callq  1f460 <malloc@plt>
   30b26:	test   %rax,%rax
   30b29:	mov    %rax,%r15
   30b2c:	je     30879 <ngettext+0x3f9>
   30b32:	mov    %rax,-0xd8(%rbp)
   30b39:	mov    %r12,-0xe0(%rbp)
   30b40:	mov    -0xe0(%rbp),%rdx
   30b47:	mov    -0xd8(%rbp),%rsi
   30b4e:	mov    %r14d,%edi
   30b51:	callq  f7479 <__read+0x9>
   30b56:	cltq   
   30b58:	test   %rax,%rax
   30b5b:	jle    30d9d <ngettext+0x91d>
   30b61:	add    %rax,-0xd8(%rbp)
   30b68:	sub    %rax,-0xe0(%rbp)
   30b6f:	jne    30b40 <ngettext+0x6c0>
   30b71:	movslq %r14d,%rdi
   30b74:	mov    $0x3,%eax
   30b79:	syscall 
   30b7b:	mov    (%r15),%edx
   30b7e:	cmp    $0x950412de,%edx
   30b84:	setne  %al
   30b87:	cmp    $0xde120495,%edx
   30b8d:	mov    %eax,%r9d
   30b90:	je     31256 <ngettext+0xdd6>
   30b96:	test   %al,%al
   30b98:	je     31256 <ngettext+0xdd6>
   30b9e:	mov    %r15,%rdi
   30ba1:	callq  1f4c0 <free@plt>
   30ba6:	jmpq   30883 <ngettext+0x403>
   30bab:	test   %ax,%ax
   30bae:	movq   $0x0,0x60(%r14)
   30bb6:	mov    %edx,0x68(%r14)
   30bba:	je     30c32 <ngettext+0x7b2>
   30bbc:	xor    %edi,%edi
   30bbe:	callq  1f4c0 <free@plt>
   30bc3:	mov    -0xe0(%rbp),%eax
   30bc9:	test   %eax,%eax
   30bcb:	je     30d90 <ngettext+0x910>
   30bd1:	mov    %r12,%rsi
   30bd4:	mov    %r15,%rdi
   30bd7:	callq  101750 <munmap>
   30bdc:	mov    %r14,%rdi
   30bdf:	callq  1f4c0 <free@plt>
   30be4:	movq   $0x0,0x10(%rbx)
   30bec:	jmpq   30883 <ngettext+0x403>
   30bf1:	cmp    $0x1ffff,%eax
   30bf6:	ja     30bbc <ngettext+0x73c>
   30bf8:	mov    0x8(%r15),%ecx
   30bfc:	mov    %ecx,0x28(%r14)
   30c00:	mov    0xc(%r15),%ecx
   30c04:	add    %r15,%rcx
   30c07:	mov    %rcx,0x30(%r14)
   30c0b:	mov    0x10(%r15),%ecx
   30c0f:	add    %r15,%rcx
   30c12:	mov    %rcx,0x38(%r14)
   30c16:	mov    0x14(%r15),%ecx
   30c1a:	cmp    $0x2,%ecx
   30c1d:	mov    %ecx,-0xf0(%rbp)
   30c23:	mov    %ecx,0x58(%r14)
   30c27:	jbe    30bab <ngettext+0x72b>
   30c29:	mov    0x18(%r15),%ecx
   30c2d:	jmpq   309fe <ngettext+0x57e>
   30c32:	movl   $0x0,0x40(%r14)
   30c3a:	movq   $0x0,0x48(%r14)
   30c42:	movq   $0x0,0x50(%r14)
   30c4a:	lea    0x80(%r14),%rdx
   30c51:	xor    %eax,%eax
   30c53:	mov    $0x7,%ecx
   30c58:	movq   $0x0,0x70(%r14)
   30c60:	movq   $0x0,0x78(%r14)
   30c68:	lea    -0xd0(%rbp),%r8
   30c6f:	mov    %rdx,%rdi
   30c72:	lea    0x15b515(%rip),%rdx        # 18c18e <_itoa_lower_digits+0x6d4e>
   30c79:	mov    %r13,%rsi
   30c7c:	rep stos %rax,%es:(%rdi)
   30c7f:	mov    %rbx,%rdi
   30c82:	callq  2ed00 <gettext+0x260>
   30c87:	cmp    $0xffffffffffffffff,%rax
   30c8b:	je     30dd9 <ngettext+0x959>
   30c91:	lea    0xc0(%r14),%rdx
   30c98:	lea    0xb8(%r14),%rsi
   30c9f:	mov    %rax,%rdi
   30ca2:	callq  33840 <textdomain+0x1450>
   30ca7:	jmpq   30883 <ngettext+0x403>
   30cac:	cmpb   $0x52,0x1(%rdx)
   30cb0:	jne    30aeb <ngettext+0x66b>
   30cb6:	cmpb   $0x49,0x2(%rdx)
   30cba:	jne    30aeb <ngettext+0x66b>
   30cc0:	movzbl 0x3(%rdx),%r14d
   30cc5:	cmp    $0x64,%r14b
   30cc9:	mov    %r14b,-0x118(%rbp)
   30cd0:	sete   %bl
   30cd3:	cmp    $0x69,%r14b
   30cd7:	sete   %r11b
   30cdb:	cmp    $0x6f,%r14b
   30cdf:	sete   %r8b
   30ce3:	cmp    $0x75,%r14b
   30ce7:	sete   %cl
   30cea:	cmp    $0x78,%r14b
   30cee:	sete   %r13b
   30cf2:	cmp    $0x58,%r14b
   30cf6:	mov    %r11d,%r14d
   30cf9:	sete   %r12b
   30cfd:	or     %ebx,%r14d
   30d00:	or     %r8d,%r14d
   30d03:	or     %cl,%r14b
   30d06:	jne    30d1e <ngettext+0x89e>
   30d08:	movzbl -0x118(%rbp),%r14d
   30d10:	and    $0xffffffdf,%r14d
   30d14:	cmp    $0x58,%r14b
   30d18:	jne    30aeb <ngettext+0x66b>
   30d1e:	movzbl 0x4(%rdx),%r14d
   30d23:	cmp    $0x38,%r14b
   30d27:	je     312ff <ngettext+0xe7f>
   30d2d:	xor    %eax,%eax
   30d2f:	cmp    $0x31,%r14b
   30d33:	jne    31265 <ngettext+0xde5>
   30d39:	cmpb   $0x36,0x5(%rdx)
   30d3d:	jne    30aeb <ngettext+0x66b>
   30d43:	cmpb   $0x0,0x6(%rdx)
   30d47:	jne    30aeb <ngettext+0x66b>
   30d4d:	test   %bl,%bl
   30d4f:	jne    315f6 <ngettext+0x1176>
   30d55:	test   %r11b,%r11b
   30d58:	jne    315ea <ngettext+0x116a>
   30d5e:	test   %r8b,%r8b
   30d61:	jne    3161f <ngettext+0x119f>
   30d67:	test   %cl,%cl
   30d69:	jne    31613 <ngettext+0x1193>
   30d6f:	test   %r13b,%r13b
   30d72:	jne    31607 <ngettext+0x1187>
   30d78:	test   %r12b,%r12b
   30d7b:	je     31602 <ngettext+0x1182>
   30d81:	lea    0x15c709(%rip),%rax        # 18d491 <_libc_intl_domainname+0x1268>
   30d88:	jmpq   30aeb <ngettext+0x66b>
   30d8d:	nopl   (%rax)
   30d90:	mov    %r15,%rdi
   30d93:	callq  1f4c0 <free@plt>
   30d98:	jmpq   30bdc <ngettext+0x75c>
   30d9d:	cmp    $0xffffffffffffffff,%rax
   30da1:	jne    30879 <ngettext+0x3f9>
   30da7:	mov    0x3930ba(%rip),%rax        # 3c3e68 <_IO_file_jumps+0x628>
   30dae:	cmpl   $0x4,%fs:(%rax)
   30db2:	jne    30879 <ngettext+0x3f9>
   30db8:	jmpq   30b40 <ngettext+0x6c0>
   30dbd:	mov    -0xf8(%rbp),%r15
   30dc4:	mov    -0x110(%rbp),%r12
   30dcb:	mov    -0x120(%rbp),%r14
   30dd2:	mov    -0x128(%rbp),%rbx
   30dd9:	mov    0x20(%r14),%rdi
   30ddd:	jmpq   30bbe <ngettext+0x73e>
   30de2:	test   %eax,%eax
   30de4:	mov    %eax,-0x108(%rbp)
   30dea:	je     30c32 <ngettext+0x7b2>
   30df0:	mov    0x1c(%r15),%eax
   30df4:	mov    %eax,%ecx
   30df6:	mov    %eax,-0xd8(%rbp)
   30dfc:	mov    0x20(%r15),%eax
   30e00:	lea    (%r15,%rax,1),%rdx
   30e04:	mov    %ecx,%eax
   30e06:	lea    0x1e(,%rax,8),%rax
   30e0e:	shr    $0x4,%rax
   30e12:	shl    $0x4,%rax
   30e16:	sub    %rax,%rsp
   30e19:	lea    0xf(%rsp),%rax
   30e1e:	and    $0xfffffffffffffff0,%rax
   30e22:	test   %ecx,%ecx
   30e24:	mov    %rax,-0xe8(%rbp)
   30e2b:	jne    30a7f <ngettext+0x5ff>
   30e31:	mov    0x28(%r15),%eax
   30e35:	add    %r15,%rax
   30e38:	mov    %rax,-0x100(%rbp)
   30e3f:	mov    0x2c(%r15),%eax
   30e43:	add    %r15,%rax
   30e46:	mov    %r15,-0xf8(%rbp)
   30e4d:	mov    -0xe8(%rbp),%r15
   30e54:	mov    %rax,-0x118(%rbp)
   30e5b:	mov    -0xf0(%rbp),%eax
   30e61:	mov    %r13,-0x148(%rbp)
   30e68:	movl   $0x0,-0xf0(%rbp)
   30e72:	mov    %r12,-0x110(%rbp)
   30e79:	mov    %r14,-0x120(%rbp)
   30e80:	mov    %r9b,-0x140(%rbp)
   30e87:	mov    %rbx,-0x128(%rbp)
   30e8e:	shl    $0x2,%rax
   30e92:	mov    %rax,-0x138(%rbp)
   30e99:	mov    %rax,-0x130(%rbp)
   30ea0:	xor    %eax,%eax
   30ea2:	mov    %rax,%r13
   30ea5:	xor    %r14d,%r14d
   30ea8:	cmpb   $0x0,-0x140(%rbp)
   30eaf:	je     31151 <ngettext+0xcd1>
   30eb5:	test   %r14,%r14
   30eb8:	je     31d27 <ngettext+0x18a7>
   30ebe:	mov    -0x118(%rbp),%rax
   30ec5:	mov    (%rax,%r13,4),%eax
   30ec9:	bswap  %eax
   30ecb:	mov    %eax,%edx
   30ecd:	add    -0xf8(%rbp),%rdx
   30ed4:	cmpl   $0xffffffff,0x8(%rdx)
   30ed8:	je     30f3b <ngettext+0xabb>
   30eda:	lea    0x4(%rdx),%r12
   30ede:	xor    %ebx,%ebx
   30ee0:	jmp    30f0b <ngettext+0xa8b>
   30ee2:	nopw   0x0(%rax,%rax,1)
   30ee8:	cmp    -0xd8(%rbp),%eax
   30eee:	jae    30dbd <ngettext+0x93d>
   30ef4:	mov    %eax,%eax
   30ef6:	mov    (%r15,%rax,8),%rdi
   30efa:	test   %rdi,%rdi
   30efd:	je     30f5b <ngettext+0xadb>
   30eff:	callq  8b6d0 <strlen>
   30f04:	add    $0x8,%r12
   30f08:	add    %rax,%rbx
   30f0b:	mov    (%r12),%eax
   30f0f:	bswap  %eax
   30f11:	mov    %eax,%eax
   30f13:	add    %rax,%rbx
   30f16:	mov    0x4(%r12),%eax
   30f1b:	bswap  %eax
   30f1d:	cmp    $0xffffffff,%eax
   30f20:	jne    30ee8 <ngettext+0xa68>
   30f22:	cmp    $0x1,%r14
   30f26:	mov    %rbx,-0xd0(%rbp,%r14,8)
   30f2e:	je     30f3f <ngettext+0xabf>
   30f30:	mov    $0x1,%r14d
   30f36:	jmpq   30ea8 <ngettext+0xa28>
   30f3b:	xor    %ebx,%ebx
   30f3d:	jmp    30f22 <ngettext+0xaa2>
   30f3f:	mov    -0xd0(%rbp),%rax
   30f46:	add    -0xc8(%rbp),%rax
   30f4d:	addl   $0x1,-0xf0(%rbp)
   30f54:	add    %rax,-0x130(%rbp)
   30f5b:	add    $0x1,%r13
   30f5f:	cmp    %r13d,-0x108(%rbp)
   30f66:	ja     30ea5 <ngettext+0xa25>
   30f6c:	cmpl   $0x0,-0xf0(%rbp)
   30f73:	mov    -0xf8(%rbp),%r15
   30f7a:	mov    -0x110(%rbp),%r12
   30f81:	mov    -0x120(%rbp),%r14
   30f88:	mov    -0x128(%rbp),%rbx
   30f8f:	mov    -0x148(%rbp),%r13
   30f96:	je     30c32 <ngettext+0x7b2>
   30f9c:	mov    -0xf0(%rbp),%eax
   30fa2:	lea    (%rax,%rax,1),%edi
   30fa5:	shl    $0x4,%rdi
   30fa9:	add    -0x130(%rbp),%rdi
   30fb0:	callq  1f460 <malloc@plt>
   30fb5:	test   %rax,%rax
   30fb8:	mov    %rax,-0xf8(%rbp)
   30fbf:	je     30dd9 <ngettext+0x959>
   30fc5:	mov    -0xf0(%rbp),%eax
   30fcb:	mov    -0xf8(%rbp),%rcx
   30fd2:	mov    -0x138(%rbp),%r10
   30fd9:	mov    -0x100(%rbp),%r9
   30fe0:	movl   $0x0,-0xd8(%rbp)
   30fea:	mov    %r12,-0x138(%rbp)
   30ff1:	mov    %rcx,0x20(%r14)
   30ff5:	mov    %rbx,-0x140(%rbp)
   30ffc:	shl    $0x4,%rax
   31000:	mov    %r13,-0x148(%rbp)
   31007:	add    %rax,%rcx
   3100a:	add    %rcx,%rax
   3100d:	mov    %rcx,-0x120(%rbp)
   31014:	mov    %rax,-0x110(%rbp)
   3101b:	add    %rax,%r10
   3101e:	mov    -0x118(%rbp),%rax
   31025:	mov    %rax,-0x100(%rbp)
   3102c:	mov    -0x108(%rbp),%eax
   31032:	mov    %r14,-0x108(%rbp)
   31039:	lea    (%r9,%rax,4),%rax
   3103d:	mov    %rax,-0x130(%rbp)
   31044:	cmp    -0x130(%rbp),%r9
   3104b:	je     314a7 <ngettext+0x1027>
   31051:	mov    -0x108(%rbp),%rax
   31058:	mov    -0xe8(%rbp),%rcx
   3105f:	xor    %edx,%edx
   31061:	mov    -0x100(%rbp),%rsi
   31068:	mov    0x18(%rax),%r8d
   3106c:	test   %r8d,%r8d
   3106f:	je     3121d <ngettext+0xd9d>
   31075:	test   %edx,%edx
   31077:	je     3149f <ngettext+0x101f>
   3107d:	mov    (%rsi),%eax
   3107f:	bswap  %eax
   31081:	mov    %eax,%eax
   31083:	add    %r15,%rax
   31086:	cmpl   $0xffffffff,0x8(%rax)
   3108a:	je     310ad <ngettext+0xc2d>
   3108c:	add    $0x4,%rax
   31090:	jmp    310a3 <ngettext+0xc23>
   31092:	mov    %edi,%edi
   31094:	cmpq   $0x0,(%rcx,%rdi,8)
   31099:	je     31140 <ngettext+0xcc0>
   3109f:	add    $0x8,%rax
   310a3:	mov    0x4(%rax),%edi
   310a6:	bswap  %edi
   310a8:	cmp    $0xffffffff,%edi
   310ab:	jne    31092 <ngettext+0xc12>
   310ad:	sub    $0x1,%edx
   310b0:	jne    3143d <ngettext+0xfbd>
   310b6:	mov    -0xd8(%rbp),%eax
   310bc:	mov    -0xf8(%rbp),%rcx
   310c3:	xor    %r11d,%r11d
   310c6:	shl    $0x4,%rax
   310ca:	add    %rax,%rcx
   310cd:	add    -0x120(%rbp),%rax
   310d4:	mov    %rcx,-0x128(%rbp)
   310db:	mov    %rax,-0x118(%rbp)
   310e2:	test   %r8d,%r8d
   310e5:	je     3140d <ngettext+0xf8d>
   310eb:	test   %r11d,%r11d
   310ee:	je     31d05 <ngettext+0x1885>
   310f4:	mov    -0x100(%rbp),%rax
   310fb:	mov    -0x118(%rbp),%r14
   31102:	mov    (%rax),%ebx
   31104:	bswap  %ebx
   31106:	mov    %ebx,%ebx
   31108:	add    %r15,%rbx
   3110b:	mov    (%rbx),%r12d
   3110e:	bswap  %r12d
   31111:	mov    %r12d,%r12d
   31114:	add    %r15,%r12
   31117:	cmpl   $0xffffffff,0x8(%rbx)
   3111b:	jne    31349 <ngettext+0xec9>
   31121:	mov    0x4(%rbx),%eax
   31124:	bswap  %eax
   31126:	mov    %eax,%eax
   31128:	mov    %rax,(%r14)
   3112b:	mov    %r12,0x8(%r14)
   3112f:	sub    $0x1,%r11d
   31133:	jne    31d37 <ngettext+0x18b7>
   31139:	addl   $0x1,-0xd8(%rbp)
   31140:	add    $0x4,%r9
   31144:	addq   $0x4,-0x100(%rbp)
   3114c:	jmpq   31044 <ngettext+0xbc4>
   31151:	test   %r14,%r14
   31154:	je     31d4d <ngettext+0x18cd>
   3115a:	mov    -0x118(%rbp),%rax
   31161:	mov    (%rax,%r13,4),%edx
   31165:	add    -0xf8(%rbp),%rdx
   3116c:	cmpl   $0xffffffff,0x8(%rdx)
   31170:	je     30f3b <ngettext+0xabb>
   31176:	lea    0x4(%rdx),%r12
   3117a:	xor    %ebx,%ebx
   3117c:	jmp    311a5 <ngettext+0xd25>
   3117e:	xchg   %ax,%ax
   31180:	cmp    -0xd8(%rbp),%eax
   31186:	jae    30dbd <ngettext+0x93d>
   3118c:	mov    (%r15,%rax,8),%rdi
   31190:	test   %rdi,%rdi
   31193:	je     30f5b <ngettext+0xadb>
   31199:	callq  8b6d0 <strlen>
   3119e:	add    $0x8,%r12
   311a2:	add    %rax,%rbx
   311a5:	mov    (%r12),%eax
   311a9:	add    %rax,%rbx
   311ac:	mov    0x4(%r12),%eax
   311b1:	cmp    $0xffffffff,%eax
   311b4:	jne    31180 <ngettext+0xd00>
   311b6:	jmpq   30f22 <ngettext+0xaa2>
   311bb:	mov    -0x100(%rbp),%r14
   311c2:	mov    -0xf8(%rbp),%r12
   311c9:	mov    -0x110(%rbp),%rbx
   311d0:	mov    0x20(%r14),%rdi
   311d4:	jmpq   30bbe <ngettext+0x73e>
   311d9:	test   %r9b,%r9b
   311dc:	mov    -0xf8(%rbp),%r12
   311e3:	mov    -0x100(%rbp),%r14
   311ea:	mov    -0x110(%rbp),%rbx
   311f1:	mov    -0x120(%rbp),%r13
   311f8:	je     30e31 <ngettext+0x9b1>
   311fe:	mov    0x28(%r15),%eax
   31202:	bswap  %eax
   31204:	mov    %eax,%eax
   31206:	add    %r15,%rax
   31209:	mov    %rax,-0x100(%rbp)
   31210:	mov    0x2c(%r15),%eax
   31214:	bswap  %eax
   31216:	mov    %eax,%eax
   31218:	jmpq   30e43 <ngettext+0x9c3>
   3121d:	test   %edx,%edx
   3121f:	je     31d5d <ngettext+0x18dd>
   31225:	mov    (%rsi),%eax
   31227:	add    %r15,%rax
   3122a:	cmpl   $0xffffffff,0x8(%rax)
   3122e:	je     310ad <ngettext+0xc2d>
   31234:	add    $0x4,%rax
   31238:	jmp    31249 <ngettext+0xdc9>
   3123a:	cmpq   $0x0,(%rcx,%rdi,8)
   3123f:	je     31140 <ngettext+0xcc0>
   31245:	add    $0x8,%rax
   31249:	mov    0x4(%rax),%edi
   3124c:	cmp    $0xffffffff,%edi
   3124f:	jne    3123a <ngettext+0xdba>
   31251:	jmpq   310ad <ngettext+0xc2d>
   31256:	movl   $0x0,-0xe0(%rbp)
   31260:	jmpq   30954 <ngettext+0x4d4>
   31265:	cmp    $0x33,%r14b
   31269:	je     31be6 <ngettext+0x1766>
   3126f:	cmp    $0x36,%r14b
   31273:	je     31b96 <ngettext+0x1716>
   31279:	cmp    $0x4c,%r14b
   3127d:	je     31749 <ngettext+0x12c9>
   31283:	cmp    $0x46,%r14b
   31287:	je     316a8 <ngettext+0x1228>
   3128d:	cmp    $0x4d,%r14b
   31291:	je     3164a <ngettext+0x11ca>
   31297:	cmp    $0x50,%r14b
   3129b:	jne    30aeb <ngettext+0x66b>
   312a1:	cmpb   $0x54,0x5(%rdx)
   312a5:	jne    30aeb <ngettext+0x66b>
   312ab:	cmpb   $0x52,0x6(%rdx)
   312af:	jne    30aeb <ngettext+0x66b>
   312b5:	cmpb   $0x0,0x7(%rdx)
   312b9:	jne    31643 <ngettext+0x11c3>
   312bf:	test   %bl,%bl
   312c1:	jne    31637 <ngettext+0x11b7>
   312c7:	test   %r11b,%r11b
   312ca:	jne    3162b <ngettext+0x11ab>
   312d0:	test   %r8b,%r8b
   312d3:	jne    31ced <ngettext+0x186d>
   312d9:	test   %cl,%cl
   312db:	jne    31ce1 <ngettext+0x1861>
   312e1:	test   %r13b,%r13b
   312e4:	jne    31cf9 <ngettext+0x1879>
   312ea:	test   %r12b,%r12b
   312ed:	je     31602 <ngettext+0x1182>
   312f3:	lea    0x15af76(%rip),%rax        # 18c270 <_libc_intl_domainname+0x47>
   312fa:	jmpq   30aeb <ngettext+0x66b>
   312ff:	cmpb   $0x0,0x5(%rdx)
   31303:	jne    31447 <ngettext+0xfc7>
   31309:	test   %bl,%bl
   3130b:	jne    3147b <ngettext+0xffb>
   31311:	test   %r11b,%r11b
   31314:	jne    31493 <ngettext+0x1013>
   3131a:	test   %r8b,%r8b
   3131d:	jne    31487 <ngettext+0x1007>
   31323:	test   %cl,%cl
   31325:	jne    3145a <ngettext+0xfda>
   3132b:	test   %r13b,%r13b
   3132e:	jne    3144e <ngettext+0xfce>
   31334:	test   %r12b,%r12b
   31337:	je     31602 <ngettext+0x1182>
   3133d:	lea    0x15c14d(%rip),%rax        # 18d491 <_libc_intl_domainname+0x1268>
   31344:	jmpq   30aeb <ngettext+0x66b>
   31349:	mov    %r10,0x8(%r14)
   3134d:	mov    %r14,-0x160(%rbp)
   31354:	add    $0x4,%rbx
   31358:	mov    %r9,-0x150(%rbp)
   3135f:	mov    %r11d,-0x154(%rbp)
   31366:	mov    %r8d,%r14d
   31369:	jmp    313b4 <ngettext+0xf34>
   3136b:	mov    0x4(%rbx),%ecx
   3136e:	bswap  %r13d
   31371:	bswap  %ecx
   31373:	test   %r13d,%r13d
   31376:	jne    313c1 <ngettext+0xf41>
   31378:	cmp    $0xffffffff,%ecx
   3137b:	je     313e9 <ngettext+0xf69>
   3137d:	mov    -0xe8(%rbp),%rax
   31384:	mov    %ecx,%ecx
   31386:	add    $0x8,%rbx
   3138a:	mov    (%rax,%rcx,8),%rsi
   3138e:	xor    %eax,%eax
   31390:	or     $0xffffffffffffffff,%rcx
   31394:	mov    %rsi,%rdi
   31397:	repnz scas %es:(%rdi),%al
   31399:	mov    %r10,%rdi
   3139c:	mov    %rcx,%rax
   3139f:	not    %rax
   313a2:	lea    -0x1(%rax),%r13
   313a6:	mov    %r13,%rdx
   313a9:	callq  943f0 <memcpy+0x70>
   313ae:	mov    %rax,%r10
   313b1:	add    %r13,%r10
   313b4:	test   %r14d,%r14d
   313b7:	mov    (%rbx),%r13d
   313ba:	jne    3136b <ngettext+0xeeb>
   313bc:	mov    0x4(%rbx),%ecx
   313bf:	jmp    31373 <ngettext+0xef3>
   313c1:	mov    %r13d,%r13d
   313c4:	mov    %r12,%rsi
   313c7:	mov    %r10,%rdi
   313ca:	mov    %r13,%rdx
   313cd:	mov    %ecx,-0x158(%rbp)
   313d3:	add    %r13,%r12
   313d6:	callq  943f0 <memcpy+0x70>
   313db:	mov    %rax,%r10
   313de:	mov    -0x158(%rbp),%ecx
   313e4:	add    %r13,%r10
   313e7:	jmp    31378 <ngettext+0xef8>
   313e9:	mov    -0x160(%rbp),%r14
   313f0:	mov    %r10,%rax
   313f3:	mov    -0x150(%rbp),%r9
   313fa:	mov    -0x154(%rbp),%r11d
   31401:	sub    0x8(%r14),%rax
   31405:	mov    %rax,(%r14)
   31408:	jmpq   3112f <ngettext+0xcaf>
   3140d:	test   %r11d,%r11d
   31410:	je     31466 <ngettext+0xfe6>
   31412:	mov    -0x100(%rbp),%rax
   31419:	mov    -0x118(%rbp),%r14
   31420:	mov    (%rax),%ebx
   31422:	add    %r15,%rbx
   31425:	mov    (%rbx),%r12d
   31428:	add    %r15,%r12
   3142b:	cmpl   $0xffffffff,0x8(%rbx)
   3142f:	jne    31349 <ngettext+0xec9>
   31435:	mov    0x4(%rbx),%eax
   31438:	jmpq   31128 <ngettext+0xca8>
   3143d:	mov    $0x1,%edx
   31442:	jmpq   3106c <ngettext+0xbec>
   31447:	xor    %eax,%eax
   31449:	jmpq   30aeb <ngettext+0x66b>
   3144e:	lea    0x15db22(%rip),%rax        # 18ef77 <_libc_intl_domainname+0x2d4e>
   31455:	jmpq   30aeb <ngettext+0x66b>
   3145a:	lea    0x15d5e2(%rip),%rax        # 18ea43 <_libc_intl_domainname+0x281a>
   31461:	jmpq   30aeb <ngettext+0x66b>
   31466:	mov    (%r9),%ebx
   31469:	mov    -0x128(%rbp),%r14
   31470:	add    %r15,%rbx
   31473:	mov    (%rbx),%r12d
   31476:	add    %r15,%r12
   31479:	jmp    3142b <ngettext+0xfab>
   3147b:	lea    0x15af10(%rip),%rax        # 18c392 <_libc_intl_domainname+0x169>
   31482:	jmpq   30aeb <ngettext+0x66b>
   31487:	lea    0x15cd86(%rip),%rax        # 18e214 <_libc_intl_domainname+0x1feb>
   3148e:	jmpq   30aeb <ngettext+0x66b>
   31493:	lea    0x15a9d6(%rip),%rax        # 18be70 <_itoa_lower_digits+0x6a30>
   3149a:	jmpq   30aeb <ngettext+0x66b>
   3149f:	mov    (%r9),%eax
   314a2:	jmpq   3107f <ngettext+0xbff>
   314a7:	mov    -0xf0(%rbp),%ecx
   314ad:	cmp    %ecx,-0xd8(%rbp)
   314b3:	mov    -0x138(%rbp),%r12
   314ba:	mov    -0x108(%rbp),%r14
   314c1:	mov    -0x140(%rbp),%rbx
   314c8:	mov    -0x148(%rbp),%r13
   314cf:	jne    31602 <ngettext+0x1182>
   314d5:	mov    0x58(%r14),%ecx
   314d9:	xor    %eax,%eax
   314db:	jmp    314fb <ngettext+0x107b>
   314dd:	cmpl   $0x0,0x68(%r14)
   314e2:	mov    0x60(%r14),%rdx
   314e6:	mov    (%rdx,%rax,4),%edx
   314e9:	je     314ed <ngettext+0x106d>
   314eb:	bswap  %edx
   314ed:	mov    -0x110(%rbp),%rsi
   314f4:	mov    %edx,(%rsi,%rax,4)
   314f7:	add    $0x1,%rax
   314fb:	cmp    %eax,%ecx
   314fd:	ja     314dd <ngettext+0x105d>
   314ff:	mov    %r13,%r8
   31502:	xor    %r9d,%r9d
   31505:	mov    %rbx,%r13
   31508:	cmp    -0xd8(%rbp),%r9d
   3150f:	mov    %r9d,%ebx
   31512:	jae    315ac <ngettext+0x112c>
   31518:	mov    -0xf8(%rbp),%rcx
   3151f:	mov    %r9,%rax
   31522:	mov    %r8,-0xf0(%rbp)
   31529:	shl    $0x4,%rax
   3152d:	mov    %r9,-0xe8(%rbp)
   31534:	mov    0x8(%rcx,%rax,1),%rdi
   31539:	callq  33920 <textdomain+0x1530>
   3153e:	mov    0x58(%r14),%edi
   31542:	xor    %edx,%edx
   31544:	mov    %eax,%ecx
   31546:	mov    -0xe8(%rbp),%r9
   3154d:	mov    -0xf0(%rbp),%r8
   31554:	div    %edi
   31556:	lea    -0x2(%rdi),%r10d
   3155a:	mov    %ecx,%eax
   3155c:	mov    %edx,%esi
   3155e:	xor    %edx,%edx
   31560:	div    %r10d
   31563:	mov    %edi,%r10d
   31566:	lea    0x1(%rdx),%eax
   31569:	mov    %eax,%ecx
   3156b:	sub    %eax,%r10d
   3156e:	sub    %edi,%ecx
   31570:	jmp    31586 <ngettext+0x1106>
   31572:	nopw   0x0(%rax,%rax,1)
   31578:	lea    (%rsi,%rcx,1),%edx
   3157b:	lea    (%rsi,%rax,1),%edi
   3157e:	cmp    %r10d,%esi
   31581:	cmovb  %edi,%edx
   31584:	mov    %edx,%esi
   31586:	mov    -0x110(%rbp),%rdi
   3158d:	mov    %esi,%edx
   3158f:	lea    (%rdi,%rdx,4),%rdx
   31593:	mov    (%rdx),%edi
   31595:	test   %edi,%edi
   31597:	jne    31578 <ngettext+0x10f8>
   31599:	mov    0x28(%r14),%eax
   3159d:	add    $0x1,%r9
   315a1:	lea    0x1(%rbx,%rax,1),%eax
   315a5:	mov    %eax,(%rdx)
   315a7:	jmpq   31508 <ngettext+0x1088>
   315ac:	mov    -0xd8(%rbp),%eax
   315b2:	mov    %r13,%rbx
   315b5:	movl   $0x0,0x68(%r14)
   315bd:	mov    %r8,%r13
   315c0:	mov    %eax,0x40(%r14)
   315c4:	mov    -0xf8(%rbp),%rax
   315cb:	mov    %rax,0x48(%r14)
   315cf:	mov    -0x120(%rbp),%rax
   315d6:	mov    %rax,0x50(%r14)
   315da:	mov    -0x110(%rbp),%rax
   315e1:	mov    %rax,0x60(%r14)
   315e5:	jmpq   30c4a <ngettext+0x7ca>
   315ea:	lea    0x15a87f(%rip),%rax        # 18be70 <_itoa_lower_digits+0x6a30>
   315f1:	jmpq   30aeb <ngettext+0x66b>
   315f6:	lea    0x15ad95(%rip),%rax        # 18c392 <_libc_intl_domainname+0x169>
   315fd:	jmpq   30aeb <ngettext+0x66b>
   31602:	callq  36d60 <abort>
   31607:	lea    0x15d969(%rip),%rax        # 18ef77 <_libc_intl_domainname+0x2d4e>
   3160e:	jmpq   30aeb <ngettext+0x66b>
   31613:	lea    0x15d429(%rip),%rax        # 18ea43 <_libc_intl_domainname+0x281a>
   3161a:	jmpq   30aeb <ngettext+0x66b>
   3161f:	lea    0x15cbee(%rip),%rax        # 18e214 <_libc_intl_domainname+0x1feb>
   31626:	jmpq   30aeb <ngettext+0x66b>
   3162b:	lea    0x15ac3b(%rip),%rax        # 18c26d <_libc_intl_domainname+0x44>
   31632:	jmpq   30aeb <ngettext+0x66b>
   31637:	lea    0x15d46f(%rip),%rax        # 18eaad <_libc_intl_domainname+0x2884>
   3163e:	jmpq   30aeb <ngettext+0x66b>
   31643:	xor    %eax,%eax
   31645:	jmpq   30aeb <ngettext+0x66b>
   3164a:	cmpb   $0x41,0x5(%rdx)
   3164e:	jne    30aeb <ngettext+0x66b>
   31654:	cmpb   $0x58,0x6(%rdx)
   31658:	jne    30aeb <ngettext+0x66b>
   3165e:	cmpb   $0x0,0x7(%rdx)
   31662:	jne    31cda <ngettext+0x185a>
   31668:	test   %bl,%bl
   3166a:	jne    31cce <ngettext+0x184e>
   31670:	test   %r11b,%r11b
   31673:	jne    31cc2 <ngettext+0x1842>
   31679:	test   %r8b,%r8b
   3167c:	jne    31cb6 <ngettext+0x1836>
   31682:	test   %cl,%cl
   31684:	jne    31caa <ngettext+0x182a>
   3168a:	test   %r13b,%r13b
   3168d:	jne    31c9e <ngettext+0x181e>
   31693:	test   %r12b,%r12b
   31696:	je     31602 <ngettext+0x1182>
   3169c:	lea    0x15abcd(%rip),%rax        # 18c270 <_libc_intl_domainname+0x47>
   316a3:	jmpq   30aeb <ngettext+0x66b>
   316a8:	cmpb   $0x41,0x5(%rdx)
   316ac:	jne    30aeb <ngettext+0x66b>
   316b2:	cmpb   $0x53,0x6(%rdx)
   316b6:	jne    30aeb <ngettext+0x66b>
   316bc:	cmpb   $0x54,0x7(%rdx)
   316c0:	jne    30aeb <ngettext+0x66b>
   316c6:	movzbl 0x8(%rdx),%r14d
   316cb:	cmp    $0x38,%r14b
   316cf:	je     318d4 <ngettext+0x1454>
   316d5:	xor    %eax,%eax
   316d7:	cmp    $0x31,%r14b
   316db:	je     31884 <ngettext+0x1404>
   316e1:	cmp    $0x33,%r14b
   316e5:	je     31830 <ngettext+0x13b0>
   316eb:	cmp    $0x36,%r14b
   316ef:	jne    30aeb <ngettext+0x66b>
   316f5:	cmpb   $0x34,0x9(%rdx)
   316f9:	jne    30aeb <ngettext+0x66b>
   316ff:	cmpb   $0x0,0xa(%rdx)
   31703:	jne    30aeb <ngettext+0x66b>
   31709:	test   %bl,%bl
   3170b:	jne    31824 <ngettext+0x13a4>
   31711:	test   %r11b,%r11b
   31714:	jne    31818 <ngettext+0x1398>
   3171a:	test   %r8b,%r8b
   3171d:	jne    3180c <ngettext+0x138c>
   31723:	test   %cl,%cl
   31725:	jne    31800 <ngettext+0x1380>
   3172b:	test   %r13b,%r13b
   3172e:	jne    317f4 <ngettext+0x1374>
   31734:	test   %r12b,%r12b
   31737:	je     31602 <ngettext+0x1182>
   3173d:	lea    0x15ab2c(%rip),%rax        # 18c270 <_libc_intl_domainname+0x47>
   31744:	jmpq   30aeb <ngettext+0x66b>
   31749:	cmpb   $0x45,0x5(%rdx)
   3174d:	jne    30aeb <ngettext+0x66b>
   31753:	cmpb   $0x41,0x6(%rdx)
   31757:	jne    30aeb <ngettext+0x66b>
   3175d:	cmpb   $0x53,0x7(%rdx)
   31761:	jne    30aeb <ngettext+0x66b>
   31767:	cmpb   $0x54,0x8(%rdx)
   3176b:	jne    30aeb <ngettext+0x66b>
   31771:	movzbl 0x9(%rdx),%r14d
   31776:	cmp    $0x38,%r14b
   3177a:	je     31aa5 <ngettext+0x1625>
   31780:	xor    %eax,%eax
   31782:	cmp    $0x31,%r14b
   31786:	je     31a55 <ngettext+0x15d5>
   3178c:	cmp    $0x33,%r14b
   31790:	je     31a01 <ngettext+0x1581>
   31796:	cmp    $0x36,%r14b
   3179a:	jne    30aeb <ngettext+0x66b>
   317a0:	cmpb   $0x34,0xa(%rdx)
   317a4:	jne    30aeb <ngettext+0x66b>
   317aa:	cmpb   $0x0,0xb(%rdx)
   317ae:	jne    30aeb <ngettext+0x66b>
   317b4:	test   %bl,%bl
   317b6:	jne    319f5 <ngettext+0x1575>
   317bc:	test   %r11b,%r11b
   317bf:	jne    319e9 <ngettext+0x1569>
   317c5:	test   %r8b,%r8b
   317c8:	jne    319dd <ngettext+0x155d>
   317ce:	test   %cl,%cl
   317d0:	jne    319d1 <ngettext+0x1551>
   317d6:	test   %r13b,%r13b
   317d9:	jne    319c5 <ngettext+0x1545>
   317df:	test   %r12b,%r12b
   317e2:	je     31602 <ngettext+0x1182>
   317e8:	lea    0x15aa81(%rip),%rax        # 18c270 <_libc_intl_domainname+0x47>
   317ef:	jmpq   30aeb <ngettext+0x66b>
   317f4:	lea    0x15aa7b(%rip),%rax        # 18c276 <_libc_intl_domainname+0x4d>
   317fb:	jmpq   30aeb <ngettext+0x66b>
   31800:	lea    0x15de47(%rip),%rax        # 18f64e <_libc_intl_domainname+0x3425>
   31807:	jmpq   30aeb <ngettext+0x66b>
   3180c:	lea    0x15aa60(%rip),%rax        # 18c273 <_libc_intl_domainname+0x4a>
   31813:	jmpq   30aeb <ngettext+0x66b>
   31818:	lea    0x15aa4e(%rip),%rax        # 18c26d <_libc_intl_domainname+0x44>
   3181f:	jmpq   30aeb <ngettext+0x66b>
   31824:	lea    0x15d282(%rip),%rax        # 18eaad <_libc_intl_domainname+0x2884>
   3182b:	jmpq   30aeb <ngettext+0x66b>
   31830:	cmpb   $0x32,0x9(%rdx)
   31834:	jne    30aeb <ngettext+0x66b>
   3183a:	cmpb   $0x0,0xa(%rdx)
   3183e:	jne    30aeb <ngettext+0x66b>
   31844:	test   %bl,%bl
   31846:	jne    319b9 <ngettext+0x1539>
   3184c:	test   %r11b,%r11b
   3184f:	jne    319ad <ngettext+0x152d>
   31855:	test   %r8b,%r8b
   31858:	jne    319a1 <ngettext+0x1521>
   3185e:	test   %cl,%cl
   31860:	jne    31995 <ngettext+0x1515>
   31866:	test   %r13b,%r13b
   31869:	jne    3190a <ngettext+0x148a>
   3186f:	test   %r12b,%r12b
   31872:	je     31602 <ngettext+0x1182>
   31878:	lea    0x15a9f1(%rip),%rax        # 18c270 <_libc_intl_domainname+0x47>
   3187f:	jmpq   30aeb <ngettext+0x66b>
   31884:	cmpb   $0x36,0x9(%rdx)
   31888:	jne    30aeb <ngettext+0x66b>
   3188e:	cmpb   $0x0,0xa(%rdx)
   31892:	jne    30aeb <ngettext+0x66b>
   31898:	test   %bl,%bl
   3189a:	jne    31989 <ngettext+0x1509>
   318a0:	test   %r11b,%r11b
   318a3:	jne    3197d <ngettext+0x14fd>
   318a9:	test   %r8b,%r8b
   318ac:	jne    31971 <ngettext+0x14f1>
   318b2:	test   %cl,%cl
   318b4:	jne    31965 <ngettext+0x14e5>
   318ba:	test   %r13b,%r13b
   318bd:	jne    31916 <ngettext+0x1496>
   318bf:	test   %r12b,%r12b
   318c2:	je     31602 <ngettext+0x1182>
   318c8:	lea    0x15a9a1(%rip),%rax        # 18c270 <_libc_intl_domainname+0x47>
   318cf:	jmpq   30aeb <ngettext+0x66b>
   318d4:	cmpb   $0x0,0x9(%rdx)
   318d8:	jne    3195e <ngettext+0x14de>
   318de:	test   %bl,%bl
   318e0:	jne    31952 <ngettext+0x14d2>
   318e2:	test   %r11b,%r11b
   318e5:	jne    31946 <ngettext+0x14c6>
   318e7:	test   %r8b,%r8b
   318ea:	jne    3193a <ngettext+0x14ba>
   318ec:	test   %cl,%cl
   318ee:	jne    3192e <ngettext+0x14ae>
   318f0:	test   %r13b,%r13b
   318f3:	jne    31922 <ngettext+0x14a2>
   318f5:	test   %r12b,%r12b
   318f8:	je     31602 <ngettext+0x1182>
   318fe:	lea    0x15bb8c(%rip),%rax        # 18d491 <_libc_intl_domainname+0x1268>
   31905:	jmpq   30aeb <ngettext+0x66b>
   3190a:	lea    0x15a965(%rip),%rax        # 18c276 <_libc_intl_domainname+0x4d>
   31911:	jmpq   30aeb <ngettext+0x66b>
   31916:	lea    0x15a959(%rip),%rax        # 18c276 <_libc_intl_domainname+0x4d>
   3191d:	jmpq   30aeb <ngettext+0x66b>
   31922:	lea    0x15d64e(%rip),%rax        # 18ef77 <_libc_intl_domainname+0x2d4e>
   31929:	jmpq   30aeb <ngettext+0x66b>
   3192e:	lea    0x15d10e(%rip),%rax        # 18ea43 <_libc_intl_domainname+0x281a>
   31935:	jmpq   30aeb <ngettext+0x66b>
   3193a:	lea    0x15c8d3(%rip),%rax        # 18e214 <_libc_intl_domainname+0x1feb>
   31941:	jmpq   30aeb <ngettext+0x66b>
   31946:	lea    0x15a523(%rip),%rax        # 18be70 <_itoa_lower_digits+0x6a30>
   3194d:	jmpq   30aeb <ngettext+0x66b>
   31952:	lea    0x15aa39(%rip),%rax        # 18c392 <_libc_intl_domainname+0x169>
   31959:	jmpq   30aeb <ngettext+0x66b>
   3195e:	xor    %eax,%eax
   31960:	jmpq   30aeb <ngettext+0x66b>
   31965:	lea    0x15dce2(%rip),%rax        # 18f64e <_libc_intl_domainname+0x3425>
   3196c:	jmpq   30aeb <ngettext+0x66b>
   31971:	lea    0x15a8fb(%rip),%rax        # 18c273 <_libc_intl_domainname+0x4a>
   31978:	jmpq   30aeb <ngettext+0x66b>
   3197d:	lea    0x15a8e9(%rip),%rax        # 18c26d <_libc_intl_domainname+0x44>
   31984:	jmpq   30aeb <ngettext+0x66b>
   31989:	lea    0x15d11d(%rip),%rax        # 18eaad <_libc_intl_domainname+0x2884>
   31990:	jmpq   30aeb <ngettext+0x66b>
   31995:	lea    0x15dcb2(%rip),%rax        # 18f64e <_libc_intl_domainname+0x3425>
   3199c:	jmpq   30aeb <ngettext+0x66b>
   319a1:	lea    0x15a8cb(%rip),%rax        # 18c273 <_libc_intl_domainname+0x4a>
   319a8:	jmpq   30aeb <ngettext+0x66b>
   319ad:	lea    0x15a8b9(%rip),%rax        # 18c26d <_libc_intl_domainname+0x44>
   319b4:	jmpq   30aeb <ngettext+0x66b>
   319b9:	lea    0x15d0ed(%rip),%rax        # 18eaad <_libc_intl_domainname+0x2884>
   319c0:	jmpq   30aeb <ngettext+0x66b>
   319c5:	lea    0x15a8aa(%rip),%rax        # 18c276 <_libc_intl_domainname+0x4d>
   319cc:	jmpq   30aeb <ngettext+0x66b>
   319d1:	lea    0x15dc76(%rip),%rax        # 18f64e <_libc_intl_domainname+0x3425>
   319d8:	jmpq   30aeb <ngettext+0x66b>
   319dd:	lea    0x15a88f(%rip),%rax        # 18c273 <_libc_intl_domainname+0x4a>
   319e4:	jmpq   30aeb <ngettext+0x66b>
   319e9:	lea    0x15a87d(%rip),%rax        # 18c26d <_libc_intl_domainname+0x44>
   319f0:	jmpq   30aeb <ngettext+0x66b>
   319f5:	lea    0x15d0b1(%rip),%rax        # 18eaad <_libc_intl_domainname+0x2884>
   319fc:	jmpq   30aeb <ngettext+0x66b>
   31a01:	cmpb   $0x32,0xa(%rdx)
   31a05:	jne    30aeb <ngettext+0x66b>
   31a0b:	cmpb   $0x0,0xb(%rdx)
   31a0f:	jne    30aeb <ngettext+0x66b>
   31a15:	test   %bl,%bl
   31a17:	jne    31b8a <ngettext+0x170a>
   31a1d:	test   %r11b,%r11b
   31a20:	jne    31b7e <ngettext+0x16fe>
   31a26:	test   %r8b,%r8b
   31a29:	jne    31b72 <ngettext+0x16f2>
   31a2f:	test   %cl,%cl
   31a31:	jne    31b66 <ngettext+0x16e6>
   31a37:	test   %r13b,%r13b
   31a3a:	jne    31adb <ngettext+0x165b>
   31a40:	test   %r12b,%r12b
   31a43:	je     31602 <ngettext+0x1182>
   31a49:	lea    0x15ba41(%rip),%rax        # 18d491 <_libc_intl_domainname+0x1268>
   31a50:	jmpq   30aeb <ngettext+0x66b>
   31a55:	cmpb   $0x36,0xa(%rdx)
   31a59:	jne    30aeb <ngettext+0x66b>
   31a5f:	cmpb   $0x0,0xb(%rdx)
   31a63:	jne    30aeb <ngettext+0x66b>
   31a69:	test   %bl,%bl
   31a6b:	jne    31b5a <ngettext+0x16da>
   31a71:	test   %r11b,%r11b
   31a74:	jne    31b4e <ngettext+0x16ce>
   31a7a:	test   %r8b,%r8b
   31a7d:	jne    31b42 <ngettext+0x16c2>
   31a83:	test   %cl,%cl
   31a85:	jne    31b36 <ngettext+0x16b6>
   31a8b:	test   %r13b,%r13b
   31a8e:	jne    31ae7 <ngettext+0x1667>
   31a90:	test   %r12b,%r12b
   31a93:	je     31602 <ngettext+0x1182>
   31a99:	lea    0x15b9f1(%rip),%rax        # 18d491 <_libc_intl_domainname+0x1268>
   31aa0:	jmpq   30aeb <ngettext+0x66b>
   31aa5:	cmpb   $0x0,0xa(%rdx)
   31aa9:	jne    31b2f <ngettext+0x16af>
   31aaf:	test   %bl,%bl
   31ab1:	jne    31b23 <ngettext+0x16a3>
   31ab3:	test   %r11b,%r11b
   31ab6:	jne    31b17 <ngettext+0x1697>
   31ab8:	test   %r8b,%r8b
   31abb:	jne    31b0b <ngettext+0x168b>
   31abd:	test   %cl,%cl
   31abf:	jne    31aff <ngettext+0x167f>
   31ac1:	test   %r13b,%r13b
   31ac4:	jne    31af3 <ngettext+0x1673>
   31ac6:	test   %r12b,%r12b
   31ac9:	je     31602 <ngettext+0x1182>
   31acf:	lea    0x15b9bb(%rip),%rax        # 18d491 <_libc_intl_domainname+0x1268>
   31ad6:	jmpq   30aeb <ngettext+0x66b>
   31adb:	lea    0x15d495(%rip),%rax        # 18ef77 <_libc_intl_domainname+0x2d4e>
   31ae2:	jmpq   30aeb <ngettext+0x66b>
   31ae7:	lea    0x15d489(%rip),%rax        # 18ef77 <_libc_intl_domainname+0x2d4e>
   31aee:	jmpq   30aeb <ngettext+0x66b>
   31af3:	lea    0x15d47d(%rip),%rax        # 18ef77 <_libc_intl_domainname+0x2d4e>
   31afa:	jmpq   30aeb <ngettext+0x66b>
   31aff:	lea    0x15cf3d(%rip),%rax        # 18ea43 <_libc_intl_domainname+0x281a>
   31b06:	jmpq   30aeb <ngettext+0x66b>
   31b0b:	lea    0x15c702(%rip),%rax        # 18e214 <_libc_intl_domainname+0x1feb>
   31b12:	jmpq   30aeb <ngettext+0x66b>
   31b17:	lea    0x15a352(%rip),%rax        # 18be70 <_itoa_lower_digits+0x6a30>
   31b1e:	jmpq   30aeb <ngettext+0x66b>
   31b23:	lea    0x15a868(%rip),%rax        # 18c392 <_libc_intl_domainname+0x169>
   31b2a:	jmpq   30aeb <ngettext+0x66b>
   31b2f:	xor    %eax,%eax
   31b31:	jmpq   30aeb <ngettext+0x66b>
   31b36:	lea    0x15cf06(%rip),%rax        # 18ea43 <_libc_intl_domainname+0x281a>
   31b3d:	jmpq   30aeb <ngettext+0x66b>
   31b42:	lea    0x15c6cb(%rip),%rax        # 18e214 <_libc_intl_domainname+0x1feb>
   31b49:	jmpq   30aeb <ngettext+0x66b>
   31b4e:	lea    0x15a31b(%rip),%rax        # 18be70 <_itoa_lower_digits+0x6a30>
   31b55:	jmpq   30aeb <ngettext+0x66b>
   31b5a:	lea    0x15a831(%rip),%rax        # 18c392 <_libc_intl_domainname+0x169>
   31b61:	jmpq   30aeb <ngettext+0x66b>
   31b66:	lea    0x15ced6(%rip),%rax        # 18ea43 <_libc_intl_domainname+0x281a>
   31b6d:	jmpq   30aeb <ngettext+0x66b>
   31b72:	lea    0x15c69b(%rip),%rax        # 18e214 <_libc_intl_domainname+0x1feb>
   31b79:	jmpq   30aeb <ngettext+0x66b>
   31b7e:	lea    0x15a2eb(%rip),%rax        # 18be70 <_itoa_lower_digits+0x6a30>
   31b85:	jmpq   30aeb <ngettext+0x66b>
   31b8a:	lea    0x15a801(%rip),%rax        # 18c392 <_libc_intl_domainname+0x169>
   31b91:	jmpq   30aeb <ngettext+0x66b>
   31b96:	cmpb   $0x34,0x5(%rdx)
   31b9a:	jne    30aeb <ngettext+0x66b>
   31ba0:	cmpb   $0x0,0x6(%rdx)
   31ba4:	jne    30aeb <ngettext+0x66b>
   31baa:	test   %bl,%bl
   31bac:	jne    31c92 <ngettext+0x1812>
   31bb2:	test   %r11b,%r11b
   31bb5:	jne    31c86 <ngettext+0x1806>
   31bbb:	test   %r8b,%r8b
   31bbe:	jne    31c7a <ngettext+0x17fa>
   31bc4:	test   %cl,%cl
   31bc6:	jne    31c6e <ngettext+0x17ee>
   31bcc:	test   %r13b,%r13b
   31bcf:	jne    31c26 <ngettext+0x17a6>
   31bd1:	test   %r12b,%r12b
   31bd4:	je     31602 <ngettext+0x1182>
   31bda:	lea    0x15a68f(%rip),%rax        # 18c270 <_libc_intl_domainname+0x47>
   31be1:	jmpq   30aeb <ngettext+0x66b>
   31be6:	cmpb   $0x32,0x5(%rdx)
   31bea:	jne    30aeb <ngettext+0x66b>
   31bf0:	cmpb   $0x0,0x6(%rdx)
   31bf4:	jne    30aeb <ngettext+0x66b>
   31bfa:	test   %bl,%bl
   31bfc:	jne    31c62 <ngettext+0x17e2>
   31bfe:	test   %r11b,%r11b
   31c01:	jne    31c56 <ngettext+0x17d6>
   31c03:	test   %r8b,%r8b
   31c06:	jne    31c4a <ngettext+0x17ca>
   31c08:	test   %cl,%cl
   31c0a:	jne    31c3e <ngettext+0x17be>
   31c0c:	test   %r13b,%r13b
   31c0f:	jne    31c32 <ngettext+0x17b2>
   31c11:	test   %r12b,%r12b
   31c14:	je     31602 <ngettext+0x1182>
   31c1a:	lea    0x15b870(%rip),%rax        # 18d491 <_libc_intl_domainname+0x1268>
   31c21:	jmpq   30aeb <ngettext+0x66b>
   31c26:	lea    0x15a649(%rip),%rax        # 18c276 <_libc_intl_domainname+0x4d>
   31c2d:	jmpq   30aeb <ngettext+0x66b>
   31c32:	lea    0x15d33e(%rip),%rax        # 18ef77 <_libc_intl_domainname+0x2d4e>
   31c39:	jmpq   30aeb <ngettext+0x66b>
   31c3e:	lea    0x15cdfe(%rip),%rax        # 18ea43 <_libc_intl_domainname+0x281a>
   31c45:	jmpq   30aeb <ngettext+0x66b>
   31c4a:	lea    0x15c5c3(%rip),%rax        # 18e214 <_libc_intl_domainname+0x1feb>
   31c51:	jmpq   30aeb <ngettext+0x66b>
   31c56:	lea    0x15a213(%rip),%rax        # 18be70 <_itoa_lower_digits+0x6a30>
   31c5d:	jmpq   30aeb <ngettext+0x66b>
   31c62:	lea    0x15a729(%rip),%rax        # 18c392 <_libc_intl_domainname+0x169>
   31c69:	jmpq   30aeb <ngettext+0x66b>
   31c6e:	lea    0x15d9d9(%rip),%rax        # 18f64e <_libc_intl_domainname+0x3425>
   31c75:	jmpq   30aeb <ngettext+0x66b>
   31c7a:	lea    0x15a5f2(%rip),%rax        # 18c273 <_libc_intl_domainname+0x4a>
   31c81:	jmpq   30aeb <ngettext+0x66b>
   31c86:	lea    0x15a5e0(%rip),%rax        # 18c26d <_libc_intl_domainname+0x44>
   31c8d:	jmpq   30aeb <ngettext+0x66b>
   31c92:	lea    0x15ce14(%rip),%rax        # 18eaad <_libc_intl_domainname+0x2884>
   31c99:	jmpq   30aeb <ngettext+0x66b>
   31c9e:	lea    0x15a5d1(%rip),%rax        # 18c276 <_libc_intl_domainname+0x4d>
   31ca5:	jmpq   30aeb <ngettext+0x66b>
   31caa:	lea    0x15d99d(%rip),%rax        # 18f64e <_libc_intl_domainname+0x3425>
   31cb1:	jmpq   30aeb <ngettext+0x66b>
   31cb6:	lea    0x15a5b6(%rip),%rax        # 18c273 <_libc_intl_domainname+0x4a>
   31cbd:	jmpq   30aeb <ngettext+0x66b>
   31cc2:	lea    0x15a5a4(%rip),%rax        # 18c26d <_libc_intl_domainname+0x44>
   31cc9:	jmpq   30aeb <ngettext+0x66b>
   31cce:	lea    0x15cdd8(%rip),%rax        # 18eaad <_libc_intl_domainname+0x2884>
   31cd5:	jmpq   30aeb <ngettext+0x66b>
   31cda:	xor    %eax,%eax
   31cdc:	jmpq   30aeb <ngettext+0x66b>
   31ce1:	lea    0x15d966(%rip),%rax        # 18f64e <_libc_intl_domainname+0x3425>
   31ce8:	jmpq   30aeb <ngettext+0x66b>
   31ced:	lea    0x15a57f(%rip),%rax        # 18c273 <_libc_intl_domainname+0x4a>
   31cf4:	jmpq   30aeb <ngettext+0x66b>
   31cf9:	lea    0x15a576(%rip),%rax        # 18c276 <_libc_intl_domainname+0x4d>
   31d00:	jmpq   30aeb <ngettext+0x66b>
   31d05:	mov    (%r9),%ebx
   31d08:	mov    -0x128(%rbp),%r14
   31d0f:	bswap  %ebx
   31d11:	mov    %ebx,%ebx
   31d13:	add    %r15,%rbx
   31d16:	mov    (%rbx),%r12d
   31d19:	bswap  %r12d
   31d1c:	mov    %r12d,%r12d
   31d1f:	add    %r15,%r12
   31d22:	jmpq   31117 <ngettext+0xc97>
   31d27:	mov    -0x100(%rbp),%rax
   31d2e:	mov    (%rax,%r13,4),%eax
   31d32:	jmpq   30ec9 <ngettext+0xa49>
   31d37:	mov    -0x108(%rbp),%rax
   31d3e:	mov    $0x1,%r11d
   31d44:	mov    0x18(%rax),%r8d
   31d48:	jmpq   310e2 <ngettext+0xc62>
   31d4d:	mov    -0x100(%rbp),%rax
   31d54:	mov    (%rax,%r13,4),%edx
   31d58:	jmpq   31165 <ngettext+0xce5>
   31d5d:	mov    (%r9),%eax
   31d60:	jmpq   31227 <ngettext+0xda7>
   31d65:	nopw   %cs:0x0(%rax,%rax,1)
   31d6f:	nop
   31d70:	mov    (%rsi),%rsi
   31d73:	mov    (%rdi),%rdi
   31d76:	lea    0x390f43(%rip),%rdx        # 3c2cc0 <h_errlist+0x940>
   31d7d:	jmpq   8fa20 <__strcasecmp+0x70>
   31d82:	nopl   0x0(%rax)
   31d86:	nopw   %cs:0x0(%rax,%rax,1)
   31d90:	push   %rbp
   31d91:	movslq %esi,%rdx
   31d94:	mov    %rdi,%rsi
   31d97:	lea    0x2c(%rdx),%rax
   31d9b:	mov    %rsp,%rbp
   31d9e:	push   %r15
   31da0:	push   %r14
   31da2:	push   %r13
   31da4:	push   %r12
   31da6:	and    $0xfffffffffffffff0,%rax
   31daa:	push   %rbx
   31dab:	sub    $0x1e8,%rsp
   31db2:	sub    %rax,%rsp
   31db5:	lea    0xf(%rsp),%rbx
   31dba:	and    $0xfffffffffffffff0,%rbx
   31dbe:	mov    %rbx,%rdi
   31dc1:	callq  8f360 <__mempcpy+0x60>
   31dc6:	movabs $0x2e656c61636f6c2f,%rdi
   31dd0:	mov    $0x73,%edx
   31dd5:	lea    0x159f94(%rip),%rsi        # 18bd70 <_itoa_lower_digits+0x6930>
   31ddc:	mov    %rdi,(%rax)
   31ddf:	movl   $0x61696c61,0x8(%rax)
   31de6:	mov    %rbx,%rdi
   31de9:	mov    %dx,0xc(%rax)
   31ded:	callq  6f1b0 <_IO_fopen>
   31df2:	test   %rax,%rax
   31df5:	mov    %rax,%r13
   31df8:	je     32226 <ngettext+0x1da6>
   31dfe:	mov    (%rax),%eax
   31e00:	mov    %eax,%edx
   31e02:	or     $0x80,%dh
   31e05:	test   $0x10,%al
   31e07:	mov    %edx,0x0(%r13)
   31e0b:	jne    32237 <ngettext+0x1db7>
   31e11:	lea    -0x1c0(%rbp),%r15
   31e18:	movq   $0x0,-0x1f0(%rbp)
   31e23:	nopl   0x0(%rax,%rax,1)
   31e28:	mov    %r13,%rdx
   31e2b:	mov    $0x190,%esi
   31e30:	mov    %r15,%rdi
   31e33:	callq  792c0 <fgets_unlocked>
   31e38:	test   %rax,%rax
   31e3b:	je     32048 <ngettext+0x1bc8>
   31e41:	mov    $0xa,%esi
   31e46:	mov    %r15,%rdi
   31e49:	callq  89a50 <strchr+0x30>
   31e4e:	mov    %rax,%r8
   31e51:	mov    0x391fa8(%rip),%rax        # 3c3e00 <_IO_file_jumps+0x5c0>
   31e58:	movzbl -0x1c0(%rbp),%ecx
   31e5f:	mov    %fs:(%rax),%rax
   31e63:	mov    %rcx,%rdx
   31e66:	testb  $0x20,0x1(%rax,%rcx,2)
   31e6b:	mov    %r15,%rcx
   31e6e:	je     31e81 <ngettext+0x1a01>
   31e70:	add    $0x1,%rcx
   31e74:	movzbl (%rcx),%esi
   31e77:	testb  $0x20,0x1(%rax,%rsi,2)
   31e7c:	mov    %rsi,%rdx
   31e7f:	jne    31e70 <ngettext+0x19f0>
   31e81:	cmp    $0x23,%dl
   31e84:	je     32038 <ngettext+0x1bb8>
   31e8a:	test   %dl,%dl
   31e8c:	je     32038 <ngettext+0x1bb8>
   31e92:	movzbl 0x1(%rcx),%edx
   31e96:	lea    0x1(%rcx),%rbx
   31e9a:	test   %dl,%dl
   31e9c:	jne    31eb7 <ngettext+0x1a37>
   31e9e:	jmpq   320a8 <ngettext+0x1c28>
   31ea3:	nopl   0x0(%rax,%rax,1)
   31ea8:	add    $0x1,%rbx
   31eac:	movzbl (%rbx),%edx
   31eaf:	test   %dl,%dl
   31eb1:	je     320a8 <ngettext+0x1c28>
   31eb7:	testb  $0x20,0x1(%rax,%rdx,2)
   31ebc:	je     31ea8 <ngettext+0x1a28>
   31ebe:	movzbl 0x1(%rbx),%esi
   31ec2:	movb   $0x0,(%rbx)
   31ec5:	add    $0x1,%rbx
   31ec9:	testb  $0x20,0x1(%rax,%rsi,2)
   31ece:	mov    %rsi,%rdx
   31ed1:	je     31ee9 <ngettext+0x1a69>
   31ed3:	nopl   0x0(%rax,%rax,1)
   31ed8:	add    $0x1,%rbx
   31edc:	movzbl (%rbx),%esi
   31edf:	testb  $0x20,0x1(%rax,%rsi,2)
   31ee4:	mov    %rsi,%rdx
   31ee7:	jne    31ed8 <ngettext+0x1a58>
   31ee9:	test   %dl,%dl
   31eeb:	je     32038 <ngettext+0x1bb8>
   31ef1:	movzbl 0x1(%rbx),%edx
   31ef5:	lea    0x1(%rbx),%rsi
   31ef9:	test   %dl,%dl
   31efb:	jne    31f0b <ngettext+0x1a8b>
   31efd:	jmp    31f25 <ngettext+0x1aa5>
   31eff:	nop
   31f00:	add    $0x1,%rsi
   31f04:	movzbl (%rsi),%edx
   31f07:	test   %dl,%dl
   31f09:	je     31f25 <ngettext+0x1aa5>
   31f0b:	movzbl %dl,%edi
   31f0e:	testb  $0x20,0x1(%rax,%rdi,2)
   31f13:	je     31f00 <ngettext+0x1a80>
   31f15:	cmp    $0xa,%dl
   31f18:	jne    3219c <ngettext+0x1d1c>
   31f1e:	movb   $0x0,(%rsi)
   31f21:	movb   $0xa,0x1(%rsi)
   31f25:	mov    0x393e14(%rip),%r12        # 3c5d40 <__vdso_clock_gettime+0x340>
   31f2c:	mov    0x393e05(%rip),%rsi        # 3c5d38 <__vdso_clock_gettime+0x338>
   31f33:	cmp    %rsi,%r12
   31f36:	jae    321a4 <ngettext+0x1d24>
   31f3c:	mov    %rcx,%rdi
   31f3f:	mov    %r8,-0x1e8(%rbp)
   31f46:	mov    %rcx,-0x1e0(%rbp)
   31f4d:	callq  8b6d0 <strlen>
   31f52:	lea    0x1(%rax),%rdx
   31f56:	mov    %rbx,%rdi
   31f59:	mov    %rdx,-0x1d0(%rbp)
   31f60:	callq  8b6d0 <strlen>
   31f65:	mov    -0x1d0(%rbp),%rdx
   31f6c:	mov    0x393ddd(%rip),%r11        # 3c5d50 <__vdso_clock_gettime+0x350>
   31f73:	add    $0x1,%rax
   31f77:	mov    %rax,%rdi
   31f7a:	mov    %rax,-0x1c8(%rbp)
   31f81:	mov    -0x1e0(%rbp),%rcx
   31f88:	mov    -0x1e8(%rbp),%r8
   31f8f:	lea    (%rdx,%r11,1),%rax
   31f93:	mov    %rax,-0x1d0(%rbp)
   31f9a:	add    %rdi,%rax
   31f9d:	mov    %rax,%rdi
   31fa0:	mov    %rax,-0x1d8(%rbp)
   31fa7:	mov    0x393d9a(%rip),%rax        # 3c5d48 <__vdso_clock_gettime+0x348>
   31fae:	cmp    %rax,%rdi
   31fb1:	ja     320b8 <ngettext+0x1c38>
   31fb7:	mov    0x39388a(%rip),%r9        # 3c5848 <stdin+0x18>
   31fbe:	mov    0x39387b(%rip),%rdi        # 3c5840 <stdin+0x10>
   31fc5:	mov    %r12,%r14
   31fc8:	mov    %rcx,%rsi
   31fcb:	mov    %r8,-0x1e8(%rbp)
   31fd2:	shl    $0x4,%r14
   31fd6:	mov    %r9,-0x1e0(%rbp)
   31fdd:	add    $0x1,%r12
   31fe1:	add    %rdi,%r14
   31fe4:	lea    (%r9,%r11,1),%rdi
   31fe8:	callq  943f0 <memcpy+0x70>
   31fed:	mov    -0x1d0(%rbp),%rdi
   31ff4:	mov    -0x1e0(%rbp),%r9
   31ffb:	mov    %rbx,%rsi
   31ffe:	mov    -0x1c8(%rbp),%rdx
   32005:	mov    %rax,(%r14)
   32008:	add    %r9,%rdi
   3200b:	callq  943f0 <memcpy+0x70>
   32010:	addq   $0x1,-0x1f0(%rbp)
   32018:	mov    %rax,0x8(%r14)
   3201c:	mov    -0x1d8(%rbp),%rax
   32023:	mov    -0x1e8(%rbp),%r8
   3202a:	mov    %r12,0x393d0f(%rip)        # 3c5d40 <__vdso_clock_gettime+0x340>
   32031:	mov    %rax,0x393d18(%rip)        # 3c5d50 <__vdso_clock_gettime+0x350>
   32038:	test   %r8,%r8
   3203b:	je     3208a <ngettext+0x1c0a>
   3203d:	testb  $0x10,0x0(%r13)
   32042:	je     31e28 <ngettext+0x19a8>
   32048:	mov    %r13,%rdi
   3204b:	callq  6e6b0 <_IO_fclose>
   32050:	cmpq   $0x0,-0x1f0(%rbp)
   32058:	jne    32202 <ngettext+0x1d82>
   3205e:	mov    -0x1f0(%rbp),%rax
   32065:	lea    -0x28(%rbp),%rsp
   32069:	pop    %rbx
   3206a:	pop    %r12
   3206c:	pop    %r13
   3206e:	pop    %r14
   32070:	pop    %r15
   32072:	pop    %rbp
   32073:	retq   
   32074:	nopl   0x0(%rax)
   32078:	mov    $0xa,%esi
   3207d:	mov    %r15,%rdi
   32080:	callq  89a50 <strchr+0x30>
   32085:	test   %rax,%rax
   32088:	jne    3203d <ngettext+0x1bbd>
   3208a:	mov    %r13,%rdx
   3208d:	mov    $0x190,%esi
   32092:	mov    %r15,%rdi
   32095:	callq  792c0 <fgets_unlocked>
   3209a:	test   %rax,%rax
   3209d:	jne    32078 <ngettext+0x1bf8>
   3209f:	jmp    3203d <ngettext+0x1bbd>
   320a1:	nopl   0x0(%rax)
   320a8:	testw  $0x2000,(%rax)
   320ad:	jne    31ed8 <ngettext+0x1a58>
   320b3:	jmp    32038 <ngettext+0x1bb8>
   320b5:	nopl   (%rax)
   320b8:	mov    -0x1c8(%rbp),%rdi
   320bf:	mov    0x393782(%rip),%r14        # 3c5848 <stdin+0x18>
   320c6:	mov    %r11,-0x208(%rbp)
   320cd:	mov    %rcx,-0x200(%rbp)
   320d4:	mov    %r8,-0x1f8(%rbp)
   320db:	mov    %rdx,-0x1e8(%rbp)
   320e2:	lea    (%rdi,%rdx,1),%rsi
   320e6:	mov    $0x400,%edi
   320eb:	cmp    $0x400,%rsi
   320f2:	cmovb  %rdi,%rsi
   320f6:	mov    %r14,%rdi
   320f9:	lea    (%rsi,%rax,1),%r10
   320fd:	mov    %r10,%rsi
   32100:	mov    %r10,-0x1e0(%rbp)
   32107:	callq  1f450 <realloc@plt>
   3210c:	test   %rax,%rax
   3210f:	je     32048 <ngettext+0x1bc8>
   32115:	cmp    %rax,%r14
   32118:	mov    0x393721(%rip),%rdi        # 3c5840 <stdin+0x10>
   3211f:	mov    -0x1e0(%rbp),%r10
   32126:	mov    -0x1e8(%rbp),%rdx
   3212d:	mov    -0x1f8(%rbp),%r8
   32134:	mov    -0x200(%rbp),%rcx
   3213b:	mov    -0x208(%rbp),%r11
   32142:	je     32186 <ngettext+0x1d06>
   32144:	test   %r12,%r12
   32147:	je     32186 <ngettext+0x1d06>
   32149:	mov    %rax,%rsi
   3214c:	mov    %r12,%r9
   3214f:	sub    %r14,%rsi
   32152:	shl    $0x4,%r9
   32156:	mov    %rsi,-0x1e0(%rbp)
   3215d:	xor    %esi,%esi
   3215f:	movq   -0x1e0(%rbp),%xmm1
   32167:	punpcklqdq %xmm1,%xmm1
   3216b:	nopl   0x0(%rax,%rax,1)
   32170:	movdqu (%rdi,%rsi,1),%xmm0
   32175:	paddq  %xmm1,%xmm0
   32179:	movups %xmm0,(%rdi,%rsi,1)
   3217d:	add    $0x10,%rsi
   32181:	cmp    %r9,%rsi
   32184:	jne    32170 <ngettext+0x1cf0>
   32186:	mov    %rax,0x3936bb(%rip)        # 3c5848 <stdin+0x18>
   3218d:	mov    %r10,0x393bb4(%rip)        # 3c5d48 <__vdso_clock_gettime+0x348>
   32194:	mov    %rax,%r9
   32197:	jmpq   31fc5 <ngettext+0x1b45>
   3219c:	movb   $0x0,(%rsi)
   3219f:	jmpq   31f25 <ngettext+0x1aa5>
   321a4:	test   %rsi,%rsi
   321a7:	je     321f5 <ngettext+0x1d75>
   321a9:	lea    (%rsi,%rsi,1),%r14
   321ad:	shl    $0x5,%rsi
   321b1:	mov    0x393688(%rip),%rdi        # 3c5840 <stdin+0x10>
   321b8:	mov    %rcx,-0x1d0(%rbp)
   321bf:	mov    %r8,-0x1c8(%rbp)
   321c6:	callq  1f450 <realloc@plt>
   321cb:	test   %rax,%rax
   321ce:	je     32048 <ngettext+0x1bc8>
   321d4:	mov    %rax,0x393665(%rip)        # 3c5840 <stdin+0x10>
   321db:	mov    %r14,0x393b56(%rip)        # 3c5d38 <__vdso_clock_gettime+0x338>
   321e2:	mov    -0x1d0(%rbp),%rcx
   321e9:	mov    -0x1c8(%rbp),%r8
   321f0:	jmpq   31f3c <ngettext+0x1abc>
   321f5:	mov    $0x640,%esi
   321fa:	mov    $0x64,%r14d
   32200:	jmp    321b1 <ngettext+0x1d31>
   32202:	mov    0x393b37(%rip),%rsi        # 3c5d40 <__vdso_clock_gettime+0x340>
   32209:	mov    0x393630(%rip),%rdi        # 3c5840 <stdin+0x10>
   32210:	lea    -0x4a7(%rip),%rcx        # 31d70 <ngettext+0x18f0>
   32217:	mov    $0x10,%edx
   3221c:	callq  39490 <qsort>
   32221:	jmpq   3205e <ngettext+0x1bde>
   32226:	lea    -0x28(%rbp),%rsp
   3222a:	xor    %eax,%eax
   3222c:	pop    %rbx
   3222d:	pop    %r12
   3222f:	pop    %r13
   32231:	pop    %r14
   32233:	pop    %r15
   32235:	pop    %rbp
   32236:	retq   
   32237:	mov    %r13,%rdi
   3223a:	callq  6e6b0 <_IO_fclose>
   3223f:	movq   $0x0,-0x1f0(%rbp)
   3224a:	jmpq   3205e <ngettext+0x1bde>
   3224f:	nop
   32250:	push   %r15
   32252:	push   %r14
   32254:	mov    $0x1,%esi
   32259:	push   %r13
   3225b:	push   %r12
   3225d:	xor    %eax,%eax
   3225f:	push   %rbp
   32260:	push   %rbx
   32261:	mov    %rdi,%rbx
   32264:	sub    $0x8,%rsp
   32268:	cmpl   $0x0,0x397a11(%rip)        # 3c9c80 <argp_program_version_hook+0x1f8>
   3226f:	je     3227d <ngettext+0x1dfd>
   32271:	lock cmpxchg %esi,0x393adf(%rip)        # 3c5d58 <__vdso_clock_gettime+0x358>
   32279:	jne    32286 <ngettext+0x1e06>
   3227b:	jmp    322a0 <ngettext+0x1e20>
   3227d:	cmpxchg %esi,0x393ad4(%rip)        # 3c5d58 <__vdso_clock_gettime+0x358>
   32284:	je     322a0 <ngettext+0x1e20>
   32286:	lea    0x393acb(%rip),%rdi        # 3c5d58 <__vdso_clock_gettime+0x358>
   3228d:	sub    $0x80,%rsp
   32294:	callq  114bd0 <pthread_setcanceltype+0x30>
   32299:	add    $0x80,%rsp
   322a0:	cmpq   $0x0,0x393a88(%rip)        # 3c5d30 <__vdso_clock_gettime+0x330>
   322a8:	je     323dc <ngettext+0x1f5c>
   322ae:	mov    0x393a8b(%rip),%r15        # 3c5d40 <__vdso_clock_gettime+0x340>
   322b5:	test   %r15,%r15
   322b8:	je     3230f <ngettext+0x1e8f>
   322ba:	mov    0x39357f(%rip),%r14        # 3c5840 <stdin+0x10>
   322c1:	xor    %r13d,%r13d
   322c4:	jmp    322df <ngettext+0x1e5f>
   322c6:	nopw   %cs:0x0(%rax,%rax,1)
   322d0:	je     323d5 <ngettext+0x1f55>
   322d6:	lea    0x1(%rbp),%r13
   322da:	cmp    %r13,%r15
   322dd:	jbe    3230f <ngettext+0x1e8f>
   322df:	lea    (%r15,%r13,1),%rbp
   322e3:	lea    0x3909d6(%rip),%rdx        # 3c2cc0 <h_errlist+0x940>
   322ea:	mov    %rbx,%rdi
   322ed:	shr    %rbp
   322f0:	mov    %rbp,%r12
   322f3:	shl    $0x4,%r12
   322f7:	add    %r14,%r12
   322fa:	mov    (%r12),%rsi
   322fe:	callq  8fa20 <__strcasecmp+0x70>
   32303:	test   %eax,%eax
   32305:	jns    322d0 <ngettext+0x1e50>
   32307:	mov    %rbp,%r15
   3230a:	cmp    %r13,%r15
   3230d:	ja     322df <ngettext+0x1e5f>
   3230f:	mov    0x393a1a(%rip),%rcx        # 3c5d30 <__vdso_clock_gettime+0x330>
   32316:	movzbl (%rcx),%edx
   32319:	test   %dl,%dl
   3231b:	je     3236e <ngettext+0x1eee>
   3231d:	mov    %rcx,%rdi
   32320:	cmp    $0x3a,%dl
   32323:	jne    32337 <ngettext+0x1eb7>
   32325:	nopl   (%rax)
   32328:	add    $0x1,%rdi
   3232c:	movzbl (%rdi),%eax
   3232f:	cmp    $0x3a,%al
   32331:	je     32328 <ngettext+0x1ea8>
   32333:	test   %al,%al
   32335:	je     32364 <ngettext+0x1ee4>
   32337:	lea    0x1(%rdi),%rax
   3233b:	jmp    32344 <ngettext+0x1ec4>
   3233d:	nopl   (%rax)
   32340:	test   %dl,%dl
   32342:	je     32353 <ngettext+0x1ed3>
   32344:	movzbl (%rax),%edx
   32347:	mov    %rax,%rsi
   3234a:	add    $0x1,%rax
   3234e:	cmp    $0x3a,%dl
   32351:	jne    32340 <ngettext+0x1ec0>
   32353:	cmp    %rsi,%rdi
   32356:	mov    %rsi,%rax
   32359:	jb     323b8 <ngettext+0x1f38>
   3235b:	test   %dl,%dl
   3235d:	je     32367 <ngettext+0x1ee7>
   3235f:	mov    %rsi,%rdi
   32362:	jmp    32320 <ngettext+0x1ea0>
   32364:	mov    %rdi,%rax
   32367:	mov    %rax,0x3939c2(%rip)        # 3c5d30 <__vdso_clock_gettime+0x330>
   3236e:	xor    %edx,%edx
   32370:	cmpl   $0x0,0x397909(%rip)        # 3c9c80 <argp_program_version_hook+0x1f8>
   32377:	je     32384 <ngettext+0x1f04>
   32379:	lock decl 0x3939d8(%rip)        # 3c5d58 <__vdso_clock_gettime+0x358>
   32380:	jne    3238c <ngettext+0x1f0c>
   32382:	jmp    323a6 <ngettext+0x1f26>
   32384:	decl   0x3939ce(%rip)        # 3c5d58 <__vdso_clock_gettime+0x358>
   3238a:	je     323a6 <ngettext+0x1f26>
   3238c:	lea    0x3939c5(%rip),%rdi        # 3c5d58 <__vdso_clock_gettime+0x358>
   32393:	sub    $0x80,%rsp
   3239a:	callq  114c00 <pthread_setcanceltype+0x60>
   3239f:	add    $0x80,%rsp
   323a6:	add    $0x8,%rsp
   323aa:	mov    %rdx,%rax
   323ad:	pop    %rbx
   323ae:	pop    %rbp
   323af:	pop    %r12
   323b1:	pop    %r13
   323b3:	pop    %r14
   323b5:	pop    %r15
   323b7:	retq   
   323b8:	mov    %rsi,0x393971(%rip)        # 3c5d30 <__vdso_clock_gettime+0x330>
   323bf:	sub    %rdi,%rsi
   323c2:	callq  31d90 <ngettext+0x1910>
   323c7:	test   %rax,%rax
   323ca:	je     3230f <ngettext+0x1e8f>
   323d0:	jmpq   322ae <ngettext+0x1e2e>
   323d5:	mov    0x8(%r12),%rdx
   323da:	jmp    32370 <ngettext+0x1ef0>
   323dc:	lea    0x159e96(%rip),%rax        # 18c279 <_libc_intl_domainname+0x50>
   323e3:	mov    %rax,0x393946(%rip)        # 3c5d30 <__vdso_clock_gettime+0x330>
   323ea:	jmpq   322ae <ngettext+0x1e2e>
   323ef:	nop
