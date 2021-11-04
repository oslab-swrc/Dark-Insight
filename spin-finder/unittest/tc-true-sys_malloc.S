// TC_OUT sysmalloc,0x83793,0x837a5,0x0(0x3c0170)
// TC_OUT sysmalloc,0x837b6,0x837cb,0x0(0x3c0180)
0000000000083460 <sysmalloc>:
   83460:	push   %r15
   83462:	push   %r14
   83464:	push   %r13
   83466:	push   %r12
   83468:	push   %rbp
   83469:	push   %rbx
   8346a:	mov    %rdi,%rbp
   8346d:	sub    $0x68,%rsp
   83471:	mov    0x33c9e0(%rip),%rax        # 3bfe58 <_DYNAMIC+0x2f8>
   83478:	test   %rsi,%rsi
   8347b:	mov    0x18(%rax),%r14
   8347f:	je     83730 <sysmalloc+0x2d0>
   83485:	cmp    %rdi,0x33ccc4(%rip)        # 3c0150 <mp_+0x10>
   8348c:	mov    %rsi,%rbx
   8348f:	jbe    83620 <sysmalloc+0x1c0>
   83495:	movb   $0x0,0x18(%rsp)
   8349a:	lea    0x58(%rbx),%rax
   8349e:	mov    %rax,0x8(%rsp)
   834a3:	mov    %r14,%rax
   834a6:	neg    %rax
   834a9:	mov    %rax,%rdi
   834ac:	mov    %rax,0x10(%rsp)
   834b1:	lea    0x7(%r14,%rbp,1),%rax
   834b6:	and    %rdi,%rax
   834b9:	mov    %rax,0x28(%rsp)
   834be:	mov    0x58(%rbx),%r13
   834c2:	mov    0x8(%r13),%rax
   834c6:	mov    %rax,%r12
   834c9:	and    $0xfffffffffffffff8,%r12
   834cd:	test   %r12,%r12
   834d0:	lea    0x0(%r13,%r12,1),%r10
   834d5:	setne  %r11b
   834d9:	cmp    0x8(%rsp),%r13
   834de:	jne    835e0 <sysmalloc+0x180>
   834e4:	test   %r11b,%r11b
   834e7:	jne    835e0 <sysmalloc+0x180>
   834ed:	lea    0x20(%rbp),%r15
   834f1:	cmp    %r15,%r12
   834f4:	jae    83cd6 <sysmalloc+0x876>
   834fa:	lea    0x33d5df(%rip),%rax        # 3c0ae0 <main_arena>
   83501:	cmp    %rax,%rbx
   83504:	je     837d8 <sysmalloc+0x378>
   8350a:	mov    %r15,%rax
   8350d:	mov    %r13,%r8
   83510:	sub    %r12,%rax
   83513:	and    $0xfffffffffc000000,%r8
   8351a:	test   %rax,%rax
   8351d:	jle    83658 <sysmalloc+0x1f8>
   83523:	lea    -0x1(%r14,%rax,1),%rcx
   83528:	and    0x10(%rsp),%rcx
   8352d:	mov    0x10(%r8),%r9
   83531:	add    %r9,%rcx
   83534:	cmp    $0x4000000,%rcx
   8353b:	ja     83658 <sysmalloc+0x1f8>
   83541:	mov    0x18(%r8),%rdi
   83545:	cmp    %rdi,%rcx
   83548:	ja     836e8 <sysmalloc+0x288>
   8354e:	mov    %r13,%rdx
   83551:	mov    %rcx,0x10(%r8)
   83555:	nop
   83556:	mov    0x880(%rbx),%rsi
   8355d:	sub    %r9,%rsi
   83560:	add    %rcx,%rsi
   83563:	add    %r8,%rcx
   83566:	sub    %r13,%rcx
   83569:	mov    %rsi,0x880(%rbx)
   83570:	or     $0x1,%rcx
   83574:	mov    %rcx,0x8(%r13)
   83578:	cmp    %rsi,0x888(%rbx)
   8357f:	jae    83588 <sysmalloc+0x128>
   83581:	mov    %rsi,0x888(%rbx)
   83588:	mov    0x8(%rdx),%rax
   8358c:	and    $0xfffffffffffffff8,%rax
   83590:	cmp    %rax,%r15
   83593:	ja     838f0 <sysmalloc+0x490>
   83599:	lea    0x33d540(%rip),%rdi        # 3c0ae0 <main_arena>
   835a0:	sub    %rbp,%rax
   835a3:	xor    %ecx,%ecx
   835a5:	lea    (%rdx,%rbp,1),%rsi
   835a9:	cmp    %rdi,%rbx
   835ac:	setne  %cl
   835af:	or     $0x1,%rbp
   835b3:	or     $0x1,%rax
   835b7:	shl    $0x2,%rcx
   835bb:	mov    %rsi,0x58(%rbx)
   835bf:	or     %rcx,%rbp
   835c2:	mov    %rbp,0x8(%rdx)
   835c6:	mov    %rax,0x8(%rsi)
   835ca:	lea    0x10(%rdx),%rax
   835ce:	add    $0x68,%rsp
   835d2:	pop    %rbx
   835d3:	pop    %rbp
   835d4:	pop    %r12
   835d6:	pop    %r13
   835d8:	pop    %r14
   835da:	pop    %r15
   835dc:	retq   
   835dd:	nopl   (%rax)
   835e0:	cmp    $0x1f,%r12
   835e4:	jbe    835f7 <sysmalloc+0x197>
   835e6:	test   $0x1,%al
   835e8:	je     835f7 <sysmalloc+0x197>
   835ea:	lea    -0x1(%r14),%rax
   835ee:	test   %rax,%r10
   835f1:	je     834ed <sysmalloc+0x8d>
   835f7:	lea    0x10b17a(%rip),%rcx        # 18e778 <__func__.11266>
   835fe:	lea    0x1071a2(%rip),%rsi        # 18a7a7 <null+0xdc9>
   83605:	lea    0x10a924(%rip),%rdi        # 18df30 <__PRETTY_FUNCTION__.11851+0x450>
   8360c:	mov    $0x963,%edx
   83611:	callq  7fd60 <__malloc_assert>
   83616:	nopw   %cs:0x0(%rax,%rax,1)
   83620:	mov    0x33cb46(%rip),%eax        # 3c016c <mp_+0x2c>
   83626:	cmp    %eax,0x33cb3c(%rip)        # 3c0168 <mp_+0x28>
   8362c:	jge    83495 <sysmalloc+0x35>
   83632:	lea    0x7(%r14,%rdi,1),%r12
   83637:	mov    %r14,%rax
   8363a:	neg    %rax
   8363d:	and    %rax,%r12
   83640:	cmp    %r12,%rdi
   83643:	jb     83d14 <sysmalloc+0x8b4>
   83649:	movb   $0x1,0x18(%rsp)
   8364e:	jmpq   8349a <sysmalloc+0x3a>
   83653:	nopl   0x0(%rax,%rax,1)
   83658:	mov    0x33cae9(%rip),%rsi        # 3c0148 <mp_+0x8>
   8365f:	lea    0x40(%rbp),%rdi
   83663:	mov    %r8,0x20(%rsp)
   83668:	callq  7fde0 <new_heap>
   8366d:	test   %rax,%rax
   83670:	je     83910 <sysmalloc+0x4b0>
   83676:	mov    0x10(%rax),%rcx
   8367a:	mov    0x20(%rsp),%r8
   8367f:	lea    0x20(%rax),%rdx
   83683:	sub    $0x20,%r12
   83687:	mov    %rbx,(%rax)
   8368a:	and    $0xfffffffffffffff0,%r12
   8368e:	mov    %rcx,%rsi
   83691:	add    0x880(%rbx),%rsi
   83698:	sub    $0x20,%rcx
   8369c:	or     $0x1,%rcx
   836a0:	mov    %r8,0x8(%rax)
   836a4:	mov    %rdx,0x58(%rbx)
   836a8:	cmp    $0x1f,%r12
   836ac:	mov    %rsi,0x880(%rbx)
   836b3:	mov    %rcx,0x28(%rax)
   836b7:	lea    0x10(%r12),%rax
   836bc:	lea    0x0(%r13,%rax,1),%rcx
   836c1:	movq   $0x1,0x8(%rcx)
   836c9:	ja     838b0 <sysmalloc+0x450>
   836cf:	mov    %rax,%rdi
   836d2:	or     $0x1,%rdi
   836d6:	mov    %rdi,0x8(%r13)
   836da:	mov    %rax,(%rcx)
   836dd:	jmpq   83578 <sysmalloc+0x118>
   836e2:	nopw   0x0(%rax,%rax,1)
   836e8:	mov    %rcx,%rsi
   836eb:	mov    $0x3,%edx
   836f0:	mov    %r8,0x20(%rsp)
   836f5:	sub    %rdi,%rsi
   836f8:	add    %r8,%rdi
   836fb:	mov    %r9,0x38(%rsp)
   83700:	mov    %rcx,0x30(%rsp)
   83705:	callq  101e80 <mprotect>
   8370a:	test   %eax,%eax
   8370c:	mov    0x20(%rsp),%r8
   83711:	jne    83658 <sysmalloc+0x1f8>
   83717:	mov    0x30(%rsp),%rcx
   8371c:	mov    0x38(%rsp),%r9
   83721:	mov    0x58(%rbx),%rdx
   83725:	mov    %rcx,0x18(%r8)
   83729:	jmpq   83551 <sysmalloc+0xf1>
   8372e:	xchg   %ax,%ax
   83730:	lea    0x7(%r14,%rdi,1),%r12
   83735:	neg    %r14
   83738:	and    %r14,%r12
   8373b:	cmp    %r12,%rdi
   8373e:	jae    838fe <sysmalloc+0x49e>
   83744:	xor    %r9d,%r9d
   83747:	xor    %edi,%edi
   83749:	mov    $0xffffffff,%r8d
   8374f:	mov    $0x22,%ecx
   83754:	mov    $0x3,%edx
   83759:	mov    %r12,%rsi
   8375c:	callq  101d90 <mmap>
   83761:	cmp    $0xffffffffffffffff,%rax
   83765:	je     838fe <sysmalloc+0x49e>
   8376b:	lea    0x10(%rax),%rdx
   8376f:	test   $0xf,%dl
   83772:	jne    83d3e <sysmalloc+0x8de>
   83778:	mov    %r12,%rcx
   8377b:	or     $0x2,%rcx
   8377f:	mov    %rcx,0x8(%rax)
   83783:	mov    $0x1,%ecx
   83788:	lock xadd %ecx,0x33c9d8(%rip)        # 3c0168 <mp_+0x28>
   83790:	add    $0x1,%ecx
   83793:	mov    0x33c9d7(%rip),%eax        # 3c0170 <mp_+0x30>
   83799:	cmp    %eax,%ecx
   8379b:	jle    837a7 <sysmalloc+0x347>
   8379d:	lock cmpxchg %ecx,0x33c9cb(%rip)        # 3c0170 <mp_+0x30>
   837a5:	jne    83793 <sysmalloc+0x333>
   837a7:	mov    %r12,%r14
   837aa:	lock xadd %r14,0x33c9c5(%rip)        # 3c0178 <mp_+0x38>
   837b3:	add    %r14,%r12
   837b6:	mov    0x33c9c3(%rip),%rax        # 3c0180 <mp_+0x40>
   837bd:	cmp    %rax,%r12
   837c0:	jbe    837cd <sysmalloc+0x36d>
   837c2:	lock cmpxchg %r12,0x33c9b5(%rip)        # 3c0180 <mp_+0x40>
   837cb:	jne    837b6 <sysmalloc+0x356>
   837cd:	mov    %rdx,%rax
   837d0:	jmpq   835ce <sysmalloc+0x16e>
   837d5:	nopl   (%rax)
   837d8:	mov    0x33c969(%rip),%rax        # 3c0148 <mp_+0x8>
   837df:	lea    0x20(%rbp,%rax,1),%rdx
   837e4:	lea    -0x1(%r14),%rax
   837e8:	neg    %r14
   837eb:	testb  $0x2,0x4(%rbx)
   837ef:	mov    %r14,0x10(%rsp)
   837f4:	mov    %rax,0x8(%rsp)
   837f9:	jne    83940 <sysmalloc+0x4e0>
   837ff:	sub    %r12,%rdx
   83802:	add    %rax,%rdx
   83805:	and    %r14,%rdx
   83808:	test   %rdx,%rdx
   8380b:	mov    %rdx,%r14
   8380e:	jle    83be0 <sysmalloc+0x780>
   83814:	mov    0x33c58d(%rip),%rax        # 3bfda8 <_DYNAMIC+0x248>
   8381b:	mov    %rdx,%rdi
   8381e:	mov    %rdx,0x18(%rsp)
   83823:	mov    %r11b,0x28(%rsp)
   83828:	mov    %r10,0x20(%rsp)
   8382d:	callq  *(%rax)
   8382f:	mov    0x18(%rsp),%rdx
   83834:	mov    %rax,%r8
   83837:	nop
   83838:	test   %rax,%rax
   8383b:	mov    0x20(%rsp),%r10
   83840:	movzbl 0x28(%rsp),%r11d
   83846:	je     83bc9 <sysmalloc+0x769>
   8384c:	mov    0x33c64d(%rip),%rax        # 3bfea0 <_DYNAMIC+0x340>
   83853:	mov    $0x1,%ecx
   83858:	mov    (%rax),%rdx
   8385b:	xor    %eax,%eax
   8385d:	test   %rdx,%rdx
   83860:	jne    83b90 <sysmalloc+0x730>
   83866:	cmpq   $0x0,0x33c91a(%rip)        # 3c0188 <mp_+0x48>
   8386e:	je     83b80 <sysmalloc+0x720>
   83874:	mov    %r14,%rsi
   83877:	add    0x33dae2(%rip),%rsi        # 3c1360 <main_arena+0x880>
   8387e:	cmp    %r8,%r10
   83881:	mov    %rsi,0x33dad8(%rip)        # 3c1360 <main_arena+0x880>
   83888:	jne    839e0 <sysmalloc+0x580>
   8388e:	test   %cl,%cl
   83890:	je     839e0 <sysmalloc+0x580>
   83896:	add    %r14,%r12
   83899:	mov    0x33d298(%rip),%rdx        # 3c0b38 <main_arena+0x58>
   838a0:	or     $0x1,%r12
   838a4:	mov    %r12,0x8(%r13)
   838a8:	jmpq   83578 <sysmalloc+0x118>
   838ad:	nopl   (%rax)
   838b0:	movq   $0x11,0x8(%r13,%r12,1)
   838b9:	or     $0x5,%r12
   838bd:	movq   $0x10,(%rcx)
   838c4:	mov    $0x1,%edx
   838c9:	mov    %r13,%rsi
   838cc:	mov    %r12,0x8(%r13)
   838d0:	mov    %rbx,%rdi
   838d3:	callq  82300 <_int_free>
   838d8:	mov    0x880(%rbx),%rsi
   838df:	mov    0x58(%rbx),%rdx
   838e3:	jmpq   83578 <sysmalloc+0x118>
   838e8:	nopl   0x0(%rax,%rax,1)
   838f0:	mov    0x33c571(%rip),%rax        # 3bfe68 <_DYNAMIC+0x308>
   838f7:	movl   $0xc,%fs:(%rax)
   838fe:	add    $0x68,%rsp
   83902:	xor    %eax,%eax
   83904:	pop    %rbx
   83905:	pop    %rbp
   83906:	pop    %r12
   83908:	pop    %r13
   8390a:	pop    %r14
   8390c:	pop    %r15
   8390e:	retq   
   8390f:	nop
   83910:	cmpb   $0x0,0x18(%rsp)
   83915:	jne    83b20 <sysmalloc+0x6c0>
   8391b:	mov    0x28(%rsp),%rax
   83920:	cmp    %rax,%rbp
   83923:	mov    %rax,%r12
   83926:	jb     83d5d <sysmalloc+0x8fd>
   8392c:	movb   $0x1,0x18(%rsp)
   83931:	jmpq   834be <sysmalloc+0x5e>
   83936:	nopw   %cs:0x0(%rax,%rax,1)
   83940:	add    %rax,%rdx
   83943:	and    %r14,%rdx
   83946:	test   %rdx,%rdx
   83949:	mov    %rdx,%r14
   8394c:	jg     83814 <sysmalloc+0x3b4>
   83952:	cmp    $0xfffff,%r14
   83959:	mov    %r14,0x18(%rsp)
   8395e:	ja     8396f <sysmalloc+0x50f>
   83960:	movq   $0x100000,0x18(%rsp)
   83969:	mov    $0x100000,%r14d
   8396f:	cmp    0x18(%rsp),%rbp
   83974:	jae    83b05 <sysmalloc+0x6a5>
   8397a:	mov    0x18(%rsp),%rsi
   8397f:	xor    %r9d,%r9d
   83982:	mov    $0xffffffff,%r8d
   83988:	xor    %edi,%edi
   8398a:	mov    $0x22,%ecx
   8398f:	mov    $0x3,%edx
   83994:	mov    %r11b,0x28(%rsp)
   83999:	mov    %r10,0x20(%rsp)
   8399e:	callq  101d90 <mmap>
   839a3:	cmp    $0xffffffffffffffff,%rax
   839a7:	mov    %rax,%r8
   839aa:	mov    0x20(%rsp),%r10
   839af:	movzbl 0x28(%rsp),%r11d
   839b5:	je     83b05 <sysmalloc+0x6a5>
   839bb:	orl    $0x2,0x33d122(%rip)        # 3c0ae4 <main_arena+0x4>
   839c2:	test   %rax,%rax
   839c5:	je     83b05 <sysmalloc+0x6a5>
   839cb:	mov    0x18(%rsp),%rax
   839d0:	add    %r8,%rax
   839d3:	sete   %cl
   839d6:	jmpq   83866 <sysmalloc+0x406>
   839db:	nopl   0x0(%rax,%rax,1)
   839e0:	mov    0x33d0fe(%rip),%edx        # 3c0ae4 <main_arena+0x4>
   839e6:	test   $0x2,%dl
   839e9:	jne    83b30 <sysmalloc+0x6d0>
   839ef:	cmp    %r8,%r10
   839f2:	jbe    839fd <sysmalloc+0x59d>
   839f4:	test   %r11b,%r11b
   839f7:	jne    83bf6 <sysmalloc+0x796>
   839fd:	test   %r12,%r12
   83a00:	je     83a12 <sysmalloc+0x5b2>
   83a02:	mov    %r8,%rax
   83a05:	sub    %r10,%rax
   83a08:	add    %rax,%rsi
   83a0b:	mov    %rsi,0x33d94e(%rip)        # 3c1360 <main_arena+0x880>
   83a12:	mov    %r8,%rax
   83a15:	mov    %r8,%rcx
   83a18:	and    $0xf,%eax
   83a1b:	je     83a2c <sysmalloc+0x5cc>
   83a1d:	mov    $0x10,%edx
   83a22:	sub    %rax,%rdx
   83a25:	lea    (%r8,%rdx,1),%rcx
   83a29:	mov    %rdx,%rax
   83a2c:	add    %r12,%rax
   83a2f:	add    %rax,%r14
   83a32:	add    %r14,%r8
   83a35:	mov    0x8(%rsp),%r14
   83a3a:	sub    %r8,%rax
   83a3d:	add    %r8,%r14
   83a40:	and    0x10(%rsp),%r14
   83a45:	add    %rax,%r14
   83a48:	test   %r14,%r14
   83a4b:	js     83cf5 <sysmalloc+0x895>
   83a51:	mov    0x33c350(%rip),%rax        # 3bfda8 <_DYNAMIC+0x248>
   83a58:	mov    %rcx,0x8(%rsp)
   83a5d:	mov    %r14,%rdi
   83a60:	mov    %r14,0x10(%rsp)
   83a65:	callq  *(%rax)
   83a67:	test   %rax,%rax
   83a6a:	mov    0x8(%rsp),%rcx
   83a6f:	mov    0x10(%rsp),%r9
   83a74:	je     83cc1 <sysmalloc+0x861>
   83a7a:	mov    0x33c41f(%rip),%rsi        # 3bfea0 <_DYNAMIC+0x340>
   83a81:	mov    (%rsi),%rsi
   83a84:	test   %rsi,%rsi
   83a87:	jne    83c92 <sysmalloc+0x832>
   83a8d:	mov    0x33d8cc(%rip),%rsi        # 3c1360 <main_arena+0x880>
   83a94:	mov    %rcx,%r8
   83a97:	sub    %r8,%rax
   83a9a:	add    %r14,%rsi
   83a9d:	mov    %r8,0x33d094(%rip)        # 3c0b38 <main_arena+0x58>
   83aa4:	add    %r9,%rax
   83aa7:	mov    %r8,%rdx
   83aaa:	or     $0x1,%rax
   83aae:	test   %r12,%r12
   83ab1:	mov    %rax,0x8(%r8)
   83ab5:	mov    %rsi,0x33d8a4(%rip)        # 3c1360 <main_arena+0x880>
   83abc:	je     83578 <sysmalloc+0x118>
   83ac2:	sub    $0x20,%r12
   83ac6:	and    $0xfffffffffffffff0,%r12
   83aca:	mov    %r12,%rax
   83acd:	or     $0x1,%rax
   83ad1:	cmp    $0x1f,%r12
   83ad5:	mov    %rax,0x8(%r13)
   83ad9:	movq   $0x11,0x8(%r13,%r12,1)
   83ae2:	movq   $0x11,0x18(%r13,%r12,1)
   83aeb:	jbe    83578 <sysmalloc+0x118>
   83af1:	lea    0x33cfe8(%rip),%rdi        # 3c0ae0 <main_arena>
   83af8:	mov    $0x1,%edx
   83afd:	mov    %r13,%rsi
   83b00:	callq  82300 <_int_free>
   83b05:	mov    0x33d854(%rip),%rsi        # 3c1360 <main_arena+0x880>
   83b0c:	mov    0x33d025(%rip),%rdx        # 3c0b38 <main_arena+0x58>
   83b13:	jmpq   83578 <sysmalloc+0x118>
   83b18:	nopl   0x0(%rax,%rax,1)
   83b20:	mov    0x880(%rbx),%rsi
   83b27:	mov    0x58(%rbx),%rdx
   83b2b:	jmpq   83578 <sysmalloc+0x118>
   83b30:	test   $0xf,%r8b
   83b34:	jne    83d87 <sysmalloc+0x927>
   83b3a:	xor    %r14d,%r14d
   83b3d:	xor    %r9d,%r9d
   83b40:	test   %rax,%rax
   83b43:	jne    83a97 <sysmalloc+0x637>
   83b49:	mov    0x33c258(%rip),%rax        # 3bfda8 <_DYNAMIC+0x248>
   83b50:	mov    %r8,0x8(%rsp)
   83b55:	xor    %edi,%edi
   83b57:	callq  *(%rax)
   83b59:	mov    0x8(%rsp),%r8
   83b5e:	mov    %r8,%rcx
   83b61:	test   %rax,%rax
   83b64:	mov    0x33d7f5(%rip),%rsi        # 3c1360 <main_arena+0x880>
   83b6b:	je     83b0c <sysmalloc+0x6ac>
   83b6d:	mov    %rcx,%r8
   83b70:	xor    %r14d,%r14d
   83b73:	xor    %r9d,%r9d
   83b76:	jmpq   83a97 <sysmalloc+0x637>
   83b7b:	nopl   0x0(%rax,%rax,1)
   83b80:	mov    %r8,0x33c601(%rip)        # 3c0188 <mp_+0x48>
   83b87:	jmpq   83874 <sysmalloc+0x414>
   83b8c:	nopl   0x0(%rax)
   83b90:	mov    %cl,0x38(%rsp)
   83b94:	mov    %rax,0x30(%rsp)
   83b99:	mov    %r11b,0x28(%rsp)
   83b9e:	mov    %r8,0x20(%rsp)
   83ba3:	mov    %r10,0x18(%rsp)
   83ba8:	callq  *%rdx
   83baa:	mov    0x18(%rsp),%r10
   83baf:	mov    0x20(%rsp),%r8
   83bb4:	movzbl 0x28(%rsp),%r11d
   83bba:	mov    0x30(%rsp),%rax
   83bbf:	movzbl 0x38(%rsp),%ecx
   83bc4:	jmpq   83866 <sysmalloc+0x406>
   83bc9:	testb  $0x2,0x33cf14(%rip)        # 3c0ae4 <main_arena+0x4>
   83bd0:	jne    83952 <sysmalloc+0x4f2>
   83bd6:	nopw   %cs:0x0(%rax,%rax,1)
   83be0:	mov    0x8(%rsp),%rax
   83be5:	lea    (%r12,%rax,1),%r14
   83be9:	add    %rdx,%r14
   83bec:	and    0x10(%rsp),%r14
   83bf1:	jmpq   83952 <sysmalloc+0x4f2>
   83bf6:	or     $0x4,%edx
   83bf9:	lea    0x40(%rsp),%r14
   83bfe:	lea    0x50(%rsp),%rsi
   83c03:	mov    %edx,0x33cedb(%rip)        # 3c0ae4 <main_arena+0x4>
   83c09:	xor    %ecx,%ecx
   83c0b:	mov    $0x10,%edx
   83c10:	mov    %r8,%rdi
   83c13:	movb   $0x0,0x50(%rsp)
   83c18:	callq  4ace0 <_itoa_word>
   83c1d:	cmp    %r14,%rax
   83c20:	mov    %rax,%r12
   83c23:	jbe    83c4a <sysmalloc+0x7ea>
   83c25:	mov    %rax,%rdx
   83c28:	mov    %rax,%rdi
   83c2b:	mov    $0x30,%esi
   83c30:	sub    %r14,%rdx
   83c33:	lea    -0x1(%rax),%r13
   83c37:	sub    %rdx,%rdi
   83c3a:	callq  90e00 <__GI_memset>
   83c3f:	lea    0x3f(%rsp),%rax
   83c44:	sub    %r13,%rax
   83c47:	add    %rax,%r12
   83c4a:	mov    0x341667(%rip),%rax        # 3c52b8 <__libc_argv>
   83c51:	lea    0x106bbf(%rip),%rdx        # 18a817 <null+0xe39>
   83c58:	lea    0x10a019(%rip),%rsi        # 18dc78 <__PRETTY_FUNCTION__.11851+0x198>
   83c5f:	lea    0x10a3b2(%rip),%rcx        # 18e018 <__PRETTY_FUNCTION__.11851+0x538>
   83c66:	mov    %r12,%r8
   83c69:	mov    $0x2,%edi
   83c6e:	mov    (%rax),%rax
   83c71:	test   %rax,%rax
   83c74:	cmovne %rax,%rdx
   83c78:	xor    %eax,%eax
   83c7a:	callq  78fa0 <__libc_message>
   83c7f:	mov    0x33d6da(%rip),%rsi        # 3c1360 <main_arena+0x880>
   83c86:	mov    0x33ceab(%rip),%rdx        # 3c0b38 <main_arena+0x58>
   83c8d:	jmpq   83578 <sysmalloc+0x118>
   83c92:	mov    %rax,0x18(%rsp)
   83c97:	mov    %r9,0x10(%rsp)
   83c9c:	mov    %rcx,0x8(%rsp)
   83ca1:	callq  *%rsi
   83ca3:	mov    0x8(%rsp),%rcx
   83ca8:	mov    0x33d6b1(%rip),%rsi        # 3c1360 <main_arena+0x880>
   83caf:	mov    0x10(%rsp),%r9
   83cb4:	mov    0x18(%rsp),%rax
   83cb9:	mov    %rcx,%r8
   83cbc:	jmpq   83a97 <sysmalloc+0x637>
   83cc1:	mov    0x33c0e0(%rip),%rax        # 3bfda8 <_DYNAMIC+0x248>
   83cc8:	xor    %edi,%edi
   83cca:	callq  *(%rax)
   83ccc:	mov    0x8(%rsp),%rcx
   83cd1:	jmpq   83b61 <sysmalloc+0x701>
   83cd6:	lea    0x10aa9b(%rip),%rcx        # 18e778 <__func__.11266>
   83cdd:	lea    0x106ac3(%rip),%rsi        # 18a7a7 <null+0xdc9>
   83ce4:	lea    0x10a2ed(%rip),%rdi        # 18dfd8 <__PRETTY_FUNCTION__.11851+0x4f8>
   83ceb:	mov    $0x966,%edx
   83cf0:	callq  7fd60 <__malloc_assert>
   83cf5:	lea    0x10aa7c(%rip),%rcx        # 18e778 <__func__.11266>
   83cfc:	lea    0x106aa4(%rip),%rsi        # 18a7a7 <null+0xdc9>
   83d03:	lea    0x106bea(%rip),%rdi        # 18a8f4 <null+0xf16>
   83d0a:	mov    $0xa40,%edx
   83d0f:	callq  7fd60 <__malloc_assert>
   83d14:	xor    %r9d,%r9d
   83d17:	or     $0xffffffff,%r8d
   83d1b:	xor    %edi,%edi
   83d1d:	mov    $0x22,%ecx
   83d22:	mov    $0x3,%edx
   83d27:	mov    %r12,%rsi
   83d2a:	callq  101d90 <mmap>
   83d2f:	cmp    $0xffffffffffffffff,%rax
   83d33:	jne    8376b <sysmalloc+0x30b>
   83d39:	jmpq   83649 <sysmalloc+0x1e9>
   83d3e:	lea    0x10aa33(%rip),%rcx        # 18e778 <__func__.11266>
   83d45:	lea    0x106a5b(%rip),%rsi        # 18a7a7 <null+0xdc9>
   83d4c:	lea    0x10a19d(%rip),%rdi        # 18def0 <__PRETTY_FUNCTION__.11851+0x410>
   83d53:	mov    $0x92d,%edx
   83d58:	callq  7fd60 <__malloc_assert>
   83d5d:	xor    %r9d,%r9d
   83d60:	or     $0xffffffff,%r8d
   83d64:	xor    %edi,%edi
   83d66:	mov    $0x22,%ecx
   83d6b:	mov    $0x3,%edx
   83d70:	mov    %rax,%rsi
   83d73:	callq  101d90 <mmap>
   83d78:	cmp    $0xffffffffffffffff,%rax
   83d7c:	jne    8376b <sysmalloc+0x30b>
   83d82:	jmpq   8392c <sysmalloc+0x4cc>
   83d87:	lea    0x10a9ea(%rip),%rcx        # 18e778 <__func__.11266>
   83d8e:	lea    0x106a12(%rip),%rsi        # 18a7a7 <null+0xdc9>
   83d95:	lea    0x10a2a4(%rip),%rdi        # 18e040 <__PRETTY_FUNCTION__.11851+0x560>
   83d9c:	mov    $0xa60,%edx
   83da1:	callq  7fd60 <__malloc_assert>
   83da6:	nopw   %cs:0x0(%rax,%rax,1)
